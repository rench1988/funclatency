// 文件名: main.cpp

#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <chrono>
#include <thread>
#include <system_error>
#include <iomanip>
#include <map>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cerrno>
#include <cstdarg>

// libbpf and skeleton headers are C headers
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "funclatency.skel.h"
}

// ===== 【新增】共享的结构体定义 =====
// 必须与eBPF C代码中的定义保持一致
#define MAX_CALL_STACK_DEPTH 256

struct call_info { 
    __u64 start_ts; 
    __u64 func_addr; 
};

struct per_thread_stack { 
    int depth; 
    struct call_info calls[MAX_CALL_STACK_DEPTH]; 
};
// ===== 结束新增 =====

// Event struct matching the one in the eBPF C code
struct Event {
    __u64 func_addr;
    __u64 duration_ns;
    __u32 pid;
    __u32 tid;
};

// Global flag to signal termination
static volatile bool exiting = false;

// Signal handler to set the exiting flag
static void sigHandler(int sig) {
    exiting = true;
}

// Symbol struct to hold parsed information from the config file
struct SymbolToTrace {
    __u64 addr;
    std::string mangled_name;
    std::string demangled_name;
};

// Global map to find a function's demangled name from its address
static std::map<__u64, std::string> global_addr_to_name;

// C-style callback for the ring buffer
int handleEvent(void *ctx, void *data, size_t data_sz) {
    const auto* e = static_cast<const Event*>(data);
    
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char time_buf[32];
    if (std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&t))) {
        std::string func_name;
        auto it = global_addr_to_name.find(e->func_addr);
        if (it != global_addr_to_name.end()) {
            func_name = it->second;
        } else {
            std::stringstream ss;
            ss << "0x" << std::hex << e->func_addr;
            func_name = ss.str();
        }

        std::cout << std::left << std::setw(10) << time_buf
                  << std::setw(8) << e->pid
                  << std::setw(8) << e->tid
                  << std::left << std::setw(40) << func_name.substr(0, 39)
                  << std::right << std::setw(15) << e->duration_ns << std::endl;
    }
    return 0;
}


// C++ class to encapsulate the eBPF tracing logic
class FuncLatencyTracer {
public:
    FuncLatencyTracer(const std::vector<SymbolToTrace>& symbols, const std::string& binary_path) {
        libbpf_set_print(libbpfPrintFn);
        
        skel_ = funclatency_bpf__open_and_load();
        if (!skel_) {
            throw std::runtime_error("Failed to open and load BPF skeleton");
        }
        
        // ===== 【新增】初始化辅助map =====
        if (initializeStackInitMap() != 0) {
            funclatency_bpf__destroy(skel_);
            throw std::runtime_error("Failed to initialize helper map (stack_init_map)");
        }
        // ===== 结束新增 =====

        for (const auto& sym : symbols) {
            attachProbe(binary_path, sym.mangled_name);
        }

        if (links_.empty()) {
            throw std::runtime_error("Failed to attach to any of the specified functions.");
        }

        setupRingBuffer();
    }

    ~FuncLatencyTracer() {
        for (auto link : links_) {
            bpf_link__destroy(link);
        }
        if (ring_buffer_) {
            ring_buffer__free(ring_buffer_);
        }
        if (skel_) {
            funclatency_bpf__destroy(skel_);
        }
    }

    void run() {
        printHeader();
        while (!exiting) {
            int err = ring_buffer__poll(ring_buffer_, 100);
            if (err == -EINTR) break;
            if (err < 0) throw std::runtime_error("Error polling ring buffer: " + std::string(strerror(-err)));
        }
    }

private:
    funclatency_bpf* skel_ = nullptr;
    ring_buffer* ring_buffer_ = nullptr;
    std::vector<bpf_link*> links_;
    
    // ===== 【新增】初始化辅助map的方法 =====
    int initializeStackInitMap() {
        // 在用户空间栈上创建一个清零的结构体
        const struct per_thread_stack initial_stack = {};
        int map_fd = bpf_map__fd(skel_->maps.stack_init_map);
        if (map_fd < 0) {
            std::cerr << "Error: Failed to get fd for stack_init_map: " << strerror(errno) << std::endl;
            return -1;
        }
        // 将这个清零的结构体作为“模板”推送到BPF map的第0个元素中
        int key = 0;
        int ret = bpf_map_update_elem(map_fd, &key, &initial_stack, BPF_ANY);
        if (ret != 0) {
             std::cerr << "Error: Failed to update stack_init_map: " << strerror(errno) << std::endl;
             return -1;
        }
        std::cout << "Successfully initialized helper map for stack allocation." << std::endl;
        return 0;
    }

    void attachProbe(const std::string& binary_path, const std::string& mangled_name) {
        struct bpf_uprobe_opts uprobe_opts;
        memset(&uprobe_opts, 0, sizeof(uprobe_opts));
        uprobe_opts.sz = sizeof(uprobe_opts);
        uprobe_opts.func_name = mangled_name.c_str();

        bpf_link* uprobe_link = bpf_program__attach_uprobe_opts(skel_->progs.uprobe_entry, -1, binary_path.c_str(), 0, &uprobe_opts);
        if (!uprobe_link) {
            std::cerr << "Warning: Failed to attach uprobe to " << mangled_name << ". Error: " << strerror(errno) << std::endl;
            return;
        }
        links_.push_back(uprobe_link);

        struct bpf_uprobe_opts uretprobe_opts;
        memset(&uretprobe_opts, 0, sizeof(uretprobe_opts));
        uretprobe_opts.sz = sizeof(uretprobe_opts);
        uretprobe_opts.func_name = mangled_name.c_str();
        uretprobe_opts.retprobe = true;

        bpf_link* uretprobe_link = bpf_program__attach_uprobe_opts(skel_->progs.uretprobe_return, -1, binary_path.c_str(), 0, &uretprobe_opts);
        if (!uretprobe_link) {
            bpf_link__destroy(uprobe_link);
            links_.pop_back();
            std::cerr << "Warning: Failed to attach uretprobe to " << mangled_name << ". Error: " << strerror(errno) << std::endl;
            return;
        }
        links_.push_back(uretprobe_link);
    }

    void setupRingBuffer() {
        ring_buffer_ = ring_buffer__new(bpf_map__fd(skel_->maps.events), handleEvent, nullptr, nullptr);
        if (!ring_buffer_) throw std::runtime_error("Failed to create ring buffer");
    }
    
    void printHeader() {
        std::cout << "Watching functions... Hit Ctrl-C to end." << std::endl;
        std::cout << std::left << std::setw(10) << "TIME"
                  << std::setw(8) << "PID"
                  << std::setw(8) << "TID"
                  << std::left << std::setw(40) << "FUNCTION"
                  << std::right << std::setw(15) << "LATENCY(ns)" << std::endl;
    }
    
    static int libbpfPrintFn(enum libbpf_print_level level, const char *format, va_list args) {
        if (level >= LIBBPF_DEBUG) return 0;
        return vfprintf(stderr, format, args);
    }
};

// --- Config parser (无修改) ---
std::vector<SymbolToTrace> parse_config(const std::string& config_path) {
    std::vector<SymbolToTrace> symbols;
    std::ifstream config_file(config_path);
    if (!config_file.is_open()) {
        throw std::runtime_error("Failed to open config file: " + config_path);
    }
    std::string line;
    int line_num = 0;
    while (std::getline(config_file, line)) {
        line_num++;
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        SymbolToTrace sym;
        std::string addr_str;
        
        ss >> addr_str >> sym.mangled_name;
        std::getline(ss, sym.demangled_name);
        if (!sym.demangled_name.empty() && sym.demangled_name.front() == ' ') {
            sym.demangled_name.erase(0, 1);
        }

        if (addr_str.empty() || sym.mangled_name.empty() || sym.demangled_name.empty()) {
            std::cerr << "Warning: malformed line in config file (line " << line_num << "): " << line << std::endl;
            continue;
        }
        
        try {
            sym.addr = std::stoull(addr_str, nullptr, 0);
        } catch(const std::exception& e) {
             std::cerr << "Warning: invalid address format in config file (line " << line_num << "): " << addr_str << std::endl;
             continue;
        }
        symbols.push_back(sym);
    }
    return symbols;
}


// --- Main function (无修改) ---
int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " /path/to/binary /path/to/config_with_addr.txt" << std::endl;
        return 1;
    }
    
    std::string binary_path = argv[1];
    std::string config_path = argv[2];
    
    signal(SIGINT, sigHandler);
    signal(SIGTERM, sigHandler);
    
    try {
        auto symbols_to_trace = parse_config(config_path);
        if (symbols_to_trace.empty()) {
            std::cerr << "No valid function entries found in config file." << std::endl;
            return 1;
        }

        std::cout << "Functions to be traced:" << std::endl;
        for (const auto& sym : symbols_to_trace) {
            global_addr_to_name[sym.addr] = sym.demangled_name;
            std::cout << "  - " << sym.demangled_name << " (at 0x" << std::hex << sym.addr << std::dec << ")" << std::endl;
        }
        
        FuncLatencyTracer tracer(symbols_to_trace, binary_path);
        
        tracer.run();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nExiting." << std::endl;
    return 0;
}