// 文件名: funclatency.bpf.c

// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CALL_STACK_DEPTH 256

// 事件结构体，用于从内核发送数据到用户空间
struct event { 
    u64 func_addr; 
    u64 duration_ns; 
    u32 pid;
    u32 tid;
};

// 调用信息，存在栈里
struct call_info { 
    u64 start_ts; 
    u64 func_addr; 
};

// 每个线程的调用栈结构体
struct per_thread_stack { 
    int depth; 
    struct call_info calls[MAX_CALL_STACK_DEPTH]; 
};

/* ===== 地图定义 (Maps) ===== */

// 【已修改】主map，使用哈希表存储每个线程(TID)的调用栈
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct per_thread_stack);
    __uint(max_entries, 10240); // 预估最大并发线程数
} call_stacks SEC(".maps");

// 【新增】辅助map，用于在用户空间初始化一个“零值”模板
// 这样可以避免在BPF程序的有限栈上创建大结构体
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct per_thread_stack));
    __uint(max_entries, 1);
} stack_init_map SEC(".maps");

// Ring buffer map，用于向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");


/* ===== 探针函数 (Probes) ===== */

SEC("uprobe")
int BPF_KPROBE(uprobe_entry) {
    // 使用线程ID作为key，确保线程安全
    u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct per_thread_stack *stack = bpf_map_lookup_elem(&call_stacks, &tid);

    if (!stack) {
        // 【已修改】如果此线程第一次被监控，从辅助map中复制一个零值模板
        // 来为它创建新的调用栈，而不是在BPF栈上创建
        u32 zero = 0;
        struct per_thread_stack *init_stack = bpf_map_lookup_elem(&stack_init_map, &zero);
        if (!init_stack) {
            // 如果模板不存在（用户程序未初始化），则无法继续
            return 0;
        }
        
        // 将模板存入主map，与当前线程ID关联
        bpf_map_update_elem(&call_stacks, &tid, init_stack, BPF_NOEXIST);
        stack = bpf_map_lookup_elem(&call_stacks, &tid);
        if (!stack) {
            return 0; // 如果仍然失败，则放弃
        }
    }

    int depth = stack->depth;
    if (depth < 0 || depth >= MAX_CALL_STACK_DEPTH) {
        // 调用栈溢出
        return 0;
    }
    
    // 获取函数入口地址，并记录时间戳和地址
    u64 ip = PT_REGS_IP(ctx);
    stack->calls[depth].start_ts = bpf_ktime_get_ns();
    stack->calls[depth].func_addr = ip;
    stack->depth = depth + 1;
    
    return 0;
}

SEC("uretprobe")
int BPF_KPROBE(uretprobe_return) {
    // 同样使用线程ID作为key
    u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct per_thread_stack *stack = bpf_map_lookup_elem(&call_stacks, &tid);
    if (!stack) {
        // 没有对应的入口记录，直接返回
        return 0;
    }
    
    int depth = stack->depth;
    if (depth <= 0) {
        // 调用栈为空，说明uprobe和uretprobe不匹配
        return 0;
    }

    int index_to_access = depth - 1;

    if (index_to_access < 0 || index_to_access >= MAX_CALL_STACK_DEPTH) {
        return 0;
    }

    struct call_info *info = &stack->calls[index_to_access];
    u64 start_ts = info->start_ts;
    u64 func_addr = info->func_addr;
    if (start_ts == 0) {
        return 0;
    }
    
    // 计算耗时
    u64 duration_ns = bpf_ktime_get_ns() - start_ts;
    
    // 通过ring buffer发送事件
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->func_addr = func_addr;
    e->duration_ns = duration_ns;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    bpf_ringbuf_submit(e, 0);

    // 栈深度减一（出栈）
    stack->depth = index_to_access;
    
    // 如果一个线程的调用栈为空，就从map中删除它，释放资源
    if (stack->depth == 0) {
        bpf_map_delete_elem(&call_stacks, &tid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";