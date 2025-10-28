// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CALL_STACK_DEPTH 16

struct event { 
    u64 func_addr; 
    u64 duration_ns; 
    u32 pid;
    u32 tid;
};

struct call_info { 
    u64 start_ts; 
    u64 func_addr; 
};

struct per_thread_stack { 
    int depth; 
    struct call_info calls[MAX_CALL_STACK_DEPTH]; 
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct per_thread_stack));
    __uint(max_entries, 1);
} call_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(uprobe_entry) {
    u32 zero = 0;
    struct per_thread_stack *stack = bpf_map_lookup_elem(&call_stacks, &zero);
    if (!stack) return 0;

    // --- Verifier-Friendly Code Start ---
    int depth = stack->depth;

    // 关键：对局部变量进行显式的、完整的边界检查
    if (depth < 0 || depth >= MAX_CALL_STACK_DEPTH) {
        return 0;
    }
    
    u64 ip = PT_REGS_IP(ctx);

    // 关键：使用经过边界检查的局部变量作为数组索引
    stack->calls[depth].start_ts = bpf_ktime_get_ns();
    stack->calls[depth].func_addr = ip;
    stack->depth = depth + 1; // 更新 depth
    // --- Verifier-Friendly Code End ---
    
    return 0;
}

SEC("uretprobe")
int BPF_KPROBE(uretprobe_return) {
    u32 zero = 0;
    struct per_thread_stack *stack = bpf_map_lookup_elem(&call_stacks, &zero);
    if (!stack) return 0;
    
    // --- Verifier-Friendly Code Start ---
    int depth = stack->depth;
    if (depth <= 0) { // Stack underflow check
        return 0;
    }

    int index_to_access = depth - 1;

    // 关键：再次对要访问的索引进行显式检查
    if (index_to_access < 0 || index_to_access >= MAX_CALL_STACK_DEPTH) {
        // This path should not be hit in practice, but it satisfies the verifier
        return 0;
    }

    struct call_info *info = &stack->calls[index_to_access];
    u64 start_ts = info->start_ts;
    u64 func_addr = info->func_addr;
    if (start_ts == 0) return 0;
    
    u64 duration_ns = bpf_ktime_get_ns() - start_ts;
    
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->func_addr = func_addr;
    e->duration_ns = duration_ns;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_ringbuf_submit(e, 0);

    stack->depth = index_to_access; // 更新 depth
    if (stack->depth == 0) {
        // Optional: clear the stack entry if no longer needed,
        // but since it's a per-cpu array, we can just leave it.
    }
    // --- Verifier-Friendly Code End ---

    return 0;
}

char LICENSE[] SEC("license") = "GPL";