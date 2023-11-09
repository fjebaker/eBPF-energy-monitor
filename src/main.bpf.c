#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef struct {
    // cannot be used but needed for verifier
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    // struct arguments from
    // `/sys/kernel/tracing/events/sched/sched_switch/format`
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;

} sched_switch_s;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} time_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} runtime_lookup SEC(".maps");

// swap prev -> new
// record time stamp at which new went in
// lookup when prev went in
// print how long it was in

inline int update_runtime(int *pid, int delta) {
    // check if we have the element already, if so, increment
    // else set it to delta
    int time_delta = delta;
    int *current = (int *) bpf_map_lookup_elem(&runtime_lookup, pid);

    if (current != 0) {
       time_delta += (*current);
    }

    return bpf_map_update_elem(&runtime_lookup, pid, &time_delta, BPF_ANY);
}

SEC("tp/sched/sched_switch")
int context_monitor(sched_switch_s *ctx) {
    int ts = bpf_ktime_get_ns();
    int smp_id = bpf_get_smp_processor_id();

    int prev_pid = ctx->prev_pid;
    int next_pid = ctx->next_pid;

    int *old_ts_ptr = (int *) bpf_map_lookup_elem(&time_lookup, &prev_pid);
    if (old_ts_ptr != 0) {
        // calculate and print the delta of the out process
        int delta = ts - (*old_ts_ptr);
        bpf_printk("SMP %d: %d ns for  %d", smp_id, delta, ctx->prev_pid );
        update_runtime(&prev_pid, delta);
    }

    // write the time the current process went in
    bpf_map_update_elem(&time_lookup, &next_pid, &ts, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
