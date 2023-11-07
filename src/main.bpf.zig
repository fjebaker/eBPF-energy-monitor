const std = @import("std");
const builtin = @import("builtin");
const eBPF = std.os.linux.BPF;
const kern = eBPF.kern;
const helpers = kern.helpers;

const c = @cImport({
    @cInclude("vmlinux.h");
});

const arch = builtin.target.cpu.arch;
const KernelError = error{KernelReadError};

inline fn printk(comptime fmt: [:0]const u8, arg: u64, arg2: u64) void {
    _ = helpers.trace_printk(fmt.ptr, fmt.len + 1, arg, arg2, 0);
}

const Registers = struct {
    di: u64,
    si: u64,
    dx: u64,
    cx: u64,
    r8: u64,

    pub fn fromRawArgs(r: RawArgs) Registers {
        const regs: *c.pt_regs = @ptrCast(&r.ptr[0]);
        return .{
            .di = regs.di,
            .si = regs.si,
            .dx = regs.dx,
            .cx = regs.cx, // would be r10 for a syscall arg 3
            .r8 = regs.r8,
        };
    }
};

const RawArgs = extern struct {
    ptr: [*]u64,
};

const SchedSwitch = extern struct {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: u32,

    prev_comm: [16]u8,
    prev_pid: u32,
    prev_prio: u32,
    prev_state: u64,
    next_comm: [16]u8,
    next_pid: u32,
    next_prio: u32,
};

export fn context_monitor(
    ctx: *SchedSwitch,
) linksection("tp/sched/sched_switch") c_int {
    printk("From %d -> %d", ctx.prev_pid, ctx.next_pid);
    return 0;
}

export const LICENSE linksection("license") = "Dual BSD/GPL".*;
