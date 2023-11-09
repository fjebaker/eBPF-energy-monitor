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

inline fn printk(comptime fmt: [:0]const u8, arg: u64, arg2: u64, arg3: u64) void {
    _ = helpers.trace_printk(fmt.ptr, fmt.len + 1, arg, arg2, arg3);
}

const UpdateType = enum(u64) {
    any = eBPF.ANY,
    no_exist = eBPF.NOEXIST,
    exist = eBPF.EXIST,
};

fn HashMap(comptime symbol_name: []const u8, comptime Val: type) type {
    return extern struct {
        const Self = @This();
        const Key = u32;

        pub const MapError = error{UpdateError};

        const Layout = extern struct {
            type: ?*[@intFromEnum(eBPF.MapType.hash)]u32,
            max_entries: ?*[10240]u32,
            key: *Key,
            value: *Val,
        };

        // how we get the data
        var ptr: Layout = undefined;
        comptime {
            @export(Self.ptr, .{ .name = symbol_name, .section = ".maps" });
        }

        pub fn get(_: *Self, key: Key) ?*Val {
            const elem = helpers.map_lookup_elem(@ptrCast(&ptr), &key);

            if (elem) |e| {
                const val: *Val = @ptrCast(@alignCast(e));
                return val;
            }

            return null;
        }

        pub const UpdateOptions = struct {
            utype: UpdateType = .no_exist,
        };

        pub fn update(_: *Self, key: Key, val: Val, opts: UpdateOptions) !void {
            const ret = helpers.map_update_elem(
                @ptrCast(&ptr),
                &key,
                &val,
                @intFromEnum(opts.utype),
            );
            if (ret != 0)
                return MapError.UpdateError;
        }
    };
}

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

var lookup: HashMap("lookup", u64) = undefined;

inline fn logic(ctx: *SchedSwitch) !void {
    const ts = helpers.ktime_get_ns();
    const smp_id = helpers.get_smp_processor_id();
    // printk("T: %d ID: %d", ts, smp_id, 0);
    printk("%d -> %d", ctx.prev_pid, ctx.next_pid, 0);
    try lookup.update(smp_id, ts, .{ .utype = .any });
}

export fn context_monitor(
    ctx: *SchedSwitch,
) linksection("tp/sched/sched_switch") c_int {
    logic(ctx) catch return 1;
    return 0;
}

export const LICENSE linksection("license") = "Dual BSD/GPL".*;
