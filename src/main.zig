const std = @import("std");
const bpf = @import("bpf.zig");

const PROG_BPF = @embedFile("@PROG_BPF");

const RuntimeMap = bpf.HashMap(u32, [8]u32);

pub fn main() !void {
    var stdout = std.io.getStdOut();

    var mem = std.heap.ArenaAllocator.init(
        std.heap.c_allocator,
    );
    defer mem.deinit();
    var alloc = mem.allocator();

    // allocate the bytes to heap
    const prog_bytes = try alloc.dupe(u8, PROG_BPF);
    // init the program
    var prog = bpf.BpfProg.init(alloc, prog_bytes);
    defer prog.deinit();

    try prog.load();
    try prog.attach();

    var hmap = try prog.getMap(RuntimeMap, "runtime_lookup");

    try stdout.writeAll("Entering main loop\n");
    var writer = stdout.writer();

    var list = std.ArrayList(ProcessData).init(alloc);
    while (true) {
        std.time.sleep(1_000_000_000);

        hmap.reset();

        while (hmap.nextKey()) |key| {
            const values = hmap.pop(key) orelse continue;
            try list.append(ProcessData.init(key, values));
        }

        // sort by which processes had cumilatively the longest time
        std.sort.insertion(ProcessData, list.items, {}, totalTimeSort);
        std.mem.reverse(ProcessData, list.items);

        for (list.items[1..], 0..) |item, i| {
            if (i > 5) break;
            try writer.print("PID {d: >8}: ", .{item.pid});
            for (item.times, 0..) |time, k| {
                if (k % 2 == 1) continue;
                try writer.print(" {d: >8}", .{time});
            }
            try writer.writeAll("\n");
        }
        try writer.writeAll("\n");

        list.items.len = 0; // defacto free all
    }
}

const ProcessData = struct {
    pid: u32,
    times: [8]u32,
    sum_times: u32,

    fn init(pid: u32, times: [8]u32) ProcessData {
        var sum: u32 = 0;
        for (times) |t| {
            sum +|= t;
        }
        return .{ .pid = pid, .times = times, .sum_times = sum };
    }
};

fn totalTimeSort(_: void, lhs: ProcessData, rhs: ProcessData) bool {
    return lhs.sum_times < rhs.sum_times;
}

const MAP_PIN_FILE = "/sys/fs/bpf/runtime_lookup-map";
