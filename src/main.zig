const std = @import("std");
const bpf = @import("bpf.zig");
const rapl = @import("rapl.zig");

const PROG_BPF = @embedFile("@PROG_BPF");
const RuntimeMap = bpf.HashMap(u32, [8]u32);

const CPU_PATHS = [_][]const u8{
    "intel-rapl:0",
    "intel-rapl:1",
};

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

fn loadBPFAndAttach(alloc: std.mem.Allocator) !bpf.BpfProg {
    // allocate the bytes to heap
    const prog_bytes = try alloc.dupe(u8, PROG_BPF);
    // init the program
    var prog = bpf.BpfProg.initOwned(alloc, prog_bytes);
    errdefer prog.deinit();

    try prog.load();
    try prog.attach();

    return prog;
}

pub fn main() !void {
    var stdout = std.io.getStdOut();
    var writer = stdout.writer();

    var mem = std.heap.ArenaAllocator.init(
        std.heap.c_allocator,
    );
    defer mem.deinit();
    var alloc = mem.allocator();

    var rapl_reader = rapl.RaplReader(CPU_PATHS.len, CPU_PATHS).init();
    for (rapl_reader.paths) |path| {
        std.debug.print("'{s}'\n", .{path});
    }

    var init_energies = try rapl_reader.read();

    var prog = try loadBPFAndAttach(alloc);
    defer prog.deinit();

    var hmap = try prog.getMap(RuntimeMap, "runtime_lookup");
    var list = std.ArrayList(ProcessData).init(alloc);
    while (true) {
        std.time.sleep(1_000_000_000);

        var current_energies = try rapl_reader.read();

        var energy_diff: [current_energies.len]u64 = undefined;
        for (0..energy_diff.len) |i| {
            energy_diff[i] = current_energies[i] -| init_energies[i];
            // overwrite for next loop
            init_energies[i] = current_energies[i];
        }

        try readFromBPF(&list, &hmap);
        try printTopN(writer, list.items, 5);
        try printEnergy(writer, &energy_diff);
        try writer.writeAll("\n");

        list.items.len = 0; // defacto free all
    }
}

fn readFromBPF(list: *std.ArrayList(ProcessData), map: *RuntimeMap) !void {
    map.reset();
    // iterate over all keys, read and remove them
    while (map.nextKey()) |key| {
        const values = map.pop(key) orelse continue;
        try list.append(ProcessData.init(key, values));
    }

    // sort by which processes had cumilatively the longest time across all cores
    std.sort.insertion(ProcessData, list.items, {}, totalTimeSort);
    // descending order
    std.mem.reverse(ProcessData, list.items);
}

fn sumIndex(items: []const ProcessData, index: usize) u32 {
    var total: u32 = 0;
    for (items) |item| {
        total += item.times[index];
    }
    return total;
}

fn printEnergy(writer: anytype, items: []const u64) !void {
    try writer.writeAll("Energy (uj) : ");
    for (items) |i| {
        try writer.print(" {d: >17}", .{i});
    }
    try writer.writeAll("\n");
}

fn printTopN(writer: anytype, items: []const ProcessData, N: usize) !void {
    try writer.writeAll("Top 5:\n");

    for (items, 0..) |item, i| {
        if (i > N) break;
        try writer.print("PID {d: >8}: ", .{item.pid});
        for (item.times, 0..) |time, k| {
            // ignore every second one
            // for some reason those are always zero or 1?
            // todo: find out why
            if (k % 2 == 1) continue;
            try writer.print(" {d: >8}", .{time});
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("----\nTot         : ");
    for (0..8) |i| {
        if (i % 2 == 1) continue;
        const tot = sumIndex(items, i);
        try writer.print(" {d: >8}", .{tot});
    }

    try writer.writeAll("\n");
}
