const std = @import("std");
const bpf = @import("bpf.zig");
const rapl = @import("rapl.zig");

const PROG_BPF = @embedFile("@PROG_BPF");
const RuntimeMap = bpf.HashMap(u32, [8]u32);

const CPU_PATHS = [_][]const u8{
    "intel-rapl:0",
    "intel-rapl:1",
};

pub const ProcessData = struct {
    pid: u32,
    times: [8]u32,
    occupancy: [8]f32 = .{0} ** 8,
    sum_times: u32,

    fn init(pid: u32, times: [8]u32) ProcessData {
        var sum: u32 = 0;
        for (0.., times) |i, t| {
            if (i % 2 == 1) continue;
            sum +|= t;
        }
        return .{ .pid = pid, .times = times, .sum_times = sum };
    }
};

pub const Monitor = struct {
    alloc: std.mem.Allocator,
    times: []u64,
    procs: std.ArrayList(ProcessData),

    pub fn init(alloc: std.mem.Allocator, nprocs: usize) !Monitor {
        var times = try alloc.alloc(u64, nprocs);
        return .{
            .alloc = alloc,
            .times = times,
            .procs = std.ArrayList(ProcessData).init(alloc),
        };
    }

    pub fn deinit(m: *Monitor) void {
        m.alloc.free(m.times);
        m.procs.deinit();
        m.* = undefined;
    }

    pub fn clear(m: *Monitor) void {
        // defactor free all without freeing
        m.procs.items.len = 0;
    }

    pub fn readMap(m: *Monitor, map: *RuntimeMap) !void {
        // reset the map before we read so that we iterate the keys
        map.reset();

        while (map.nextKey()) |key| {
            const values = map.pop(key) orelse continue;
            try m.procs.append(ProcessData.init(key, values));
        }

        // sort by which processes had cumilatively the longest time across all cores
        std.sort.insertion(ProcessData, m.procs.items, {}, totalTimeSort);
        // descending order
        std.mem.reverse(ProcessData, m.procs.items);

        m.integrateTimes();

        m.calculateOccupancy();
    }

    fn calculateOccupancy(m: *Monitor) void {
        for (m.procs.items) |*proc| {
            var occupancy: [8]f32 = undefined;
            for (0.., m.times) |i, total_time| {
                occupancy[i * 2] =
                    @as(
                    f32,
                    @floatFromInt(proc.times[i * 2]),
                ) / @as(
                    f32,
                    @floatFromInt(total_time),
                );
            }
            proc.occupancy = occupancy;
        }
    }

    fn sumIndex(items: []const ProcessData, index: usize) u32 {
        var total: u32 = 0;
        for (items) |item| {
            total += item.times[index];
        }
        return total;
    }

    fn integrateTimes(m: *Monitor) void {
        for (m.times, 0..) |*t, i| {
            // again have to account for the skip so mult by 2
            t.* = sumIndex(m.procs.items, i * 2);
        }
    }
};

pub const EnergyUsage = struct {
    const EMap = std.AutoHashMap(u32, std.ArrayList(f32)); // pid -> energy time series

    alloc: std.mem.Allocator,
    emaps: []EMap,
    times: std.ArrayList(u64),

    pub fn init(alloc: std.mem.Allocator, N: usize) !EnergyUsage {
        var emaps = try alloc.alloc(EMap, N);
        errdefer alloc.free(emaps);

        var times = std.ArrayList(u64).init(alloc);
        errdefer times.deinit();

        for (emaps) |*e| e.* = EMap.init(alloc);

        return .{ .alloc = alloc, .emaps = emaps, .times = times };
    }

    pub fn put(self: *EnergyUsage, index: usize, key: u32, value: f32) !void {
        var map: *EMap = &self.emaps[index];
        if (map.contains(key)) {
            try map.getPtr(key).?.append(value);
        } else {
            var array_list = std.ArrayList(f32).init(self.alloc);
            errdefer array_list.deinit();
            try array_list.append(value);
            try map.put(key, array_list);
        }
    }

    pub fn deinit(self: *EnergyUsage) void {
        for (self.emaps) |*e| {
            var itt = e.valueIterator();
            while (itt.next()) |v| {
                v.deinit();
            }
            e.deinit();
        }
        self.alloc.free(self.emaps);
        self.times.deinit();
        self.* = undefined;
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

    var mon = try Monitor.init(alloc, 4);
    defer mon.deinit();

    var usage = try EnergyUsage.init(alloc, 2);
    defer usage.deinit();

    var counter: usize = 0;
    while (true) {
        std.time.sleep(1_000_000_000);

        var current_energies = try rapl_reader.read();

        var energy_diff: [current_energies.len]u64 = undefined;
        for (0..energy_diff.len) |i| {
            energy_diff[i] = current_energies[i] -| init_energies[i];
            // overwrite for next loop
            init_energies[i] = current_energies[i];
        }

        try mon.readMap(&hmap);
        try printTopN(writer, mon.procs.items, 5);

        try writer.print("----\nTotal number of procs: {d}\n", .{mon.procs.items.len});
        try writer.writeAll("----\nTot         : ");
        try printLine(writer, u64, mon.times, false);
        try writer.writeAll("\n");

        try printEnergy(writer, &energy_diff);
        try writer.writeAll("\n");

        // sum over socket
        for (0.., energy_diff) |i, en| {
            const i_1 = i * 2;
            const i_2 = (i + 1) * 2;

            const total_cpu_time: f32 = @floatFromInt(mon.times[i] + mon.times[i + 1]);
            const energy: f32 = @floatFromInt(en);

            for (mon.procs.items) |proc| {
                const t1: f32 = @floatFromInt(proc.times[i_1]);
                const t2: f32 = @floatFromInt(proc.times[i_2]);
                const e_usage = (t1 + t2) / total_cpu_time * energy;
                try usage.put(i, proc.pid, e_usage);
            }
        }

        mon.clear();
        if (counter == 20) break;
        counter += 1;
    }
}

const OutputStructure = struct {
    times: []u64,
    cpu: struct {
        id: usize,
        pids: struct {
            pid: u32,
            usage: []f32,
        },
    },
};

fn printEnergy(writer: anytype, items: []const u64) !void {
    try writer.writeAll("Energy (uj) : ");
    for (items) |i| {
        try writer.print(" {d: >31}", .{i});
    }
    try writer.writeAll("\n");
}

fn printTopN(writer: anytype, items: []const ProcessData, N: usize) !void {
    try writer.writeAll("Top 5:\n");

    for (items, 0..) |proc, i| {
        if (i > N) break;
        try writer.print("PID {d: >8}: ", .{proc.pid});
        for (0.., proc.times, proc.occupancy) |k, t, o| {
            if (k % 2 == 1) continue;
            try writer.print(" {d: >8} ({d: >3.0}%)", .{ t, o * 100 });
        }
        try writer.writeAll("\n");
    }
}

fn printLine(writer: anytype, comptime T: type, items: []const T, skip: bool) !void {
    for (0.., items) |i, v| {
        if (skip and i % 2 == 1) continue;
        try writer.print(" {d: >15}", .{v});
    }
}
