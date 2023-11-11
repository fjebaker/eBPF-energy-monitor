const std = @import("std");
const bpf = @import("bpf.zig");
const rapl = @import("rapl.zig");

const PROG_BPF = @embedFile("@PROG_BPF");
const RuntimeMap = bpf.HashMap(u32, [8]u32);

const CPU_PATHS = [_][]const u8{
    "intel-rapl:0",
    "intel-rapl:1",
};

pub const PidEntry = struct {
    times: []u32,
    occupancy: []f32,
    total_time: u64,

    pub fn init(alloc: std.mem.Allocator, all_times: [8]u32) !PidEntry {
        var times = try alloc.alloc(u32, 4);
        var occupancy = try alloc.alloc(f32, 4);

        var total_time: u64 = 0;
        for (times, 0..) |*t, i| {
            t.* = all_times[i * 2];
            total_time += t.*;
        }
        return .{
            .times = times,
            .occupancy = occupancy,
            .total_time = total_time,
        };
    }
};

pub const EnergyTracker = struct {
    pub const TimeSeries = std.ArrayList(u32);

    usage: TimeSeries,

    pub fn init(alloc: std.mem.Allocator) EnergyTracker {
        return .{ .usage = TimeSeries.init(alloc) };
    }
};

pub const RawData = struct {
    pub const PidMap = std.AutoHashMap(u32, PidEntry);

    data: PidMap,
    arena: std.heap.ArenaAllocator,
    times: []u64,

    pub fn init(alloc: std.mem.Allocator, n_proc: usize) !RawData {
        var times = try alloc.alloc(u64, n_proc);
        return .{
            .data = PidMap.init(alloc),
            .arena = std.heap.ArenaAllocator.init(alloc),
            .times = times,
        };
    }

    pub fn deinit(self: *RawData) void {
        self.data.deinit();
        self.arena.child_allocator.free(self.times);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *RawData) void {
        self.data.clearRetainingCapacity();
    }

    // Caller owns the memory
    pub fn getPids(self: *const RawData, alloc: std.mem.Allocator) ![]u32 {
        var pids = try std.ArrayList(u32).initCapacity(alloc, self.data.count());
        errdefer pids.deinit();

        var itt = self.data.keyIterator();
        while (itt.next()) |key| {
            try pids.append(key.*);
        }

        return pids.toOwnedSlice();
    }

    fn durationSort(self: *const RawData, lhs: u32, rhs: u32) bool {
        const lhs_entry = self.data.get(lhs).?;
        const rhs_entry = self.data.get(rhs).?;
        return lhs_entry.total_time > rhs_entry.total_time;
    }

    // Caller owns the memory
    pub fn getOccupancySortedPids(
        self: *const RawData,
        alloc: std.mem.Allocator,
    ) ![]u32 {
        var pids = try self.getPids(alloc);

        std.sort.insertion(u32, pids, self, durationSort);
        return pids;
    }

    fn pushEntry(rd: *RawData, pid: u32, entry: PidEntry) !void {
        var existing: *PidEntry = rd.data.getPtr(pid) orelse {
            try rd.data.putNoClobber(pid, entry);
            return;
        };

        for (0..existing.occupancy.len) |i| {
            existing.times[i] += entry.times[i];
            existing.total_time += entry.total_time;
        }
    }

    fn calculateOccupancy(self: *RawData) void {
        var itt = self.data.valueIterator();

        while (itt.next()) |vptr| {
            for (vptr.occupancy, vptr.times, self.times) |*o, t, tot| {
                const time: f32 = @floatFromInt(t);
                const total: f32 = @floatFromInt(tot);

                o.* = time / total;
            }
        }
    }

    pub fn readMap(rd: *RawData, map: *RuntimeMap) !void {
        // reset the map before we read so that we iterate the keys
        map.reset();

        for (rd.times) |*t| t.* = 0;

        var alloc = rd.arena.allocator();

        while (map.nextKey()) |key| {
            const values = map.pop(key) orelse continue;
            const entry = try PidEntry.init(alloc, values);

            try rd.pushEntry(key, entry);

            for (rd.times, entry.times) |*t, add| {
                t.* += add;
            }
        }

        rd.calculateOccupancy();
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

    var alloc = std.heap.c_allocator;

    var rapl_reader = rapl.RaplReader(CPU_PATHS.len, CPU_PATHS).init();
    for (rapl_reader.paths) |path| {
        std.debug.print("'{s}'\n", .{path});
    }

    var init_energies = try rapl_reader.read();

    var prog = try loadBPFAndAttach(alloc);
    defer prog.deinit();

    var hmap = try prog.getMap(RuntimeMap, "runtime_lookup");

    var data = try RawData.init(alloc, 4);
    defer data.deinit();

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

        try data.readMap(&hmap);
        try printTopN(alloc, writer, data, 5);

        try writer.print("----\nTotal number of procs: {d}\n", .{data.data.count()});
        try writer.writeAll("----\nTot         : ");
        try printLine(writer, u64, data.times, false);
        try writer.writeAll("\n");

        try printEnergy(writer, &energy_diff);
        try writer.writeAll("\n");

        // sum over socket
        // for (0.., energy_diff) |i, en| {
        //     const i_1 = i * 2;
        //     const i_2 = (i + 1) * 2;

        //     const total_cpu_time: f32 = @floatFromInt(mon.times[i] + mon.times[i + 1]);
        //     const energy: f32 = @floatFromInt(en);

        //     for (mon.procs.items) |proc| {
        //         const t1: f32 = @floatFromInt(proc.times[i_1]);
        //         const t2: f32 = @floatFromInt(proc.times[i_2]);
        //         const e_usage = (t1 + t2) / total_cpu_time * energy;
        //         try usage.put(i, proc.pid, e_usage);
        //     }
        // }

        data.clear();
        // if (counter == 2) break;
        counter += 1;
    }

    // assemble the output data from views into everything that's already allocated
    // make sure this uses arena allocator

    // var cpus = try alloc.alloc(CpuData, init_energies.len);
    // for (0.., cpus) |i, *cpu| {
    //     cpu.* = try gatherCPU(alloc, usage, i);
    // }

    // var output: OutputStructure = .{ .cpus = cpus };

    // const json = try std.json.stringifyAlloc(
    //     alloc,
    //     output,
    //     .{ .whitespace = .indent_4 },
    // );

    // try std.fs.cwd().writeFile("data.json", json);
}

pub const OutputStructure = struct {
    cpus: []CpuData,
};

pub fn gatherCPU(
    alloc: std.mem.Allocator,
    data: EnergyUsage,
    id: usize,
) !CpuData {
    var pids = try alloc.alloc(PidData, data.emaps[id].count());
    errdefer alloc.free(pids);

    var itt = data.emaps[id].iterator();
    var i: usize = 0;
    while (itt.next()) |entry| {
        std.debug.print("{any}\n", .{entry.value_ptr.items});
        pids[i] = .{
            .pid = entry.key_ptr.*,
            // .usage = entry.value_ptr.items,
        };
    }

    return .{ .id = id, .pid_usage = pids };
}

pub const PidData = struct {
    pid: u32,
    // usage: []f32,
};
pub const CpuData = struct {
    id: usize,
    pid_usage: []PidData,
};

fn printEnergy(writer: anytype, items: []const u64) !void {
    try writer.writeAll("Energy (uj) : ");
    for (items) |i| {
        try writer.print(" {d: >31}", .{i});
    }
    try writer.writeAll("\n");
}

fn printTopN(alloc: std.mem.Allocator, writer: anytype, data: RawData, N: usize) !void {
    var ordered_pids = try data.getOccupancySortedPids(alloc);
    defer alloc.free(ordered_pids);

    try writer.writeAll("Top 5:\n");

    for (ordered_pids, 0..) |pid, i| {
        if (i > N) break;

        const entry = data.data.get(pid).?;

        try writer.print("PID {d: >8}: ", .{pid});
        for (entry.times, entry.occupancy) |t, o| {
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
