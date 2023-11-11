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
                const elapsed: f32 = @floatFromInt(t);
                const total: f32 = @floatFromInt(tot);

                o.* = elapsed / total;
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

pub const TimeStamp = struct {
    time: u64,
    usage: f32,
};

pub const PidUsage = struct {
    pid: u32,
    usage: []TimeStamp,
};

pub const EnergyUsage = struct {
    pub const Tracker = std.AutoHashMap(u32, std.ArrayList(TimeStamp));

    alloc: std.mem.Allocator,
    trackers: []Tracker,

    pub fn init(alloc: std.mem.Allocator, N: usize) !EnergyUsage {
        var trackers = try alloc.alloc(Tracker, N);
        errdefer alloc.free(trackers);

        for (trackers) |*e| e.* = Tracker.init(alloc);

        return .{ .alloc = alloc, .trackers = trackers };
    }

    pub fn toPidUsage(self: *const EnergyUsage, alloc: std.mem.Allocator, index: usize) ![]PidUsage {
        var pids = try alloc.alloc(PidUsage, self.trackers[index].count());
        errdefer alloc.free(pids);

        var itt = self.trackers[index].iterator();
        var i: usize = 0;
        while (itt.next()) |entry| {
            const pid = entry.key_ptr.*;
            const usage = entry.value_ptr.items;
            pids[i] = .{ .pid = pid, .usage = usage };
            i += 1;
        }

        return pids;
    }

    pub fn pushUsage(
        self: *EnergyUsage,
        cpu: usize,
        pid: u32,
        time: u64,
        value: f32,
    ) !void {
        var tracker = &self.trackers[cpu];

        if (tracker.contains(pid)) {
            var list = tracker.getPtr(pid).?;
            try list.append(.{ .time = time, .usage = value });
        } else {
            var list = std.ArrayList(TimeStamp).init(self.alloc);
            errdefer list.deinit();

            try list.append(.{ .time = time, .usage = value });

            try tracker.putNoClobber(pid, list);
        }
    }

    pub fn deinit(self: *EnergyUsage) void {
        for (self.trackers) |*t| {
            var itt = t.valueIterator();
            while (itt.next()) |v| {
                v.deinit();
            }
            t.deinit();
        }
        self.alloc.free(self.trackers);
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
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    // var alloc = gpa.allocator();

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

    var usage = try EnergyUsage.init(alloc, 2);
    defer usage.deinit();

    var counter: usize = 0;

    std.time.sleep(std.time.ns_per_s);
    while (true) {
        const time_start = std.time.nanoTimestamp();

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

        const now_milis: u64 = @intCast(@divFloor(time_start, 1000));

        // sum over socket
        for (0.., energy_diff) |i, diff| {
            const j1 = i * 2;

            const total_socket_time: f32 = @floatFromInt(
                data.times[j1] + data.times[j1 + 1],
            );
            const energy_difference: f32 = @floatFromInt(diff);

            var itt = data.data.iterator();
            while (itt.next()) |entry| {
                const proc = entry.value_ptr;
                const t1: f32 = @floatFromInt(proc.times[j1]);
                const t2: f32 = @floatFromInt(proc.times[j1 + 1]);

                const total_time = t1 + t2;

                const occupation = total_time / total_socket_time;
                const pid_energy = occupation * energy_difference;

                try usage.pushUsage(i, entry.key_ptr.*, now_milis, pid_energy);
            }
        }

        data.clear();
        if (counter == 300) break;
        counter += 1;
        const delta: u64 = @intCast(std.time.nanoTimestamp() - time_start);

        std.time.sleep(std.time.ns_per_s - delta);
    }

    // assemble the output data from views into everything that's already allocated
    // make sure this uses arena allocator

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    var arena_alloc = arena.allocator();

    var cpus = try arena_alloc.alloc(CpuData, init_energies.len);
    for (0.., cpus) |i, *cpu| {
        cpu.* = .{
            .id = i,
            .pid_usage = try usage.toPidUsage(arena_alloc, i),
        };
    }

    var output: OutputStructure = .{ .cpus = cpus };

    const json = try std.json.stringifyAlloc(
        arena_alloc,
        output,
        .{ .whitespace = .indent_4 },
    );

    try std.fs.cwd().writeFile("data.json", json);
}

pub const OutputStructure = struct {
    cpus: []CpuData,
};

pub const CpuData = struct {
    id: usize,
    pid_usage: []PidUsage,
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
