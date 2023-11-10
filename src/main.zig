const std = @import("std");
const c = @cImport({
    @cInclude("bpf/libbpf.h");
});

const PROG_BPF = @embedFile("@PROG_BPF");

const LibBpfError = error{
    OpenError,
    LoadError,
    AttachError,
    NoSuchMap,
    FailedToPin,
};

pub const BpfProg = struct {
    const LinkList = std.ArrayList(*c.bpf_link);

    alloc: std.mem.Allocator,
    bytes: []const u8,

    obj: ?*c.struct_bpf_object = null,
    links: LinkList,

    pub fn init(alloc: std.mem.Allocator, bytes: []const u8) BpfProg {
        const links = LinkList.init(alloc);
        return .{
            .alloc = alloc,
            .bytes = bytes,
            .links = links,
        };
    }

    fn attachProg(bp: *BpfProg, prog: *c.bpf_program) !void {
        const link = c.bpf_program__attach(prog);
        if (link) |l| {
            try bp.links.append(l);
        } else {
            return LibBpfError.AttachError;
        }
    }

    pub fn attach(bp: *BpfProg) !void {
        var current: ?*c.bpf_program = null;
        while (c.bpf_object__next_program(bp.obj, current)) |prog| {
            current = prog;
            try bp.attachProg(prog);
        }
    }

    pub fn destroyAllLinks(bp: *BpfProg) void {
        for (bp.links.items) |link| {
            _ = c.bpf_link__destroy(link);
        }
    }

    pub fn deinit(bp: *BpfProg) void {
        bp.destroyAllLinks();
        bp.links.deinit();
        bp.close();
        bp.alloc.free(bp.bytes);
        bp.* = undefined;
    }

    pub fn close(bp: *BpfProg) void {
        if (bp.obj) |obj| {
            c.bpf_object__close(obj);
        }
    }

    pub fn load(bp: *BpfProg) !void {
        bp.obj = c.bpf_object__open_mem(bp.bytes.ptr, bp.bytes.len, null) orelse
            return LibBpfError.OpenError;

        const ret = c.bpf_object__load(bp.obj);
        if (ret != 0) {
            return LibBpfError.LoadError;
        }
    }

    pub fn getMap(bp: *BpfProg, name: []const u8) !c_int {
        const map_ptr = c.bpf_object__find_map_by_name(bp.obj, name.ptr);
        if (map_ptr) |ptr| {
            return c.bpf_map__fd(ptr);
        }
        return LibBpfError.NoSuchMap;
    }
};

pub const BpfMap = struct {
    alloc: std.mem.Allocator,
    fd: c_int,

    pub fn init(alloc: std.mem.Allocator, fd: c_int) BpfMap {
        return .{ .alloc = alloc, .fd = fd };
    }
};

pub fn main() !void {
    var stdout = std.io.getStdOut();

    var mem = std.heap.ArenaAllocator.init(
        std.heap.c_allocator,
    );
    defer mem.deinit();
    var alloc = mem.allocator();

    // allocate the bytes to heap
    const prog_bytes = try alloc.dupe(u8, PROG_BPF);
    var prog = BpfProg.init(alloc, prog_bytes);
    defer prog.deinit();

    try prog.load();
    try prog.attach();

    var map_ptr = c.bpf_object__find_map_by_name(prog.obj, "runtime_lookup").?;
    var hmap = PerCpuHashMap.init(map_ptr);

    try stdout.writeAll("Entering main loop\n");
    var writer = stdout.writer();

    var list = std.ArrayList(ProcessData).init(alloc);
    while (true) {
        std.time.sleep(1_000_000_000);

        hmap.reset();

        while (hmap.next()) |key| {
            const values = hmap.get(key) orelse continue;
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

const PerCpuHashMap = struct {
    map: *c.struct_bpf_map,
    fd: c_int,
    key: ?u32 = null,

    pub fn init(map: *c.struct_bpf_map) PerCpuHashMap {
        const fd = c.bpf_map__fd(map);
        return .{ .map = map, .fd = fd };
    }

    pub fn get(hmap: *PerCpuHashMap, key: u32) ?[8]u32 {
        var values: [8]u32 = .{0} ** 8;
        const ret = c.bpf_map__lookup_elem(
            hmap.map,
            &key,
            @sizeOf(u32),
            &values,
            values.len * @sizeOf(u32),
            0,
        );
        if (ret == 0) {
            return values;
        }
        return null;
    }

    pub fn reset(hmap: *PerCpuHashMap) void {
        hmap.key = null;
    }

    pub fn next(hmap: *PerCpuHashMap) ?u32 {
        const curr: ?*u32 = if (hmap.key) |*key| key else null;
        var next_key: u32 = undefined;
        const ret = c.bpf_map__get_next_key(hmap.map, curr, &next_key, @sizeOf(u32));
        switch (ret) {
            0 => {
                hmap.key = next_key;
                return next_key;
            },
            -1 => return null, // last element
            else => {
                std.debug.print("ret: {d}\n", .{ret});
            },
        }
        return null;
    }
};
