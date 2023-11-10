const std = @import("std");

// using the system library for now
// could also vendor the libbpf source code and compile it with zig
pub const c = @cImport({
    @cInclude("bpf/libbpf.h");
});

pub const LibBpfError = error{
    OpenError,
    LoadError,
    AttachError,
    NoSuchMap,
    FailedToPin,
};

/// Wrapper struct around core functions of `libbpf` to provide more
/// zig idiomatic abstractions and safety
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

    pub fn getMap(bp: *BpfProg, comptime MapType: type, name: []const u8) !MapType {
        const map_ptr = c.bpf_object__find_map_by_name(bp.obj, name.ptr);
        if (map_ptr) |ptr| {
            return MapType.init(ptr);
        }
        return LibBpfError.NoSuchMap;
    }
};

pub fn HashMap(comptime K: type, comptime V: type) type {
    return struct {
        // provide public accessors to the child types
        pub const Key = K;
        pub const Value = V;

        const Self = @This();

        map: *c.struct_bpf_map,
        fd: c_int,
        key: ?Key = null,

        pub fn init(map: *c.struct_bpf_map) Self {
            const fd = c.bpf_map__fd(map);
            return .{ .map = map, .fd = fd };
        }

        fn getImpl(self: *Self, comptime lookup_func: anytype, key: Key) ?Value {
            var value: Value = undefined;

            const ret = lookup_func(
                self.map,
                &key,
                @sizeOf(Key),
                &value,
                @sizeOf(Value),
                0, // todo: what are these flags?
            );

            if (ret == 0) {
                return value;
            }

            return null;
        }

        /// Get value associated with the key
        /// Returns null if element not found
        pub fn get(self: *Self, key: Key) ?Value {
            return self.getImpl(c.bpf_map__lookup_elem, key);
        }

        /// Get and remove the value associated with the key
        /// Returns null if element not found
        pub fn pop(self: *Self, key: Key) ?Value {
            return self.getImpl(c.bpf_map__lookup_and_delete_elem, key);
        }

        /// Reset the iteration to the first element
        pub fn reset(self: *Self) void {
            self.key = null;
        }

        /// Get the next key in the iteration. Returns null if no
        /// more keys left.
        pub fn nextKey(self: *Self) ?Key {
            // get a ptr or null ptr to current key
            var key: ?*Key = if (self.key) |*key| key else null;
            var next_key: Key = undefined;

            const ret = c.bpf_map__get_next_key(
                self.map,
                key,
                &next_key,
                @sizeOf(Key),
            );

            switch (ret) {
                // ok
                0 => {
                    self.key = next_key;
                    return next_key;
                },
                // last element
                -2 => return null,
                else => {
                    // todo: return an error once i find the error docs
                    std.debug.print("ret: {d}\n", .{ret});
                },
            }
            return null;
        }
    };
}

const PerCpuHashMap = struct {};
