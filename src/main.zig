const std = @import("std");
const c = @cImport({
    @cInclude("bpf/libbpf.h");
});

const PROG_BPF = @embedFile("@PROG_BPF");

const LibBpfError = error{ OpenError, LoadError, AttachError };

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

    while (true) {
        std.time.sleep(1_000_000_000);
        try stdout.writeAll(".");
    }
}
