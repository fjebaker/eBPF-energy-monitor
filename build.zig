const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const arch = (target.cpu_arch orelse builtin.cpu.arch);
    const bpf_target: std.zig.CrossTarget =
        .{
        .cpu_arch = switch (arch.endian()) {
            .Big => .bpfeb,
            .Little => .bpfel,
        },
        .os_tag = .freestanding,
    };

    const obj = b.addObject(.{
        .name = "zig-bpf-prog",
        .root_source_file = .{ .path = "src/main.bpf.zig" },
        .target = bpf_target,
        .optimize = .ReleaseFast,
    });
    obj.addIncludePath(.{ .path = "include" }); // to get the vmlinux.h
    obj.strip = true;

    // the magic
    const install = b.addInstallFile(obj.getEmittedBin(), "zig-bpf.o");
    b.getInstallStep().dependOn(&install.step);
}
