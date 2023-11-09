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

    const c_obj = b.addObject(
        .{
            .name = "c-bpf.o",
            .target = bpf_target,
            .optimize = .ReleaseFast,
        },
    );
    c_obj.addCSourceFile(
        .{
            .file = .{ .path = "src/main.bpf.c" },
            .flags = &.{ "-Wall", "-D__BPF_TRACING__" },
        },
    );
    c_obj.linkLibC();
    c_obj.addIncludePath(.{ .path = "/usr/include" });
    c_obj.addIncludePath(.{ .path = "include" });

    // todo: generate the vmlinux.h
    const install = b.addInstallFile(c_obj.getEmittedBin(), "c-bpf.o");

    const strip_cmd = b.addSystemCommand(&.{
        "llvm-strip",
        "-g",
        "zig-out/c-bpf.o",
    });
    strip_cmd.step.dependOn(&install.step);

    b.getInstallStep().dependOn(&strip_cmd.step);
}
