const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
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

    // get the object output path and strip it
    //
    const c_obj_path = c_obj.getEmittedBin();
    const install = b.addInstallFile(c_obj_path, "c-bpf.o");

    const strip_cmd = b.addSystemCommand(&.{
        "llvm-strip",
        "-g",
    });
    strip_cmd.addFileArg(c_obj_path);
    strip_cmd.step.dependOn(&install.step);

    // install the object path for inspection purposes, after it has been stripped
    b.getInstallStep().dependOn(&strip_cmd.step);

    const exe = b.addExecutable(.{
        .name = "emon",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();
    exe.addIncludePath(.{ .path = "/usr/include" });
    exe.addIncludePath(.{ .path = "include" });
    exe.linkSystemLibrary("bpf");

    exe.addAnonymousModule("@PROG_BPF", .{ .source_file = c_obj_path });

    exe.step.dependOn(&strip_cmd.step);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the application");
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    run_step.dependOn(&run_cmd.step);
}
