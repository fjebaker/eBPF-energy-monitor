const std = @import("std");

fn ct_intToString(comptime value: comptime_int) []const u8 {
    if (value < 0) @compileError("Cannot convert negative value");
    const s: []const u8 = @typeName([value]void);
    return s[1 .. s.len - 5];
}

const SYSFS_ROOT = "/sys/devices/virtual/powercap/intel-rapl/";

pub fn RaplReader(comptime N: comptime_int, comptime Paths: [N][]const u8) type {
    // make paths to all files
    comptime var path_builder: [N][]const u8 = undefined;

    inline for (0.., Paths) |i, path| {
        path_builder[i] = SYSFS_ROOT ++ path ++ "/energy_uj";
    }

    return struct {
        const Self = @This();

        paths: [N][]const u8 = path_builder,

        pub fn init() Self {
            return .{};
        }

        pub fn read(self: *const Self) ![N]u64 {
            var values: [N]u64 = undefined;

            var buffer: [32]u8 = undefined;
            for (0.., self.paths) |i, path| {
                const f = try std.fs.openFileAbsolute(path, .{});
                defer f.close();
                const size = try f.readAll(&buffer);
                // remove trailing whitespace
                const number = buffer[0 .. size - 1];
                values[i] = try std.fmt.parseInt(u64, number, 10);
            }

            return values;
        }
    };
}
