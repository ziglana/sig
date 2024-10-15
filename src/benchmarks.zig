const std = @import("std");
const builtin = @import("builtin");

const sig = @import("sig.zig");
const Duration = sig.time.Duration;

const Decl = std.builtin.Type.Declaration;

const io = std.io;
const math = std.math;
const meta = std.meta;

/// to run gossip benchmarks:
/// zig build benchmark -- gossip
pub fn main() !void {
    const allocator = std.heap.c_allocator;

    if (builtin.mode == .Debug) std.debug.print("warning: running benchmark in Debug mode\n", .{});

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_filter = cli_args.next();
    const filter = blk: {
        if (maybe_filter) |filter| {
            std.debug.print("filtering benchmarks with prefix: {s}\n", .{filter});
            break :blk filter;
        } else {
            std.debug.print("no filter: running all benchmarks\n", .{});
            break :blk "";
        }
    };

    // TODO: very manual for now (bc we only have 2 benchmarks)
    // if we have more benchmarks we can make this more efficient
    const max_time_per_bench = 2 * std.time.ms_per_s; // !!
    const run_all_benchmarks = filter.len == 0;

    if (std.mem.startsWith(u8, filter, "swissmap") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            @import("accountsdb/index.zig").BenchmarkSwissMap,
            max_time_per_bench,
            .microseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "geyser") or run_all_benchmarks) {
        std.debug.print("Geyser Streaming Benchmark:\n", .{});
        try @import("geyser/lib.zig").benchmark.runBenchmark();
    }

    if (std.mem.startsWith(u8, filter, "accounts_db") or run_all_benchmarks) {
        var run_all = false;
        if (std.mem.eql(u8, "accounts_db", filter) or run_all_benchmarks) {
            run_all = true;
        }

        if (std.mem.eql(u8, "accounts_db_readwrite", filter) or run_all) {
            try benchmarkCSV(
                allocator,
                @import("accountsdb/db.zig").BenchmarkAccountsDB,
                max_time_per_bench,
                .seconds,
            );
        }

        if (std.mem.eql(u8, "accounts_db_snapshot", filter) or run_all) blk: {
            // NOTE: for this benchmark you need to setup a snapshot in test-data/snapshot_bench
            // and run as a binary ./zig-out/bin/... so the open file limits are ok
            const dir_path = sig.TEST_DATA_DIR ++ "bench_snapshot/";
            var snapshot_dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
                std.debug.print("[accounts_db_snapshot]: need to setup a snapshot in {s} for this benchmark...\n", .{dir_path});
                break :blk;
            };
            snapshot_dir.close();

            try benchmarkCSV(
                allocator,
                @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                max_time_per_bench,
                .seconds,
            );
        }
    }

    if (std.mem.startsWith(u8, filter, "socket_utils") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            @import("net/socket_utils.zig").BenchmarkPacketProcessing,
            max_time_per_bench,
            .milliseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "gossip") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            max_time_per_bench,
            .milliseconds,
        );
        try benchmarkCSV(
            allocator,
            @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            max_time_per_bench,
            .milliseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "sync") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            @import("sync/channel.zig").BenchmarkChannel,
            max_time_per_bench,
            .microseconds,
        );
    }
}

const TimeUnits = enum {
    nanoseconds,
    microseconds,
    milliseconds,
    seconds,

    const Self = @This();

    pub fn toString(self: Self) []const u8 {
        return switch (self) {
            .nanoseconds => "ns",
            .milliseconds => "ms",
            .microseconds => "us",
            .seconds => "s",
        };
    }

    pub fn unitsfromNanoseconds(self: Self, time_ns: u64) !u64 {
        return switch (self) {
            .nanoseconds => time_ns,
            .milliseconds => try std.math.divCeil(u64, time_ns, std.time.ns_per_ms),
            .microseconds => try std.math.divCeil(u64, time_ns, std.time.ns_per_us),
            .seconds => time_ns / std.time.ns_per_s,
        };
    }
};

// src: https://github.com/Hejsil/zig-bench
pub fn benchmarkCSV(
    allocator: std.mem.Allocator,
    comptime B: type,
    max_time: u128,
    time_unit: TimeUnits,
) !void {
    const args = if (@hasDecl(B, "args")) B.args else [_]void{{}};
    const min_iterations = if (@hasDecl(B, "min_iterations")) B.min_iterations else 10000;
    const max_iterations = if (@hasDecl(B, "max_iterations")) B.max_iterations else 100000;

    const functions = comptime blk: {
        var res: []const Decl = &[_]Decl{};
        for (@typeInfo(B).Struct.decls) |decl| {
            if (@typeInfo(@TypeOf(@field(B, decl.name))) != .Fn)
                continue;
            res = res ++ [_]Decl{decl};
        }

        break :blk res;
    };

    if (functions.len == 0) {
        @compileError("No benchmarks to run.");
    }

    inline for (functions, 0..) |def, fcni| {
        _ = fcni;

        inline for (args) |arg| {
            const benchFunction = @field(B, def.name);
            const arguments = switch (@TypeOf(arg)) {
                void => .{},
                else => .{arg},
            };

            // NOTE: @TypeOf guarantees no runtime side-effects of argument expressions.
            // this means the function will *not* be called, this is just computing the return
            // type.
            const result_type: type = @TypeOf(try @call(.auto, benchFunction, arguments));
            const runtime_type = switch (result_type) {
                Duration => struct { result: u64 },
                else => result_type,
            };
            var runtimes: std.MultiArrayList(runtime_type) = .{};
            defer runtimes.deinit(allocator);

            var min: u64 = math.maxInt(u64);
            var max: u64 = 0;
            var runtime_sum: u128 = 0;

            var min_s: runtime_type = undefined;
            var max_s: runtime_type = undefined;

            var i: u64 = 0;
            while (i < min_iterations or
                (i < max_iterations and runtime_sum < max_time)) : (i += 1)
            {
                switch (result_type) {
                    Duration => {
                        const duration = try @call(.auto, benchFunction, arguments);
                        const runtime = try time_unit.unitsfromNanoseconds(duration.asNanos());
                        try runtimes.append(allocator, .{ .result = runtime });
                        runtime_sum += runtime;
                        min = @min(runtimes.items(.result)[i], min);
                        max = @max(runtimes.items(.result)[i], max);
                    },
                    inline else => {
                        const result = try @call(.auto, benchFunction, arguments);
                        try runtimes.append(allocator, result);

                        if (i == 0) {
                            min_s = result;
                            max_s = result;
                        } else {
                            const U = @typeInfo(result_type).Struct;
                            inline for (U.fields) |field| {
                                const f_max = @field(max_s, field.name);
                                const f_min = @field(min_s, field.name);
                                @field(max_s, field.name) = @max(@field(result, field.name), f_max);
                                @field(min_s, field.name) = @min(@field(result, field.name), f_min);
                            }
                        }
                    },
                }
            }

            switch (@TypeOf(arg)) {
                void => {
                    std.debug.print("{s},", .{def.name});
                },
                else => {
                    std.debug.print("{s} ({s}),", .{ def.name, arg.name });
                },
            }

            switch (result_type) {
                Duration => {
                    // print column headers
                    std.debug.print("min,max\n", .{});
                    // print column results
                    std.debug.print("_, {d}, {d}", .{ min, max });
                },
                inline else => {
                    // print column headers
                    const U = @typeInfo(result_type).Struct;
                    inline for (U.fields) |field| {
                        std.debug.print("{s}_max,", .{field.name});
                    }
                    inline for (U.fields) |field| {
                        std.debug.print("{s}_min,", .{field.name});
                    }
                    std.debug.print("\n", .{});
                    // print results
                    std.debug.print("_, ", .{}); // account for the function name
                    inline for (U.fields) |field| {
                        const f_max = @field(max_s, field.name);
                        const f_min = @field(min_s, field.name);
                        std.debug.print("{d}, {d}, ", .{ f_max, f_min });
                    }
                },
            }

            // NOTE: can do this for future functionality
            // const x: std.MultiArrayList(runtime_type).Field = @enumFromInt(j);
            // const f_max = runtimes.items(x)[0];
            std.debug.print("\n", .{});
        }
    }
}

fn printResult(
    writer: anytype,
    min_widths: [6]u64,
    runtime_sum: u128,
    runtimes: []const u64,
    iterations: u64,
    function_name: []const u8,
    arg_name: anytype,
    min: u64,
    max: u64,
) !void {
    const runtime_mean: u64 = @intCast(runtime_sum / iterations);

    var d_sq_sum: u128 = 0;
    for (runtimes[0..iterations]) |runtime| {
        const d = @as(i64, @intCast(@as(i128, @intCast(runtime)) - runtime_mean));
        d_sq_sum += @as(u64, @intCast(d * d));
    }
    const variance = d_sq_sum / iterations;
    _ = try printBenchmark(
        writer,
        min_widths,
        function_name,
        arg_name,
        iterations,
        min,
        max,
        variance,
        runtime_mean,
    );
}

fn printBenchmark(
    writer: anytype,
    min_widths: [6]u64,
    func_name: []const u8,
    arg_name: anytype,
    iterations: anytype,
    min_runtime: anytype,
    max_runtime: anytype,
    variance: anytype,
    mean_runtime: anytype,
) ![6]u64 {
    const arg_len = std.fmt.count("{}", .{arg_name});
    const name_len = try alignedPrint(writer, .left, min_widths[0], "{s}{s}{}{s}", .{
        func_name,
        "("[0..@intFromBool(arg_len != 0)],
        arg_name,
        ")"[0..@intFromBool(arg_len != 0)],
    });
    try writer.writeAll(" ");
    const it_len = try alignedPrint(writer, .right, min_widths[1], "{}", .{iterations});
    try writer.writeAll(" ");
    const min_runtime_len = try alignedPrint(writer, .right, min_widths[2], "{}", .{min_runtime});
    try writer.writeAll(" ");
    const max_runtime_len = try alignedPrint(writer, .right, min_widths[3], "{}", .{max_runtime});
    try writer.writeAll(" ");
    const variance_len = try alignedPrint(writer, .right, min_widths[4], "{}", .{variance});
    try writer.writeAll(" ");
    const mean_runtime_len = try alignedPrint(writer, .right, min_widths[5], "{}", .{mean_runtime});

    return [_]u64{ name_len, it_len, min_runtime_len, max_runtime_len, variance_len, mean_runtime_len };
}

fn formatter(comptime fmt_str: []const u8, value: anytype) Formatter(fmt_str, @TypeOf(value)) {
    return .{ .value = value };
}

fn Formatter(comptime fmt_str: []const u8, comptime T: type) type {
    return struct {
        value: T,

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, fmt_str, .{self.value});
        }
    };
}

fn alignedPrint(writer: anytype, dir: enum { left, right }, width: u64, comptime fmt: []const u8, args: anytype) !u64 {
    const value_len = std.fmt.count(fmt, args);

    var cow = io.countingWriter(writer);
    if (dir == .right)
        try cow.writer().writeByteNTimes(' ', math.sub(u64, width, value_len) catch 0);
    try cow.writer().print(fmt, args);
    if (dir == .left)
        try cow.writer().writeByteNTimes(' ', math.sub(u64, width, value_len) catch 0);
    return cow.bytes_written;
}
