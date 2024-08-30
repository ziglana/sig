const std = @import("std");
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Mux = @import("mux.zig").Mux;
const Backoff = @import("backoff.zig").Backoff;

pub fn Channel(T: type) type {
    return struct {
        head: Position,
        tail: Position,
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: Allocator,

        const Self = @This();
        const BLOCK_CAP = 31;
        const SHIFT = 1;
        const LAP = 32;

        const WRITE: usize = 0b01;
        const READ: usize = 0b10;
        const DESTROY: usize = 0b100;

        const HAS_NEXT: usize = 0b01;

        const Position = struct {
            index: Atomic(usize),
            block: Atomic(?*Buffer),

            fn init() Position {
                return .{
                    .index = Atomic(usize).init(0),
                    .block = Atomic(?*Buffer).init(null),
                };
            }

            fn deinit(pos: *Position, allocator: Allocator) void {
                if (pos.block.load(.monotonic)) |block| {
                    block.deinit(allocator);
                    allocator.destroy(block);
                }
            }
        };

        const Buffer = struct {
            next: Atomic(?*Buffer),
            slots: [BLOCK_CAP]Slot,

            fn create(allocator: Allocator) !*Buffer {
                const new = try allocator.create(Buffer);
                @memset(&new.slots, Slot.uninit);
                new.next = Atomic(?*Buffer).init(null);
                return new;
            }

            fn destroy(block: *Buffer, start: usize, allocator: Allocator) void {
                for (start..BLOCK_CAP - 1) |i| {
                    const slot = &block.slots[i];

                    if (slot.state.load(.acquire) & READ == 0 and
                        slot.state.fetchOr(DESTROY, .acq_rel) & READ == 0)
                    {
                        return;
                    }
                }

                allocator.destroy(block);
            }

            fn deinit(block: *Buffer, allocator: Allocator) void {
                if (block.next.load(.monotonic)) |n| {
                    n.deinit(allocator);
                    allocator.destroy(n);
                }
            }
        };

        const Slot = struct {
            value: T,
            state: Atomic(usize),

            const uninit: Slot = .{
                .value = undefined,
                .state = Atomic(usize).init(0),
            };
        };

        pub fn init(allocator: Allocator, initial_capacity: usize) Self {
            _ = initial_capacity; // TODO: do something with this
            return .{
                .head = Position.init(),
                .tail = Position.init(),
                .allocator = allocator,
            };
        }

        pub fn create(allocator: Allocator, initial_capacity: usize) !*Self {
            const channel = try allocator.create(Self);
            channel.* = Self.init(allocator, initial_capacity);
            return channel;
        }

        pub fn send(channel: *Self, value: T) !void {
            var backoff = Backoff.init();
            var tail = channel.tail.index.load(.acquire);
            var block = channel.tail.block.load(.acquire);
            var next_block: ?*Buffer = null;

            while (true) {
                const offset = (tail >> SHIFT) % LAP;
                if (offset == BLOCK_CAP) {
                    backoff.snooze();
                    tail = channel.tail.index.load(.acquire);
                    block = channel.tail.block.load(.acquire);
                    continue;
                }

                if (offset + 1 == BLOCK_CAP and next_block == null) {
                    next_block = try Buffer.create(channel.allocator);
                }

                if (block == null) {
                    const new = try Buffer.create(channel.allocator);

                    if (channel.tail.block.cmpxchgStrong(block, new, .release, .monotonic) == null) {
                        channel.head.block.store(new, .release);
                        block = new;
                    } else {
                        next_block = new;
                        tail = channel.tail.index.load(.acquire);
                        block = channel.tail.block.load(.acquire);
                        continue;
                    }
                }

                const new_tail = tail + (1 << SHIFT);

                if (channel.tail.index.cmpxchgWeak(tail, new_tail, .seq_cst, .acquire)) |t| {
                    tail = t;
                    block = channel.tail.block.load(.acquire);
                    backoff.spin();
                } else {
                    if (offset + 1 == BLOCK_CAP) {
                        const next_index = new_tail +% (1 << SHIFT);
                        channel.tail.block.store(next_block, .release);
                        channel.tail.index.store(next_index, .release);
                        block.?.next.store(next_block, .release);
                    } else if (next_block) |b| {
                        channel.allocator.destroy(b);
                    }

                    const slot = &block.?.slots[offset];
                    slot.value = value;
                    _ = slot.state.fetchOr(WRITE, .release);
                    return;
                }
            }
        }

        pub fn receive(channel: *Self) ?T {
            var backoff = Backoff.init();
            var head = channel.head.index.load(.acquire);
            var block = channel.head.block.load(.acquire);

            while (true) {
                const offset = (head >> SHIFT) % LAP;

                if (offset == BLOCK_CAP) {
                    backoff.snooze();
                    head = channel.head.index.load(.acquire);
                    block = channel.head.block.load(.acquire);
                    continue;
                }

                var new_head = head + (1 << SHIFT);

                if (new_head & HAS_NEXT == 0) {
                    channel.tail.index.fence(.seq_cst);
                    const tail = channel.tail.index.load(.monotonic);

                    if (head >> SHIFT == tail >> SHIFT) {
                        return null;
                    }

                    if ((head >> SHIFT) / LAP != (tail >> SHIFT) / LAP) {
                        new_head |= HAS_NEXT;
                    }
                }

                if (block == null) {
                    backoff.snooze();
                    head = channel.head.index.load(.acquire);
                    block = channel.head.block.load(.acquire);
                    continue;
                }

                if (channel.head.index.cmpxchgWeak(head, new_head, .seq_cst, .acquire)) |h| {
                    head = h;
                    block = channel.head.block.load(.acquire);
                    backoff.spin();
                } else {
                    if (offset + 1 == BLOCK_CAP) {
                        const next = while (true) {
                            backoff.snooze();
                            const next = block.?.next.load(.acquire);
                            if (next != null) break next.?;
                        };
                        var next_index = (new_head & ~HAS_NEXT) +% (1 << SHIFT);

                        if (next.next.load(.monotonic) != null) {
                            next_index |= HAS_NEXT;
                        }

                        channel.head.block.store(next, .release);
                        channel.head.index.store(next_index, .release);
                    }

                    const slot = &block.?.slots[offset];
                    while (slot.state.load(.acquire) & WRITE == 0) {}
                    const value = slot.value;

                    if (offset + 1 == BLOCK_CAP) {
                        block.?.destroy(0, channel.allocator);
                    } else if (slot.state.fetchOr(READ, .acq_rel) & DESTROY != 0) {
                        block.?.destroy(offset + 1, channel.allocator);
                    }

                    return value;
                }
            }
        }

        pub fn len(channel: *Self) usize {
            while (true) {
                var tail = channel.tail.index.load(.seq_cst);
                var head = channel.head.index.load(.seq_cst);

                if (channel.tail.index.load(.seq_cst) == tail) {
                    tail &= ~((@as(usize, 1) << SHIFT) - 1);
                    head &= ~((@as(usize, 1) << SHIFT) - 1);

                    if ((tail >> SHIFT) & (LAP - 1) == (LAP - 1)) {
                        tail +%= (1 << SHIFT);
                    }
                    if ((head >> SHIFT) & (LAP - 1) == (LAP - 1)) {
                        head +%= (1 << SHIFT);
                    }

                    const lap = (head >> SHIFT) / LAP;
                    tail -%= (lap * LAP) << SHIFT;
                    head -%= (lap * LAP) << SHIFT;

                    tail >>= SHIFT;
                    head >>= SHIFT;

                    return tail - head - tail / LAP;
                }
            }
        }

        pub fn isEmpty(channel: *Self) bool {
            const head = channel.head.index.load(.seq_cst);
            const tail = channel.tail.index.load(.seq_cst);
            return (head >> SHIFT) == (tail >> SHIFT);
        }

        pub fn deinit(channel: *Self) void {
            var head = channel.head.index.raw;
            var tail = channel.tail.index.raw;
            var block = channel.head.block.raw;

            head &= ~((@as(usize, 1) << SHIFT) - 1);
            tail &= ~((@as(usize, 1) << SHIFT) - 1);

            while (head != tail) {
                const offset = (head >> SHIFT) % LAP;

                if (offset >= BLOCK_CAP) {
                    const next = block.?.next.raw;
                    channel.allocator.destroy(block.?);
                    block = next;
                }

                head +%= (1 << SHIFT);
            }

            if (block) |b| {
                channel.allocator.destroy(b);
            }
        }

        pub fn close(channel: *Self) void {
            _ = channel;
        }
    };
}

const expect = std.testing.expect;

test "smoke" {
    var ch = Channel(u32).init(std.testing.allocator, 0);
    defer ch.deinit();

    try ch.send(7);
    try expect(ch.receive() == 7);

    try ch.send(8);
    try expect(ch.receive() == 8);
    try expect(ch.receive() == null);
}

test "len_empty_full" {
    var ch = Channel(u32).init(std.testing.allocator, 0);
    defer ch.deinit();

    try expect(ch.len() == 0);
    try expect(ch.isEmpty());

    try ch.send(0);

    try expect(ch.len() == 1);
    try expect(!ch.isEmpty());

    _ = ch.receive().?;

    try expect(ch.len() == 0);
    try expect(ch.isEmpty());
}

test "len" {
    var ch = Channel(u64).init(std.testing.allocator, 0);
    defer ch.deinit();

    try expect(ch.len() == 0);

    for (0..50) |i| {
        try ch.send(i);
        try expect(ch.len() == i + 1);
    }

    for (0..50) |i| {
        _ = ch.receive().?;
        try expect(ch.len() == 50 - i - 1);
    }

    try expect(ch.len() == 0);
}

test "spsc" {
    const COUNT = 100;

    const S = struct {
        fn producer(ch: *Channel(u64)) !void {
            for (0..COUNT) |i| {
                try ch.send(i);
            }
        }

        fn consumer(ch: *Channel(u64)) void {
            for (0..COUNT) |i| {
                while (true) {
                    if (ch.receive()) |x| {
                        assert(x == i);
                        break;
                    }
                }
            }
        }
    };

    var ch = Channel(u64).init(std.testing.allocator, 0);
    defer ch.deinit();

    const consumer = try std.Thread.spawn(.{}, S.consumer, .{&ch});
    const producer = try std.Thread.spawn(.{}, S.producer, .{&ch});

    consumer.join();
    producer.join();
}

test "mpmc" {
    const COUNT = 100;
    const THREADS = 4;

    const S = struct {
        fn producer(ch: *Channel(u64)) !void {
            for (0..COUNT) |i| {
                try ch.send(i);
            }
        }

        fn consumer(ch: *Channel(u64), v: *[COUNT]Atomic(usize)) void {
            for (0..COUNT) |_| {
                const n = while (true) {
                    if (ch.receive()) |x| break x;
                };
                _ = v[n].fetchAdd(1, .seq_cst);
            }
        }
    };

    var v: [COUNT]Atomic(usize) = .{Atomic(usize).init(0)} ** COUNT;

    var ch = Channel(u64).init(std.testing.allocator, 0);
    defer ch.deinit();

    var c_threads: [THREADS]std.Thread = undefined;
    var p_threads: [THREADS]std.Thread = undefined;

    for (&c_threads) |*c_thread| {
        c_thread.* = try std.Thread.spawn(.{}, S.consumer, .{ &ch, &v });
    }

    for (&p_threads) |*p_thread| {
        p_thread.* = try std.Thread.spawn(.{}, S.producer, .{&ch});
    }

    for (c_threads, p_threads) |c_thread, p_thread| {
        c_thread.join();
        p_thread.join();
    }

    for (v) |c| try expect(c.load(.seq_cst) == THREADS);
}

const Block = struct {
    num: u32 = 333,
    valid: bool = true,
    data: [1024]u8 = undefined,
};

const logger = std.log.scoped(.sync_channel_tests);

fn testUsizeReceiver(chan: anytype, recv_count: usize) void {
    var count: usize = 0;
    while (count < recv_count) {
        if (chan.receive()) |_| count += 1;
    }
}

fn testUsizeSender(chan: anytype, send_count: usize) void {
    var i: usize = 0;
    while (i < send_count) : (i += 1) {
        chan.send(i) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
    }
}

const Packet = @import("../net/packet.zig").Packet;

fn testPacketSender(chan: anytype, total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        const packet = Packet.default();
        chan.send(packet) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
    }
}

fn testPacketReceiver(chan: anytype, total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (chan.receive()) |_| count += 1;
    }
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 10;
    pub const max_iterations = 20;

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        n_items: usize,
        n_senders: usize,
        n_receivers: usize,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "  10k_items,   1_senders,   1_receivers ",
            .n_items = 10_000,
            .n_senders = 1,
            .n_receivers = 1,
        },
        .{
            .name = " 100k_items,   4_senders,   4_receivers ",
            .n_items = 100_000,
            .n_senders = 4,
            .n_receivers = 4,
        },
        .{
            .name = " 500k_items,   8_senders,   8_receivers ",
            .n_items = 500_000,
            .n_senders = 8,
            .n_receivers = 8,
        },
        .{
            .name = "   1m_items,  16_senders,  16_receivers ",
            .n_items = 1_000_000,
            .n_senders = 16,
            .n_receivers = 16,
        },
    };

    pub fn benchmarkSimpleUsizeBetterChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        const allocator = std.heap.page_allocator;
        var channel = Channel(usize).init(allocator, n_items / 2);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeSender, .{ &channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeReceiver, .{ &channel, receives_per_receiver });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        channel.close();
        const elapsed = timer.read();
        return elapsed;
    }

    pub fn benchmarkSimplePacketBetterChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        const allocator = std.heap.page_allocator;
        var channel = Channel(Packet).init(allocator, n_items / 2);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketSender, .{ &channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketReceiver, .{ &channel, receives_per_receiver });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        channel.close();
        const elapsed = timer.read();
        return elapsed;
    }
};
