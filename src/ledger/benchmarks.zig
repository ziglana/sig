const std = @import("std");
const sig = @import("../sig.zig");
const ledger_tests = @import("./tests.zig");
const ledger = @import("lib.zig");

const Reward = ledger.transaction_status.Reward;
const Rewards = ledger.transaction_status.Rewards;
const RewardType = ledger.transaction_status.RewardType;
const Pubkey = sig.core.Pubkey;
const TestState = ledger_tests.TestState;
const TestDB = ledger_tests.TestDB;

const schema = ledger.schema.schema;
const deinitShreds = ledger_tests.deinitShreds;
const testShreds = ledger_tests.testShreds;

const test_shreds_dir = sig.TEST_DATA_DIR ++ "/shreds";
const State = TestState("global");
const DB = TestDB("global");

fn createRewards(allocator: std.mem.Allocator, count: usize) !Rewards {
    var rng = std.Random.DefaultPrng.init(100);
    const rand = rng.random();
    var rewards: Rewards = Rewards.init(allocator);
    for (0..count) |i| {
        try rewards.append(Reward{
            .pubkey = &Pubkey.initRandom(rand).data,
            .lamports = @intCast(42 + i),
            .post_balance = std.math.maxInt(u64),
            .reward_type = RewardType.Fee,
            .commission = null,
        });
    }
    return rewards;
}

pub const BenchmarkLedger = struct {
    pub const min_iterations = 25;
    pub const max_iterations = 25;

    /// Analogous to [bench_write_small](https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L59)
    ///
    /// There is a notable difference from agave: This does not measure the
    /// creation of shreds from entries. But even if you remove that from
    /// the agave benchmark, the benchmark result is the same.
    pub fn @"ShredInserter.insertShreds - 1751 shreds"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench write small", .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();

        const shreds_path = "agave.blockstore.bench_write_small.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const is_repairs = try inserter.allocator.alloc(bool, shreds.len);
        defer inserter.allocator.free(is_repairs);
        for (0..shreds.len) |i| {
            is_repairs[i] = false;
        }

        var timer = try sig.time.Timer.start();
        _ = try inserter.insertShreds(shreds, is_repairs, null, false, null);
        return timer.read();
    }

    /// Analogous to [bench_read_sequential]https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L78
    pub fn @"BlockstoreReader.getDataShred - Sequential"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench read sequential", .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const total_shreds = shreds.len;

        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);

        const slot: u32 = 0;
        const num_reads = total_shreds / 15;

        var rng = std.Random.DefaultPrng.init(100);

        var timer = try sig.time.Timer.start();
        const start_index = rng.random().intRangeAtMost(u32, 0, @intCast(total_shreds));
        for (start_index..start_index + num_reads) |i| {
            const shred_index = i % total_shreds;
            _ = try reader.getDataShred(slot, shred_index);
        }
        return timer.read();
    }

    /// Analogous to [bench_read_random]https://github.com/anza-xyz/agave/blob/92eca1192b055d896558a78759d4e79ab4721ff1/ledger/benches/blockstore.rs#L103
    pub fn @"BlockstoreReader.getDataShred - Random"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench read randmom", .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const total_shreds = shreds.len;
        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);
        const num_reads = total_shreds / 15;

        const slot: u32 = 0;

        var rng = std.Random.DefaultPrng.init(100);

        var indices = try std.ArrayList(u32).initCapacity(inserter.allocator, num_reads);
        defer indices.deinit();
        for (num_reads) |_| {
            indices.appendAssumeCapacity(rng.random().uintAtMost(u32, @intCast(total_shreds)));
        }

        var timer = try sig.time.Timer.start();
        for (indices.items) |shred_index| {
            _ = try reader.getDataShred(slot, shred_index);
        }
        return timer.read();
    }

    /// Analogous to [bench_serialize_write_bincode](https://github.com/anza-xyz/agave/blob/9c2098450ca7e5271e3690277992fbc910be27d0/ledger/benches/protobuf.rs#L88)
    pub fn @"Database.put Rewards"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench serialize write bincode", .noop);
        defer state.deinit();
        const slot: u32 = 0;

        var rewards: Rewards = try createRewards(allocator, 100);
        const rewards_slice = try rewards.toOwnedSlice();
        var timer = try sig.time.Timer.start();
        try state.db.put(schema.rewards, slot, .{
            .rewards = rewards_slice,
            .num_partitions = null,
        });
        return timer.read();
    }

    /// Analogous to [bench_read_bincode](https://github.com/anza-xyz/agave/blob/9c2098450ca7e5271e3690277992fbc910be27d0/ledger/benches/protobuf.rs#L100)
    pub fn @"Database.get Rewards"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench read bincode", .noop);
        defer state.deinit();
        const slot: u32 = 1;

        var rewards: Rewards = try createRewards(allocator, 100);
        try state.db.put(schema.rewards, slot, .{
            .rewards = try rewards.toOwnedSlice(),
            .num_partitions = null,
        });
        var timer = try sig.time.Timer.start();
        _ = try state.db.get(allocator, schema.rewards, slot);
        return timer.read();
    }
};
