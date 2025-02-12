const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Account = sig.core.Account;
const SnapshotFields = sig.accounts_db.SnapshotFields;
const FileId = sig.accounts_db.accounts_file.FileId;
const AccountsDbFields = sig.accounts_db.snapshots.AccountsDbFields;
const BankFields = sig.accounts_db.snapshots.BankFields;
const AccountFileInfo = sig.accounts_db.snapshots.AccountFileInfo;
const EpochRewardStatus = sig.accounts_db.snapshots.EpochRewardStatus;
const StakeReward = sig.accounts_db.snapshots.StakeReward;

const MAX_FUZZ_TIME_NS = std.time.ns_per_s * 100_000;

pub fn run(args: *std.process.ArgIterator) !void {
    _ = args;
    const seed = std.crypto.random.int(u64);

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    {
        // open and append seed
        const SEED_FILE_PATH = sig.TEST_DATA_DIR ++ "fuzz_snapshot_seeds.txt";
        const seed_file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{ .truncate = false });
        defer seed_file.close();

        try seed_file.writer().print("{}\n", .{seed});
    }
    std.debug.print("seed: {}\n", .{seed});

    var prng = std.rand.DefaultPrng.init(seed);
    const random = prng.random();

    var bytes_buffer = std.ArrayList(u8).init(allocator);
    defer bytes_buffer.deinit();

    var i: u64 = 0;

    var timer = try std.time.Timer.start();
    while (timer.read() < MAX_FUZZ_TIME_NS) : (i += 1) {
        bytes_buffer.clearRetainingCapacity();

        const snapshot_original: SnapshotFields = try randomSnapshotFields(allocator, random);
        defer snapshot_original.deinit(allocator);

        try bytes_buffer.ensureUnusedCapacity(bincode.sizeOf(snapshot_original, .{}) * 2);

        const original_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), snapshot_original, .{});
        const original_bytes_end = bytes_buffer.items.len;

        const snapshot_deserialized = try bincode.readFromSlice(allocator, SnapshotFields, bytes_buffer.items[original_bytes_start..original_bytes_end], .{});
        defer snapshot_deserialized.deinit(allocator);

        const serialized_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), snapshot_deserialized, .{});
        const serialized_bytes_end = bytes_buffer.items.len;

        const original_bytes = bytes_buffer.items[original_bytes_start..original_bytes_end];
        const serialized_bytes = bytes_buffer.items[serialized_bytes_start..serialized_bytes_end];
        try std.testing.expectEqualSlices(u8, original_bytes, serialized_bytes);
        std.debug.print("Verified {d} snapshots\n", .{i});
    }
}

const max_list_entries = 1 << 8;

fn randomSnapshotFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    random: std.Random,
) !SnapshotFields {
    const bank_fields = try BankFields.initRandom(allocator, random, max_list_entries);
    errdefer bank_fields.deinit(allocator);

    const accounts_db_fields = try randomAccountsDbFields(allocator, random, .{});
    errdefer accounts_db_fields.deinit(allocator);

    const epoch_reward_status: ?EpochRewardStatus = if (random.boolean()) null else switch (random.enumValue(@typeInfo(EpochRewardStatus).Union.tag_type.?)) {
        .Active => .{ .Active = .{
            .parent_start_block_height = random.int(u64),
            .calculated_epoch_stake_rewards = blk: {
                const stake_rewards = try allocator.alloc(StakeReward, random.uintAtMost(usize, max_list_entries));
                errdefer allocator.free(stake_rewards);
                errdefer for (stake_rewards) |*reward| {
                    reward.stake_account.deinit(allocator);
                };
                for (stake_rewards) |*rewards| {
                    rewards.* = .{
                        .stake_pubkey = Pubkey.initRandom(random),
                        .stake_reward_info = .{
                            .reward_type = random.enumValue(sig.accounts_db.snapshots.RewardType),
                            .lamports = random.int(i64),
                            .post_balance = random.int(u64),
                            .commission = if (random.boolean()) random.int(u8) else null,
                        },
                        .stake_account = try Account.initRandom(allocator, random, random.uintAtMost(usize, max_list_entries)),
                    };
                }
                break :blk std.ArrayList(StakeReward).fromOwnedSlice(allocator, stake_rewards);
            },
        } },
        .Inactive => .Inactive,
    };
    errdefer comptime unreachable;

    return .{
        .bank_fields = bank_fields,
        .accounts_db_fields = accounts_db_fields,
        .lamports_per_signature = random.int(u64),
        .bank_fields_inc = .{
            .snapshot_persistence = if (random.boolean()) null else .{
                .full_slot = random.int(Slot),
                .full_hash = Hash.initRandom(random),
                .full_capitalization = random.int(u64),
                .incremental_hash = Hash.initRandom(random),
                .incremental_capitalization = random.int(u64),
            },
            .epoch_accounts_hash = if (random.boolean()) null else Hash.initRandom(random),
            .epoch_reward_status = epoch_reward_status,
        },
    };
}

const AccountsDbFieldsRandomConfig = struct {
    slot: struct { min: Slot, max: Slot } = .{
        .min = 0,
        .max = std.math.maxInt(Slot),
    },

    file_id: struct { min: FileId, max: FileId } = .{
        .min = FileId.fromInt(0),
        .max = FileId.fromInt(std.math.maxInt(FileId.Int)),
    },

    file_map_len: struct { min: usize, max: usize } = .{
        .min = 1,
        .max = 4096 * 8,
    },

    file_len: struct { min: usize, max: usize } = .{
        .min = 0,
        .max = 4096 * 4,
    },

    stored_meta_write_version_max: u64 = 0,
};

fn randomAccountsDbFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    random: std.Random,
    params: AccountsDbFieldsRandomConfig,
) std.mem.Allocator.Error!AccountsDbFields {
    std.debug.assert(params.file_map_len.min >= 1);

    const FileIdAdapter = struct {
        file_map: *const AccountsDbFields.FileMap,

        pub fn hash(_: @This(), key: FileId) u32 {
            return key.toInt();
        }

        pub fn eql(ctx: @This(), a: FileId, _: void, b_index: usize) bool {
            const b = ctx.file_map.values()[b_index].id;
            return a == b;
        }
    };

    var total_data_len: u64 = 0;
    var max_slot: Slot = 0;

    const file_map_len = random.intRangeAtMost(usize, params.file_map_len.min, params.file_map_len.max);

    var file_map = AccountsDbFields.FileMap.init(allocator);
    errdefer file_map.deinit();
    try file_map.ensureTotalCapacity(file_map_len);

    var file_id_set = std.AutoArrayHashMap(void, void).init(allocator);
    defer file_id_set.deinit();
    try file_id_set.ensureTotalCapacity(file_map_len);

    for (0..file_map_len) |_| while (true) {
        const new_slot = random.intRangeAtMost(Slot, params.slot.min, params.slot.max);
        const slot_gop = file_map.getOrPutAssumeCapacity(new_slot);
        if (slot_gop.found_existing) continue;

        const new_id: FileId = while (true) {
            const new_id = FileId.fromInt(random.intRangeAtMost(FileId.Int, params.file_id.min.toInt(), params.file_id.max.toInt()));
            const id_gop = file_id_set.getOrPutAssumeCapacityAdapted(new_id, FileIdAdapter{
                .file_map = &file_map,
            });
            if (id_gop.found_existing) continue;
            break new_id;
        };

        const account_file_info: AccountFileInfo = .{
            .id = new_id,
            .length = random.intRangeAtMost(usize, params.file_len.min, @min(std.math.maxInt(u64) - total_data_len, params.file_len.max)),
        };
        slot_gop.value_ptr.* = account_file_info;
        max_slot = @max(max_slot, new_slot);
        total_data_len += account_file_info.length;
        break;
    };

    return .{
        .file_map = file_map,
        .stored_meta_write_version = random.uintAtMost(u64, params.stored_meta_write_version_max),
        .slot = max_slot,
        .bank_hash_info = .{
            .accounts_delta_hash = Hash.initRandom(random),
            .accounts_hash = Hash.initRandom(random),
            .stats = .{
                .num_updated_accounts = random.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
                .num_removed_accounts = random.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
                .num_lamports_stored = random.int(u64),
                .total_data_len = total_data_len,
                .num_executable_accounts = random.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
            },
        },
        // NOTE: see field comment about these always being empty
        .rooted_slots = .{},
        .rooted_slot_hashes = .{},
    };
}
