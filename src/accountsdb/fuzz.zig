const std = @import("std");
const sig = @import("../lib.zig");
const zstd = @import("zstd");

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const Hash = sig.core.Hash;
const BankFields = sig.accounts_db.snapshots.BankFields;
const BankHashInfo = sig.accounts_db.snapshots.BankHashInfo;

pub const TrackedAccount = struct {
    pubkey: Pubkey,
    slot: u64,
    data: []u8,

    pub fn random(rand: std.rand.Random, slot: Slot, allocator: std.mem.Allocator) !TrackedAccount {
        return .{
            .pubkey = Pubkey.random(rand),
            .slot = slot,
            .data = try allocator.alloc(u8, 32),
        };
    }

    pub fn deinit(self: *TrackedAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn toAccount(self: *const TrackedAccount, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = 19,
            .data = try allocator.dupe(u8, self.data),
            .owner = Pubkey.default(),
            .executable = false,
            .rent_epoch = 0,
        };
    }
};

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const logger = Logger.init(gpa, .debug);
    defer logger.deinit();
    logger.spawn();

    const use_disk = rand.boolean();

    var test_data_dir = try std.fs.cwd().makeOpenPath("test_data", .{});
    defer test_data_dir.close();

    const snapshot_dir_name = "accountsdb_fuzz";
    var snapshot_dir = try test_data_dir.makeOpenPath(snapshot_dir_name, .{});
    defer snapshot_dir.close();
    defer {
        // NOTE: sometimes this can take a long time so we print when we start and finish
        std.debug.print("deleting snapshot dir...\n", .{});
        test_data_dir.deleteTree(snapshot_dir_name) catch |err| {
            std.debug.print("failed to delete snapshot dir ('{s}'): {}\n", .{ sig.utils.fmt.tryRealPath(snapshot_dir, "."), err });
        };
        std.debug.print("deleted snapshot dir\n", .{});
    }
    std.debug.print("use disk: {}\n", .{use_disk});

    const alt_dir_name = "alt";
    var alt_dir = try snapshot_dir.makeOpenPath(alt_dir_name, .{});
    defer alt_dir.close();
    defer {
        // NOTE: sometimes this can take a long time so we print when we start and finish
        std.debug.print("deleting snapshot dir...\n", .{});
        test_data_dir.deleteTree(alt_dir_name) catch |err| {
            std.debug.print("failed to delete snapshot dir ('{s}'): {}\n", .{ sig.utils.fmt.tryRealPath(snapshot_dir, "."), err });
        };
        std.debug.print("deleted snapshot dir\n", .{});
    }

    var accounts_db = try AccountsDB.init(gpa, logger, snapshot_dir, .{
        .use_disk_index = use_disk,
        // TODO: other things we can fuzz (number of bins, ...)
    });
    defer accounts_db.deinit(true);

    const exit = try gpa.create(std.atomic.Value(bool));
    defer gpa.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    const manager_handle = try std.Thread.spawn(.{}, AccountsDB.runManagerLoop, .{
        &accounts_db,
        exit,
    });
    errdefer {
        exit.store(true, .seq_cst);
        manager_handle.join();
    }

    var tracked_accounts = std.AutoArrayHashMap(Pubkey, TrackedAccount).init(gpa);
    defer tracked_accounts.deinit();
    defer for (tracked_accounts.values()) |*value| {
        value.deinit(gpa);
    };
    try tracked_accounts.ensureTotalCapacity(10_000);

    var random_bank_fields = try BankFields.random(gpa, rand, 1 << 8);
    defer random_bank_fields.deinit(gpa);

    const random_bank_hash_info: BankHashInfo = .{
        .accounts_delta_hash = Hash.random(rand),
        .accounts_hash = Hash.random(rand),
        .stats = .{
            .num_updated_accounts = rand.int(u64),
            .num_removed_accounts = rand.int(u64),
            .num_lamports_stored = rand.int(u64),
            .total_data_len = rand.int(u64),
            .num_executable_accounts = rand.int(u64),
        },
    };

    const zstd_compressor = try zstd.Compressor.init(.{});
    defer zstd_compressor.deinit();

    var largest_rooted_slot: Slot = 0;
    var slot: Slot = 0;

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_actions) |max_actions| {
            if (slot >= max_actions) {
                std.debug.print("reached max actions: {}\n", .{max_actions});
                break;
            }
        }
        defer slot += 1;

        const Action = enum { put, get };
        const action: Action = rand.enumValue(Action);

        switch (action) {
            .put => {
                const N_ACCOUNTS_PER_SLOT = 10;

                var accounts: [N_ACCOUNTS_PER_SLOT]Account = undefined;
                var pubkeys: [N_ACCOUNTS_PER_SLOT]Pubkey = undefined;

                for (&accounts, &pubkeys, 0..) |*account, *pubkey, i| {
                    errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(gpa);

                    var tracked_account = try TrackedAccount.random(rand, slot, gpa);

                    const existing_pubkey = rand.boolean();
                    if (existing_pubkey and tracked_accounts.count() > 0) {
                        const index = rand.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                        const key = tracked_accounts.keys()[index];
                        tracked_account.pubkey = key;
                    }

                    account.* = try tracked_account.toAccount(gpa);
                    pubkey.* = tracked_account.pubkey;

                    const r = try tracked_accounts.getOrPut(tracked_account.pubkey);
                    if (r.found_existing) {
                        r.value_ptr.deinit(gpa);
                    }
                    // always overwrite the old slot
                    r.value_ptr.* = tracked_account;
                }
                defer for (accounts) |account| account.deinit(gpa);

                try accounts_db.putAccountSlice(
                    &accounts,
                    &pubkeys,
                    slot,
                );
            },
            .get => {
                const n_keys = tracked_accounts.count();
                if (n_keys == 0) {
                    continue;
                }
                const index = rand.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                const key = tracked_accounts.keys()[index];

                const tracked_account = tracked_accounts.get(key).?;
                var account = try accounts_db.getAccount(&tracked_account.pubkey);
                defer account.deinit(gpa);

                if (!std.mem.eql(u8, tracked_account.data, account.data)) {
                    @panic("found accounts with different data");
                }
            },
        }

        const create_new_root = rand.boolean();
        if (create_new_root) {
            largest_rooted_slot = @min(slot, largest_rooted_slot + 2);
            accounts_db.largest_root_slot.store(largest_rooted_slot, .seq_cst);
        }

        const empty_file_map = blk: {
            const file_map: *const AccountsDB.FileMap, var file_map_lg = accounts_db.file_map.readWithLock();
            defer file_map_lg.unlock();
            break :blk file_map.count() == 0;
        };

        if (!empty_file_map and slot % 500 == 0 and slot != largest_rooted_slot) {
            const snapshot_random_hash = Hash.random(rand);
            const snap_info: sig.accounts_db.snapshots.FullSnapshotFileInfo = .{
                .slot = largest_rooted_slot,
                .hash = snapshot_random_hash,
            };

            std.debug.print("Generating snapshot for slot {}...\n", .{largest_rooted_slot});

            const archive_file = try alt_dir.createFile(snap_info.snapshotNameStr().constSlice(), .{ .read = true });
            defer archive_file.close();

            // write the archive
            var zstd_write_buffer: [4096 * 4]u8 = undefined;
            const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, &zstd_write_buffer);

            random_bank_fields.slot = largest_rooted_slot;
            const lamports_per_signature = rand.int(u64);

            try accounts_db.writeSnapshotTarFull(
                zstd_write_ctx.writer(),
                .{ .bank_slot_deltas = &.{} },
                random_bank_fields,
                lamports_per_signature,
                random_bank_hash_info,
                0,
            );

            try zstd_write_ctx.finish();

            std.debug.print("Unpacking snapshot for slot {}...\n", .{largest_rooted_slot});
            try archive_file.seekTo(0);
            try sig.accounts_db.snapshots.parallelUnpackZstdTarBall(
                gpa,
                logger,
                archive_file,
                alt_dir,
                std.Thread.getCpuCount() catch 1,
                true,
            );

            const snap_files: sig.accounts_db.SnapshotFiles = .{
                .full_snapshot = snap_info,
                .incremental_snapshot = null,
            };

            var snap_fields_and_paths = try sig.accounts_db.AllSnapshotFields.fromFiles(gpa, logger, alt_dir, snap_files);
            defer snap_fields_and_paths.deinit(gpa);

            var new_accounts_db = try AccountsDB.init(gpa, logger, alt_dir, accounts_db.config);
            defer new_accounts_db.deinit(false);

            std.debug.print("Validating snapshot for slot {}...\n", .{largest_rooted_slot});

            try new_accounts_db.loadFromSnapshot(
                snap_fields_and_paths.full.accounts_db_fields.file_map,
                1,
                gpa,
            );
            std.debug.print("Validated snapshot for slot {d}\n", .{largest_rooted_slot});
        }
    }

    std.debug.print("fuzzing complete\n", .{});
    exit.store(true, .seq_cst);
    manager_handle.join();
}
