const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");

const UdpSocket = net.Socket;
const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Instant = std.time.Instant;

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Deduper = sig.utils.deduper.Deduper;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const Duration = sig.time.Duration;
const TurbineTree = sig.turbine.TurbineTree;
const TurbineTreeCache = sig.turbine.TurbineTreeCache;
const Channel = sig.sync.Channel;
const ShredId = sig.ledger.shred.ShredId;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const BlockstoreWriter = sig.ledger.BlockstoreWriter;
const ShredInserter = sig.ledger.insert_shred.ShredInserter;
const Shred = sig.ledger.shred.Shred;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const BankFields = sig.accounts_db.snapshots.BankFields;
const RwMux = sig.sync.RwMux;
const Logger = sig.trace.log.Logger;

pub fn runRetransmitService(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_schedule: EpochSchedule,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(std.ArrayList(sig.net.Packet)),
    retransmit_sockets: []const UdpSocket,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    rand: std.rand.Random,
    exit: *AtomicBool,
    logger: *Logger,
) !void {
    logger.debug("Initialising retransmit service");
    logger.debug("Initialising TurbineTreeCache");
    var turbine_tree_cache = TurbineTreeCache.init(
        allocator,
        my_contact_info,
        epoch_schedule,
        gossip_table_rw,
    );

    logger.debug("Initialising ShredDeduper");
    var shred_deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer shred_deduper.deinit();

    logger.debug("Entering retransmit loop");
    while (exit.load(.unordered)) {
        try retransmit(
            allocator,
            bank_fields,
            leader_schedule_cache,
            shreds_receiver,
            retransmit_sockets,
            &turbine_tree_cache,
            &shred_deduper,
            rand,
            logger,
        );
    }
}

fn retransmit(
    allocator: std.mem.Allocator,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(std.ArrayList(sig.net.Packet)),
    sockets: []const UdpSocket,
    turbine_tree_cache: *TurbineTreeCache,
    shred_deduper: *ShredDeduper(2),
    rand: std.rand.Random,
    logger: *Logger,
) !void {
    // Drain shred receiver into raw shreds
    logger.debug("Draining shreds receiver");
    const raw_shred_batches = try shreds_receiver.try_drain() orelse return;
    defer {
        for (raw_shred_batches) |batch| batch.deinit();
        allocator.free(raw_shred_batches);
    }

    // Reset dedupers
    logger.info("Resetting dedupers");
    shred_deduper.maybeReset(
        rand,
        DEDUPER_FALSE_POSITIVE_RATE,
        DEDUPER_RESET_CYCLE,
    );

    // Group shreds by slot
    logger.debug("Grouping shreds by slot");
    const ShredsArray = std.ArrayList(struct { ShredId, []const u8 });
    var slot_shreds = std.AutoArrayHashMap(Slot, ShredsArray).init(allocator);
    defer {
        for (slot_shreds.values()) |arr| arr.deinit();
        slot_shreds.deinit();
    }

    for (raw_shred_batches) |raw_shred_batch| {
        for (raw_shred_batch.items) |raw_shred| {
            const shred_id = try sig.ledger.shred.layout.getShredId(&raw_shred);

            if (shred_deduper.dedup(&shred_id, &raw_shred.data, MAX_DUPLICATE_COUNT)) {
                continue;
            }

            if (slot_shreds.getEntry(shred_id.slot)) |entry| {
                try entry.value_ptr.append(.{ shred_id, &raw_shred.data });
            } else {
                var new_slot_shreds = ShredsArray.init(allocator);
                try new_slot_shreds.append(.{ shred_id, &raw_shred.data });
                try slot_shreds.put(shred_id.slot, new_slot_shreds);
            }
        }
    }

    // Retransmit shreds
    logger.debug("Retransmitting shreds");
    for (slot_shreds.keys(), slot_shreds.values()) |slot, shreds| {
        logger.debugf("Getting leader and turbine tree for slot {}", .{slot});
        const slot_leader = if (leader_schedule_cache.slotLeader(slot)) |leader| leader else blk: {
            const epoch, _ = bank_fields.epoch_schedule.getEpochAndSlotIndex(slot);
            try leader_schedule_cache.put(epoch, try bank_fields.leaderSchedule(allocator));
            break :blk leader_schedule_cache.slotLeader(slot) orelse unreachable;
        };
        const turbine_tree = try turbine_tree_cache.getTurbineTree(slot, bank_fields);

        // PERF: Move outside for loop and parallelize
        logger.debugf("Sending {} shreds for slot {}", .{ shreds.items.len, slot });
        for (shreds.items, 0..) |shred, i| {
            const shred_id, const shred_bytes = shred;
            defer allocator.free(shred_bytes);

            const socket = sockets[i % sockets.len];

            const addresses = try turbine_tree.getRetransmitAddresses(
                allocator,
                slot_leader,
                shred_id,
                TurbineTree.getDataPlaneFanout(),
            );
            defer allocator.free(addresses);

            for (addresses) |address| {
                _ = try socket.sendTo(address.toEndpoint(), shred_bytes);
            }
        }
    }
}

const MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;

pub fn ShredDeduper(comptime K: usize) type {
    return struct {
        bytes_filter: BytesFilter,
        shred_id_filter: ShredIdFilter,

        const BytesFilter = Deduper(K, []const u8);
        const ShredIdFilter = Deduper(K, ShredIdFilterKey);
        const ShredIdFilterKey = struct { id: ShredId, index: usize };

        pub fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_bits: u64) !ShredDeduper(K) {
            return .{
                .bytes_filter = try BytesFilter.init(allocator, rand, num_bits),
                .shred_id_filter = try ShredIdFilter.init(allocator, rand, num_bits),
            };
        }

        pub fn deinit(self: *ShredDeduper(K)) void {
            self.bytes_filter.deinit();
            self.shred_id_filter.deinit();
        }

        pub fn maybeReset(self: *ShredDeduper(K), rand: std.rand.Random, false_positive_rate: f64, reset_cycle: Duration) void {
            _ = self.bytes_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
            _ = self.shred_id_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
        }

        pub fn dedup(self: *ShredDeduper(K), shred_id: *const ShredId, shred_bytes: []const u8, max_duplicate_count: usize) bool {
            if (self.bytes_filter.dedup(&shred_bytes)) return true;
            for (0..max_duplicate_count) |i| {
                if (!self.shred_id_filter.dedup(&.{ .id = shred_id.*, .index = i })) return false;
            }
            return true;
        }
    };
}
