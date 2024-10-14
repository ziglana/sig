const std = @import("std");
const sig = @import("../sig.zig");

const IpAddr = sig.net.IpAddr;
const SocketAddr = sig.net.SocketAddr;
const ShredId = sig.ledger.shred.ShredId;
const RwMux = sig.sync.RwMux;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const BankFields = sig.accounts_db.snapshots.BankFields;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const GossipTable = sig.gossip.GossipTable;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);
const AtomicUsize = std.atomic.Value(usize);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const ThreadPool = sig.sync.ThreadPool;

/// TurbineTreeCache
/// Cache turbine trees and clear them once they are too old.
/// The time to live ensures updates to gossip data are reflected
/// in the turbine trees.
pub const TurbineTreeCache = struct {
    cache: std.AutoArrayHashMap(Epoch, Entry),
    cache_entry_ttl: Duration,

    pub const Entry = struct {
        created: Instant,
        turbine_tree: *TurbineTree,

        pub fn alive(self: *const Entry, ttl: Duration) bool {
            return self.created.elapsed().asNanos() < ttl.asNanos();
        }
    };

    pub fn init(allocator: std.mem.Allocator) TurbineTreeCache {
        return .{
            .cache = std.AutoArrayHashMap(Epoch, Entry).init(allocator),
            .cache_entry_ttl = Duration.fromSecs(5),
        };
    }

    pub fn deinit(self: *TurbineTreeCache) void {
        for (self.cache.values()) |entry| entry.turbine_tree.releaseUnsafe();
        self.cache.deinit();
    }

    pub fn get(self: *TurbineTreeCache, epoch: Epoch) !?*TurbineTree {
        const gopr = try self.cache.getOrPut(epoch);

        if (gopr.found_existing) {
            if (gopr.value_ptr.alive(self.cache_entry_ttl)) {
                return gopr.value_ptr.turbine_tree.acquireUnsafe();
            } else {
                gopr.value_ptr.turbine_tree.releaseUnsafe();
                std.debug.assert(self.cache.swapRemove(epoch));
            }
        }

        return null;
    }

    pub fn put(self: *TurbineTreeCache, epoch: Epoch, turbine_tree: *TurbineTree) !void {
        try self.cache.put(epoch, .{
            .created = Instant.now(),
            .turbine_tree = turbine_tree.acquireUnsafe(),
        });
    }
};

/// A TurbineTree is a data structure used to determine the set of nodes to
/// broadcast or retransmit shreds to in the network.
pub const TurbineTree = struct {
    allocator: std.mem.Allocator,
    my_pubkey: Pubkey,
    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    nodes: std.ArrayList(Node),
    /// Pubkey -> index in nodes
    index: std.AutoArrayHashMap(Pubkey, usize),
    /// Weighted shuffle of node stakes
    weighted_shuffle: WeightedShuffle,
    /// The reference count is used to facilitate deallocation, it does not
    /// provide thread safety in a general sense.
    reference_count: AtomicUsize,

    /// The maximum number of nodes each node should retransmit to
    pub const DATA_PLANE_FANOUT: usize = 200;
    /// The maximum depth of the TurbineTree (0->1->2->3)
    /// Fanout of 200 and max depth of 4 allows for ~200^3 (8 million) nodes
    pub const MAX_TURBINE_TREE_DEPTH: usize = 4;
    /// The maximum number of nodes per IP address
    /// When this limit is reached, the nodes contact info is removed so that
    /// the shuffle is deterministic but the node is not used for retransmit
    pub const MAX_NODES_PER_IP_ADDRESS: usize = 10;

    /// Nodes in the TurbineTree may be identified by solely their
    /// pubkey if they are not in the gossip table or their contact info
    /// is not known
    pub const NodeId = union(enum) {
        contact_info: ThreadSafeContactInfo,
        pubkey: Pubkey,
    };

    /// A node in the TurbineTree
    pub const Node = struct {
        id: NodeId,
        stake: u64,

        pub fn pubkey(self: Node) Pubkey {
            return switch (self.id) {
                .contact_info => |ci| ci.pubkey,
                .pubkey => |pk| pk,
            };
        }

        pub fn contactInfo(self: Node) ?ThreadSafeContactInfo {
            return switch (self.id) {
                .contact_info => |ci| ci,
                .pubkey => null,
            };
        }

        pub fn tvuAddress(self: Node) ?SocketAddr {
            return switch (self.id) {
                .contact_info => |ci| ci.tvu_addr,
                .pubkey => null,
            };
        }

        pub fn fromContactInfo(ci: ThreadSafeContactInfo) Node {
            return .{ .id = .contact_info(ci), .stake = ci.stake };
        }
    };

    pub fn initForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        use_stake_hack_for_testing: bool,
    ) !TurbineTree {
        const tvu_peers = try getTvuPeers(
            allocator,
            my_contact_info,
            gossip_table_rw,
        );
        defer tvu_peers.deinit();

        const nodes = try getNodes(
            allocator,
            my_contact_info,
            tvu_peers.items,
            staked_nodes,
            use_stake_hack_for_testing,
        );
        errdefer nodes.deinit();

        var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
        errdefer index.deinit();
        for (nodes.items, 0..) |node, i| try index.put(node.pubkey(), i);

        var node_stakes = try std.ArrayList(u64).initCapacity(allocator, nodes.items.len);
        defer node_stakes.deinit();
        for (nodes.items) |node| node_stakes.appendAssumeCapacity(node.stake);

        const weighted_shuffle = try WeightedShuffle.init(allocator, node_stakes.items);

        return .{
            .allocator = allocator,
            .my_pubkey = my_contact_info.pubkey,
            .nodes = nodes,
            .index = index,
            .weighted_shuffle = weighted_shuffle,
            .reference_count = AtomicUsize.init(1),
        };
    }

    pub fn deinit(self: *TurbineTree) void {
        self.nodes.deinit();
        self.index.deinit();
        self.weighted_shuffle.deinit();
    }

    /// CAUTION: use this method iff you are certain that the TurbineTree has not been
    /// deinitialized. Invalid usage will panic in debug and release safe mode and result
    /// in a use after free in release fast mode.
    pub fn acquireUnsafe(self: *TurbineTree) *TurbineTree {
        const previous_references = self.reference_count.fetchAdd(1, .monotonic);
        std.debug.assert(previous_references > 0);
        return self;
    }

    /// CAUTION: use this method iff you are certain that the TurbineTree has not been
    /// deinitialized. Invalid usage will result in a use after free.
    pub fn releaseUnsafe(self: *TurbineTree) void {
        if (self.reference_count.fetchSub(1, .monotonic) == 1) self.deinit();
    }

    /// Agave uses slot and root bank to check for feature activation for
    /// running fanout experiments. Fine to just use a constant until we
    /// want to run experiments.
    pub fn getDataPlaneFanout(
        // slot: Slot,
        // root_bank: *Bank,
    ) usize {
        return DATA_PLANE_FANOUT;
    }

    /// Get the root distance and retransmit children for the given slot leader and shred id.
    /// The retransmit children are calculated from the weighted shuffle of nodes using the
    /// slot leader and shred id as the seed for the shuffle.
    pub fn getRetransmitChildren(
        self: *const TurbineTree,
        allocator: std.mem.Allocator,
        slot_leader: Pubkey,
        shred_id: ShredId,
        fanout: usize,
    ) !struct {
        usize, // root distance
        std.ArrayList(Node), // children
    } {
        if (slot_leader.equals(&self.my_pubkey)) {
            return error.LoopBack;
        }

        // Clone the weighted shuffle, and remove the slot leader as
        // it should not be included in the retransmit set
        var weighted_shuffle = try self.weighted_shuffle.clone();
        defer weighted_shuffle.deinit();
        if (self.index.get(slot_leader)) |index| {
            weighted_shuffle.removeIndex(index);
        }

        // Shuffle the nodes and find my index
        var shuffled_nodes = try std.ArrayList(Node).initCapacity(
            allocator,
            self.nodes.items.len,
        );
        defer shuffled_nodes.deinit();

        var my_index: usize = undefined;
        var found_my_index = false;
        var chacha = getSeededRng(slot_leader, shred_id);
        var shuffled_indexes = weighted_shuffle.shuffle(chacha.random());

        while (shuffled_indexes.next()) |index| {
            shuffled_nodes.appendAssumeCapacity(self.nodes.items[index]);
            if (!found_my_index) {
                if (self.nodes.items[index].pubkey().equals(&self.my_pubkey)) {
                    my_index = shuffled_nodes.items.len - 1;
                    found_my_index = true;
                }
            }
        }

        // Compute the retransmit children from the shuffled nodes
        const children = try computeRetransmitChildren(
            allocator,
            fanout,
            my_index,
            shuffled_nodes.items,
        );

        // Compute the root distance
        const root_distance: usize = if (my_index == 0)
            0
        else if (my_index <= fanout)
            1
        else if (my_index <= (fanout +| 1) *| fanout) // Does this make sense?
            2
        else
            3;

        return .{ root_distance, children };
    }

    /// Create a seeded RNG for the given leader and shred id.
    /// The resulting RNG must be identical to the agave implementation
    /// to ensure that the weighted shuffle is deterministic.
    fn getSeededRng(leader: Pubkey, shred: ShredId) ChaChaRng {
        const seed = shred.seed(leader);
        return ChaChaRng.fromSeed(seed);
    }

    // root     : [0]
    // 1st layer: [1, 2, ..., fanout]
    // 2nd layer: [[fanout + 1, ..., fanout * 2],
    //             [fanout * 2 + 1, ..., fanout * 3],
    //             ...
    //             [fanout * fanout + 1, ..., fanout * (fanout + 1)]]
    // 3rd layer: ...
    // ...
    // The leader node broadcasts shreds to the root node.
    // The root node retransmits the shreds to all nodes in the 1st layer.
    // Each other node retransmits shreds to fanout many nodes in the next layer.
    // For example the node k in the 1st layer will retransmit to nodes:
    // fanout + k, 2*fanout + k, ..., fanout*fanout + k
    fn computeRetransmitChildren(
        allocator: std.mem.Allocator,
        fanout: usize,
        index: usize,
        nodes: []const Node,
    ) !std.ArrayList(Node) {
        var children = try std.ArrayList(Node).initCapacity(allocator, fanout);

        const offset = (index -| 1) % fanout;
        const anchor = index - offset;
        const step = if (index == 0) 1 else fanout;
        var curr = anchor * fanout + offset + 1;
        var steps: usize = 0;

        while (curr < nodes.len and steps < fanout) {
            children.appendAssumeCapacity(nodes[curr]);
            curr += step;
            steps += 1;
        }

        return children;
    }

    // Returns the parent node in the turbine broadcast tree.
    // Returns None if the node is the root of the tree.
    fn computeRetransmitParent(
        fanout: usize,
        index_: usize,
        nodes: []const Node,
    ) ?Pubkey {
        var index = index_;
        const offset = (index -| 1) % fanout;
        index = if (index == 0) return null else (index - 1) / fanout;
        index = index - (index -| 1) % fanout;
        index = if (index == 0) index else index + offset;
        return nodes[index].pubkey();
    }

    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    fn getNodes(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        use_stake_hack_for_testing: bool,
    ) !std.ArrayList(Node) {
        var nodes = try std.ArrayList(Node).initCapacity(allocator, tvu_peers.len + staked_nodes.count());
        defer nodes.deinit();

        var pubkeys = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer pubkeys.deinit();

        // Add ourself to the list of nodes
        if (use_stake_hack_for_testing) {
            var max_stake: u64 = 0;
            for (staked_nodes.values()) |stake| if (stake > max_stake) {
                max_stake = stake;
            };
            nodes.appendAssumeCapacity(.{ .id = .{ .contact_info = my_contact_info }, .stake = @divFloor(max_stake, 2) });
        } else {
            try nodes.append(.{
                .id = .{ .contact_info = my_contact_info },
                .stake = if (staked_nodes.get(my_contact_info.pubkey)) |stake| stake else 0,
            });
        }
        try pubkeys.put(my_contact_info.pubkey, void{});

        // Add all TVU peers directly to the list of nodes
        // The TVU peers are all nodes in gossip table with the same shred version
        for (tvu_peers) |peer| {
            nodes.appendAssumeCapacity(.{
                .id = .{ .contact_info = peer },
                .stake = if (staked_nodes.get(peer.pubkey)) |stake| stake else 0,
            });
            try pubkeys.put(peer.pubkey, void{});
        }

        // Add all staked nodes to the list of nodes
        // Skip nodes that are already in the list, i.e. nodes with contact info
        for (staked_nodes.keys(), staked_nodes.values()) |pubkey, stake| {
            if (stake > 0 and !pubkeys.contains(pubkey)) {
                nodes.appendAssumeCapacity(.{
                    .id = .{ .pubkey = pubkey },
                    .stake = stake,
                });
            }
        }

        // Sort the nodes by stake, then pubkey
        std.mem.sortUnstable(Node, nodes.items, {}, struct {
            pub fn lt(_: void, lhs: Node, rhs: Node) bool {
                if (lhs.stake > rhs.stake) return true;
                if (lhs.stake < rhs.stake) return false;
                return std.mem.lessThan(u8, &lhs.pubkey().data, &rhs.pubkey().data);
            }
        }.lt);

        // Filter out nodes which exceed the maximum number of nodes per IP and
        // nodes with a stake of 0
        var result = try std.ArrayList(Node).initCapacity(allocator, nodes.items.len);
        errdefer result.deinit();
        var ip_counts = std.AutoArrayHashMap(IpAddr, usize).init(allocator);
        defer ip_counts.deinit();
        for (nodes.items) |node| {
            // Add the node to the result if it does not exceed the
            // maximum number of nodes per IP
            var exceeds_ip_limit = false;
            if (node.tvuAddress()) |tvu_addr| {
                const ip_count = ip_counts.get(tvu_addr.ip()) orelse 0;
                if (ip_count < MAX_NODES_PER_IP_ADDRESS) {
                    result.appendAssumeCapacity(node);
                } else {
                    exceeds_ip_limit = true;
                }
                try ip_counts.put(tvu_addr.ip(), ip_count + 1);
            }

            // Keep the node for deterministic shuffle but remove
            // contact info so that it is not used for retransmit
            if (exceeds_ip_limit and node.stake > 0) {
                result.appendAssumeCapacity(.{
                    .id = .{ .pubkey = node.pubkey() },
                    .stake = node.stake,
                });
            }
        }

        return result;
    }

    /// Get Tvu peers from the gossip table, that is all peers with a matching
    /// shred version.
    fn getTvuPeers(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
    ) !std.ArrayList(ThreadSafeContactInfo) {
        const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        var contact_info_iter = gossip_table.contactInfoIterator(0);
        var tvu_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(allocator, gossip_table.contact_infos.count());

        while (contact_info_iter.nextThreadSafe()) |contact_info| {
            if (!contact_info.pubkey.equals(&my_contact_info.pubkey) and contact_info.shred_version == my_contact_info.shred_version) {
                tvu_peers.appendAssumeCapacity(contact_info);
            }
        }

        return tvu_peers;
    }
};

/// TestEnvironment sets up the dependencies for testing the TurbineTree.
/// Testing could be made more thorough by constructing the gossip table and
/// bank fields, and using the TurbineTreeProvider but this is sufficient for now.
const TestEnvironment = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ContactInfo,
    gossip_table_tp: ThreadPool,
    gossip_table_rw: RwMux(GossipTable),
    nodes: std.ArrayList(ContactInfo),
    staked_nodes: std.AutoArrayHashMap(Pubkey, u64),

    fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_nodes: usize) !TestEnvironment {
        const my_keypair = try KeyPair.create([_]u8{0} ** KeyPair.seed_length);

        const my_contact_info = try ContactInfo.random(
            allocator,
            rand,
            Pubkey.fromPublicKey(&my_keypair.public_key),
            0,
            0,
            0,
        );

        var nodes = std.ArrayList(ContactInfo).init(allocator);
        errdefer nodes.deinit();

        var staked_nodes = std.AutoArrayHashMap(Pubkey, u64).init(allocator);
        errdefer staked_nodes.deinit();

        var gossip_table_tp = ThreadPool.init(.{});
        var gossip_table = try GossipTable.init(
            allocator,
            &gossip_table_tp,
        );
        errdefer gossip_table.deinit();

        // Create nodes
        try nodes.append(my_contact_info);
        for (0..num_nodes - 1) |_| {
            try nodes.append(try ContactInfo.random(
                allocator,
                rand,
                Pubkey.random(rand),
                0,
                0,
                0,
            ));
        }

        // Insert nodes in gossip table
        for (nodes.items) |node| {
            _ = try gossip_table.insert(
                SignedGossipData.init(.{ .ContactInfo = node }),
                0,
            );
        }

        // Add stakes for nodes with contact info
        // Set stake to zero for 1/7 nodes
        try staked_nodes.put(my_contact_info.pubkey, 10);
        var contact_info_iterator = gossip_table.contactInfoIterator(0);
        while (contact_info_iterator.next()) |contact_info| {
            try staked_nodes.put(
                contact_info.pubkey,
                if (rand.intRangeAtMost(u8, 0, 6) != 0)
                    rand.intRangeLessThan(u64, 0, 20)
                else
                    0,
            );
        }

        // Add some staked nodes with no contact info
        for (0..@divFloor(num_nodes, 2)) |_| {
            try staked_nodes.put(Pubkey.random(rand), rand.intRangeLessThan(u64, 0, 20));
        }

        return .{
            .allocator = allocator,
            .my_contact_info = my_contact_info,
            .gossip_table_tp = gossip_table_tp,
            .gossip_table_rw = RwMux(GossipTable).init(gossip_table),
            .nodes = nodes,
            .staked_nodes = staked_nodes,
        };
    }

    fn deinit(self: *TestEnvironment) void {
        self.my_contact_info.deinit();
        const gossip_table: *GossipTable, _ = self.gossip_table_rw.writeWithLock();
        gossip_table.deinit();
        for (self.nodes.items) |node| node.deinit();
        self.nodes.deinit();
        self.staked_nodes.deinit();
    }
};

fn testGetRandomNodes(n: comptime_int, rng: std.rand.Random) [n]TurbineTree.Node {
    var nodes: [n]TurbineTree.Node = undefined;
    for (0..n) |i| nodes[i] = .{
        .id = .{ .pubkey = Pubkey.random(rng) },
        .stake = 0,
    };
    return nodes;
}

fn testCheckRetransmitNodes(allocator: std.mem.Allocator, fanout: usize, nodes: []const TurbineTree.Node, node_expected_children: []const []const TurbineTree.Node) !void {
    // Create an index of the nodes
    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(TurbineTree.computeRetransmitParent(fanout, 0, nodes), null);

    // Check that the retransmit and parent nodes are correct
    for (node_expected_children, 0..) |expected_children, i| {
        // Check that the retransmit children for the ith node are correct
        const actual_peers = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        defer actual_peers.deinit();
        for (expected_children, actual_peers.items) |expected, actual| {
            try std.testing.expectEqual(expected.pubkey(), actual.pubkey());
        }

        // Check that the ith node is the parent of its retransmit children
        const expected_parent_pubkey = nodes[i].pubkey();
        for (expected_children) |peer| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(fanout, index.get(peer.pubkey()).?, nodes).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }

    // Check that the remaining nodes have no children
    for (node_expected_children.len..nodes.len) |i| {
        const actual_peers = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        defer actual_peers.deinit();
        try std.testing.expectEqual(0, actual_peers.items.len);
    }
}

fn testCheckRetransmitNodesRoundTrip(allocator: std.mem.Allocator, fanout: usize, size: comptime_int) !void {
    var prng = std.rand.DefaultPrng.init(0);
    const rand = prng.random();

    var nodes = testGetRandomNodes(size, rand);

    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(null, TurbineTree.computeRetransmitParent(fanout, 0, &nodes));

    // Check that each node is contained in its parents computed children
    for (1..size) |i| {
        const parent = TurbineTree.computeRetransmitParent(fanout, i, &nodes).?;
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, index.get(parent).?, &nodes);
        defer children.deinit();
        var node_i_in_children = false;
        for (children.items) |child| {
            if (child.pubkey().equals(&nodes[i].pubkey())) {
                node_i_in_children = true;
                break;
            }
        }
        try std.testing.expect(node_i_in_children);
    }

    // Check that the computed parent of each nodes child the parent
    for (0..size) |i| {
        const expected_parent_pubkey = nodes[i].pubkey();
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, &nodes);
        defer children.deinit();
        for (children.items) |child| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(fanout, index.get(child.pubkey()).?, &nodes).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }
}

test "agave: cluster nodes retransmit" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    // Setup Environment
    const num_nodes = 1000;
    var env = try TestEnvironment.init(allocator, prng.random(), 1000);
    defer env.deinit();

    // Get Turbine Tree
    var turbine_tree = try TurbineTree.initForRetransmit(
        std.testing.allocator,
        ThreadSafeContactInfo.fromContactInfo(env.my_contact_info),
        &env.gossip_table_rw,
        &env.staked_nodes.unmanaged,
        false,
    );
    defer turbine_tree.deinit();

    // All nodes with contact-info or stakes should be in the index.
    std.debug.print("tree_nodes: {}\n", .{turbine_tree.nodes.items.len});
    try std.testing.expect(turbine_tree.nodes.items.len > num_nodes);

    // Assert that all nodes keep their contact-info.
    // and, all staked nodes are also included.
    var node_map = std.AutoArrayHashMap(Pubkey, TurbineTree.Node).init(allocator);
    defer node_map.deinit();

    for (turbine_tree.nodes.items) |node| try node_map.put(node.pubkey(), node);

    for (env.nodes.items) |node| {
        try std.testing.expectEqual(node.pubkey, node_map.get(node.pubkey).?.pubkey());
    }

    for (env.staked_nodes.keys(), env.staked_nodes.values()) |pubkey, stake| {
        if (stake > 0) {
            try std.testing.expectEqual(stake, node_map.get(pubkey).?.stake);
        }
    }
}

// test "agave: cluster nodes broadcast"

test "agave: get retransmit nodes" {
    { // 20 nodes, 2 fanout
        var prng = std.rand.DefaultPrng.init(0);
        const nds = testGetRandomNodes(20, prng.random());
        const nodes: []const TurbineTree.Node = &.{
            nds[7], // root
            nds[6], nds[10], // 1st layer
            // 2nd layer
            nds[5], nds[19], // 1st neighborhood
            nds[0], nds[14], // 2nd
            // 3rd layer
            nds[3], nds[1], // 1st neighborhood
            nds[12], nds[2], // 2nd
            nds[11], nds[4], // 3rd
            nds[15], nds[18], // 4th
            // 4th layer
            nds[13], nds[16], // 1st neighborhood
            nds[17], nds[9], // 2nd
            nds[8], // 3rd
        };
        const peers: []const []const TurbineTree.Node = &.{
            &.{ nds[6], nds[10] },
            &.{ nds[5], nds[0] },
            &.{ nds[19], nds[14] },
            &.{ nds[3], nds[12] },
            &.{ nds[1], nds[2] },
            &.{ nds[11], nds[15] },
            &.{ nds[4], nds[18] },
            &.{ nds[13], nds[17] },
            &.{ nds[16], nds[9] },
            &.{nds[8]},
        };
        try testCheckRetransmitNodes(std.testing.allocator, 2, nodes, peers);
    }
    { // 36 nodes, 3 fanout
        var prng = std.rand.DefaultPrng.init(0);
        const nds = testGetRandomNodes(36, prng.random());
        const nodes: []const TurbineTree.Node = &.{
            nds[19], // root
            nds[14], nds[15], nds[28], // 1st layer
            // 2nd layer
            nds[29], nds[4], nds[5], // 1st neighborhood
            nds[9], nds[16], nds[7], // 2nd
            nds[26], nds[23], nds[2], // 3rd
            // 3rd layer
            nds[31], nds[3], nds[17], // 1st neighborhood
            nds[20], nds[25], nds[0], // 2nd
            nds[13], nds[30], nds[18], // 3rd
            nds[35], nds[21], nds[22], // 4th
            nds[6], nds[8], nds[11], // 5th
            nds[27], nds[1], nds[10], // 6th
            nds[12], nds[24], nds[34], // 7th
            nds[33], nds[32], // 8th
        };
        const peers: []const []const TurbineTree.Node = &.{
            &.{ nds[14], nds[15], nds[28] },
            &.{ nds[29], nds[9], nds[26] },
            &.{ nds[4], nds[16], nds[23] },
            &.{ nds[5], nds[7], nds[2] },
            &.{ nds[31], nds[20], nds[13] },
            &.{ nds[3], nds[25], nds[30] },
            &.{ nds[17], nds[0], nds[18] },
            &.{ nds[35], nds[6], nds[27] },
            &.{ nds[21], nds[8], nds[1] },
            &.{ nds[22], nds[11], nds[10] },
            &.{ nds[12], nds[33] },
            &.{ nds[24], nds[32] },
            &.{nds[34]},
        };
        try testCheckRetransmitNodes(std.testing.allocator, 3, nodes, peers);
    }
}

test "agave: get retransmit nodes round trip" {
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 2, 1_347);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 3, 1_359);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 4, 4_296);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 5, 3_925);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 6, 8_778);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 7, 9_879);
}
