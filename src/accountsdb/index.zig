//! all index related structs (account ref, simd hashmap, …)

const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const FileId = sig.accounts_db.accounts_file.FileId;
const RwMux = sig.sync.RwMux;

const swiss_map = @import("swiss_map.zig");
pub const SwissMapManaged = swiss_map.SwissMapManaged;
pub const SwissMapUnmanaged = swiss_map.SwissMapUnmanaged;
pub const BenchmarkSwissMap = swiss_map.BenchmarkSwissMap;
pub const BenchHashMap = swiss_map.BenchHashMap;

pub const AccountReferenceHead = struct {
    ref_ptr: *AccountRef,

    const Self = @This();

    pub fn highestRootedSlot(self: *const Self, rooted_slot_max: Slot) struct { usize, Slot } {
        var ref_slot_max: usize = 0;
        var rooted_ref_count: usize = 0;

        var curr: ?*AccountRef = self.ref_ptr;
        while (curr) |ref| : (curr = ref.next_ptr) {
            // only track states less than the rooted slot (ie, they are also rooted)
            const is_not_rooted = ref.slot > rooted_slot_max;
            if (is_not_rooted) continue;

            const is_larger_slot = ref.slot > ref_slot_max or rooted_ref_count == 0;
            if (is_larger_slot) {
                ref_slot_max = ref.slot;
            }
            rooted_ref_count += 1;
        }

        return .{ rooted_ref_count, ref_slot_max };
    }

    pub const PtrToFieldThatIsPtrToRef = union(enum) {
        null,
        head,
        inner: *?*AccountRef,
    };
    /// Returns a pointer to the field which is a pointer to the
    /// account reference pointer with a field `.slot` == `slot`.
    /// Returns `.null` if no account reference has said slot value.
    /// Returns `.head` if `head_ref.ref_ptr.slot == slot`.
    /// Returns `.inner = ptr` if `ptr.*.?.*.slot == slot`.
    pub inline fn getPtrToFieldThatIsPtrToRefWithSlot(
        head_ref: *const AccountReferenceHead,
        slot: Slot,
    ) PtrToFieldThatIsPtrToRef {
        if (head_ref.ref_ptr.slot == slot) return .head;
        var curr_ref_ptr_ptr: *?*AccountRef = &head_ref.ref_ptr.next_ptr;
        while (true) {
            const curr_ref = curr_ref_ptr_ptr.* orelse return .null;
            if (curr_ref.slot == slot) {
                return .{ .inner = curr_ref_ptr_ptr };
            }
            curr_ref_ptr_ptr = &curr_ref.next_ptr;
        }
    }
};

/// reference to an account (either in a file or cache)
pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,
    next_ptr: ?*AccountRef = null,

    /// Analogous to [StorageLocation](https://github.com/anza-xyz/agave/blob/b47a4ec74d85dae0b6d5dd24a13a8923240e03af/accounts-db/src/account_info.rs#L23)
    pub const AccountLocation = union(enum(u8)) {
        File: struct {
            file_id: FileId,
            offset: usize,
        },
        Cache: struct {
            index: usize,
        },
    };

    pub fn default() AccountRef {
        return AccountRef{
            .pubkey = Pubkey.default(),
            .slot = 0,
            .location = .{
                .Cache = .{ .index = 0 },
            },
        };
    }
};

/// stores the mapping from Pubkey to the account location (AccountRef)
///
/// Analogous to [AccountsIndex](https://github.com/anza-xyz/agave/blob/a6b2283142192c5360ad0f53bec1eb4a9fb36154/accounts-db/src/accounts_index.rs#L644)
pub const AccountIndex = struct {
    allocator: std.mem.Allocator,
    reference_allocator: std.mem.Allocator,
    reference_memory: RwMux(ReferenceMemory),
    bins: []RwMux(RefMap),

    /// Guards exclusive access to `ref_head_pool`.
    ref_head_pool_mtx: std.Thread.Mutex = .{},
    /// Must be passed the `allocator` field for allocating methods.
    ref_head_pool: RefHeadPool = .{},

    pubkey_bin_calculator: PubkeyBinCalculator,
    const Self = @This();

    pub const ReferenceMemory = std.AutoHashMap(Slot, std.ArrayList(AccountRef));
    pub const RefMap = SwissMapManaged(Pubkey, *RwMux(AccountReferenceHead), pubkey_hash, pubkey_eql);

    pub fn init(
        /// used to allocate the hashmap data
        allocator: std.mem.Allocator,
        /// used to allocate the references
        reference_allocator: std.mem.Allocator,
        /// number of bins to shard across
        number_of_bins: usize,
    ) !Self {
        const bins = try allocator.alloc(RwMux(RefMap), number_of_bins);
        errdefer allocator.free(number_of_bins);
        @memset(bins, RwMux(RefMap).init(RefMap.init(allocator)));

        return Self{
            .allocator = allocator,
            .reference_allocator = reference_allocator,
            .bins = bins,
            .pubkey_bin_calculator = PubkeyBinCalculator.init(number_of_bins),
            .reference_memory = RwMux(ReferenceMemory).init(ReferenceMemory.init(allocator)),
        };
    }

    pub fn deinit(self: *Self, free_memory: bool) void {
        for (self.bins) |*bin_rw| {
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();
            bin.deinit();
        }
        self.allocator.free(self.bins);

        {
            _ = self.ref_head_pool_mtx; // no point in locking at this point, anything trying to access the pool at this point would be committing a UAF.
            self.ref_head_pool.deinit(self.allocator);
        }

        {
            const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
            defer reference_memory_lg.unlock();

            if (free_memory) {
                var iter = reference_memory.iterator();
                while (iter.next()) |entry| {
                    entry.value_ptr.deinit();
                }
            }
            reference_memory.deinit();
        }
    }

    pub fn ensureBinsTotalCapacity(self: *Self, size: u32) !void {
        for (self.bins) |*bin_rw| {
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();
            try bin.ensureTotalCapacity(size);
        }
        self.ref_head_pool_mtx.lock();
        defer self.ref_head_pool_mtx.unlock();
        try self.ref_head_pool.ensureTotalCapacity(self.allocator, size * self.bins.len);
    }

    pub fn putReferenceBlock(self: *Self, slot: Slot, references: std.ArrayList(AccountRef)) !void {
        const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();
        try reference_memory.putNoClobber(slot, references);
    }

    pub fn freeReferenceBlock(self: *Self, slot: Slot) error{MemoryNotFound}!void {
        const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();

        const removed_kv = reference_memory.fetchRemove(slot) orelse return error.MemoryNotFound;
        removed_kv.value.deinit();
    }

    /// Get a read-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same bin is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).read*(){.get(pubkey)}` directly.
    pub fn getReferenceHeadRead(self: *Self, pubkey: *const Pubkey) ?struct { *const AccountReferenceHead, RwMux(AccountReferenceHead).RLockGuard } {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).readWithLock();
        defer bin_lg.unlock();
        const ref_head_rw = bin.get(pubkey.*) orelse return null;
        return ref_head_rw.readWithLock();
    }

    /// Get a write-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same bin is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).write*(){.get(pubkey)}` directly.
    pub fn getReferenceHeadWrite(self: *Self, pubkey: *const Pubkey) ?struct { *AccountReferenceHead, RwMux(AccountReferenceHead).WLockGuard } {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).readWithLock();
        defer bin_lg.unlock();
        const ref_head_rw = bin.get(pubkey.*) orelse return null;
        return ref_head_rw.writeWithLock();
    }

    pub const GetAccountRefError = error{ SlotNotFound, PubkeyNotFound };

    /// Get a pointer to the account reference pointer with slot `slot` and pubkey `pubkey`,
    /// alongside the write lock guard for the parent bin, and thus by extension the account
    /// reference; this also locks access to all other account references in the parent bin.
    /// This can be used to update an account reference (ie by replacing the `*AccountRef`).
    pub fn getReferencePtrPtrWrite(
        self: *const Self,
        pubkey: *const Pubkey,
        slot: Slot,
    ) GetAccountRefError!struct { **AccountRef, RwMux(AccountReferenceHead).WLockGuard } {
        const head_ref, var head_ref_lg = blk: {
            const bin, var bin_lg = self.getBinFromPubkey(pubkey).readWithLock();
            defer bin_lg.unlock();

            const head_ref_rw = bin.get(pubkey.*) orelse return error.PubkeyNotFound;
            break :blk head_ref_rw.writeWithLock();
        };
        errdefer head_ref_lg.unlock();

        const ref_ptr_ptr = switch (head_ref.getPtrToFieldThatIsPtrToRefWithSlot(slot)) {
            .null => return error.SlotNotFound,
            .head => &head_ref.ref_ptr,
            .inner => |inner| &inner.*.?,
        };
        return .{ ref_ptr_ptr, head_ref_lg };
    }

    /// returns a reference to the slot in the index which is a local copy
    /// useful for reading the slot without holding the lock.
    /// NOTE: its not safe to read the underlying data without holding the lock
    pub fn getReferenceSlotCopy(self: *Self, pubkey: *const Pubkey, slot: Slot) ?AccountRef {
        const head_ref, var head_ref_lg = self.getReferenceHeadRead(pubkey) orelse return null;
        defer head_ref_lg.unlock();

        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        var slot_ref_copy: AccountRef = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break ref.*;
        } else return null;
        // since this will purely be a copy, it's safer to not allow the caller
        // to observe the `next_ptr` value, because they won't have the lock.
        slot_ref_copy.next_ptr = null;
        return slot_ref_copy;
    }

    pub fn exists(self: *Self, pubkey: *const Pubkey, slot: Slot) bool {
        const head_ref, var head_ref_lg = self.getReferenceHeadRead(pubkey) orelse return false;
        defer head_ref_lg.unlock();

        // find the slot in the reference list
        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const does_exist = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break true;
        } else false;

        return does_exist;
    }

    /// Adds the reference to the index if there is not a duplicate (ie, the same slot).
    ///
    /// Returns if the reference was inserted.
    ///
    /// Assumes `self.getBinFromPubkey(&account_ref.pubkey)` has enough capacity for at
    /// least onef more entry.
    ///
    /// Locks `self.ref_head_pool_mtx` and allocates if necessary.
    pub fn indexRefIfNotDuplicateSlotAssumeBinCapacity(self: *Self, account_ref: *AccountRef) std.mem.Allocator.Error!bool {
        self.ref_head_pool_mtx.lock();
        defer self.ref_head_pool_mtx.unlock();
        try self.ref_head_pool.ensureUnusedCapacity(self.allocator, 1);
        return self.indexRefIfNotDuplicateSlotAssumeCapacityPoolLocked(account_ref);
    }

    /// Adds the reference to the index if there is not a duplicate (ie, the same slot).
    ///
    /// Returns if the reference was inserted.
    ///
    /// Assumes `self.getBinFromPubkey(&account_ref.pubkey)` has enough capacity for at
    /// least onef more entry.
    ///
    /// Assumes `self.ref_head_pool_mtx` is already locked, and that there is capacity
    /// in `self.ref_head_pool` for at least one more element.
    pub fn indexRefIfNotDuplicateSlotAssumeCapacityPoolLocked(self: *Self, account_ref: *AccountRef) bool {
        const head_ref, var head_ref_lg = blk: {
            const bin, var bin_lg = self.getBinFromPubkey(&account_ref.pubkey).writeWithLock();
            defer bin_lg.unlock(); // the lock on the bin also locks the reference map

            const gop = bin.getOrPutAssumeCapacity(account_ref.pubkey);
            if (!gop.found_existing) {
                gop.value_ptr.* = self.acquireAndInitRwHeadRefAssumeCapacityLocked(.{ .ref_ptr = account_ref });
                return true;
            }

            break :blk gop.value_ptr.*.writeWithLock();
        };
        defer head_ref_lg.unlock();

        // traverse until you find the end
        var curr = head_ref.ref_ptr;
        while (true) {
            if (curr.slot == account_ref.slot) {
                // found a duplicate => dont do the insertion
                return false;
            }

            const next_ptr = curr.next_ptr orelse {
                // end of the list => insert it here
                curr.next_ptr = account_ref;
                return true;
            };

            // keep traversing
            curr = next_ptr;
        }
    }

    /// Adds a reference to the index.
    ///
    /// Assumes `self.getBinFromPubkey(&account_ref.pubkey)` has enough capacity for at
    /// least onef more entry.
    ///
    /// Locks `self.ref_head_pool_mtx` and allocates if necessary.
    ///
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRefAssumeBinCapacity(self: *Self, account_ref: *AccountRef) std.mem.Allocator.Error!void {
        self.ref_head_pool_mtx.lock();
        defer self.ref_head_pool_mtx.unlock();
        try self.ref_head_pool.ensureUnusedCapacity(self.allocator, 1);
        self.indexRefAssumeCapacityPoolLocked(account_ref);
    }

    /// Adds a reference to the index.
    ///
    /// Assumes `self.getBinFromPubkey(&account_ref.pubkey)` has enough capacity for at
    /// least onef more entry.
    ///
    /// Assumes `self.ref_head_pool_mtx` is already locked, and that there is capacity
    /// in `self.ref_head_pool` for at least one more element.
    ///
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRefAssumeCapacityPoolLocked(self: *Self, account_ref: *AccountRef) void {
        const head_ref, var head_ref_lg = blk: {
            const bin, var bin_lg = self.getBinFromPubkey(&account_ref.pubkey).writeWithLock();
            defer bin_lg.unlock(); // the lock on the bin also locks the reference map

            const gop = bin.getOrPutAssumeCapacity(account_ref.pubkey); // 1)
            if (!gop.found_existing) {
                gop.value_ptr.* = self.acquireAndInitRwHeadRefAssumeCapacityLocked(.{ .ref_ptr = account_ref });
                return;
            }

            break :blk gop.value_ptr.*.writeWithLock();
        };
        defer head_ref_lg.unlock();

        // traverse until you find the end
        var curr_ref = head_ref.ref_ptr;
        while (curr_ref.next_ptr) |next_ref| {
            curr_ref = next_ref;
        }
        std.debug.assert(curr_ref.next_ptr == null);
        curr_ref.next_ptr = account_ref;
    }

    pub fn updateReference(
        self: *const Self,
        pubkey: *const Pubkey,
        slot: Slot,
        new_ref: *AccountRef,
    ) GetAccountRefError!void {
        const ref_ptr_ptr, var head_ref_lg = try self.getReferencePtrPtrWrite(pubkey, slot);
        defer head_ref_lg.unlock();
        std.debug.assert(ref_ptr_ptr.*.slot == slot);
        std.debug.assert(ref_ptr_ptr.*.pubkey.equals(pubkey));
        ref_ptr_ptr.* = new_ref;
    }

    pub fn removeReference(self: *Self, pubkey: *const Pubkey, slot: Slot) error{ SlotNotFound, PubkeyNotFound }!void {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).writeWithLock();
        defer bin_lg.unlock();

        const head_ref_rw = bin.get(pubkey.*) orelse return error.PubkeyNotFound;
        const head_ref, var head_ref_lg = head_ref_rw.writeWithLock();
        switch (head_ref.getPtrToFieldThatIsPtrToRefWithSlot(slot)) {
            .null => {
                head_ref_lg.unlock();
                return error.SlotNotFound;
            },
            .inner => |inner| {
                inner.* = if (inner.*) |ref| ref.next_ptr else null;
                head_ref_lg.unlock();
            },
            .head => {
                head_ref.ref_ptr = head_ref.ref_ptr.next_ptr orelse {
                    bin.remove(pubkey.*) catch |err| switch (err) {
                        error.KeyNotFound => unreachable, // we already know it exists
                    };
                    self.recycleRwHeadRef(head_ref_rw); // we don't unlock `head_ref_lg` at this point, because it can no longer be assumed to possess valid state.
                    return;
                };
                head_ref_lg.unlock();
            },
        }
    }

    fn acquireAndInitRwHeadRefAssumeCapacity(self: *Self, init_value: AccountReferenceHead) *RwMux(AccountReferenceHead) {
        self.ref_head_pool_mtx.lock();
        defer self.ref_head_pool_mtx.unlock();
        return self.acquireAndInitRwHeadRefAssumeCapacityLocked(init_value);
    }
    /// Assumes `self.ref_head_pool_mtx` is locked.
    fn acquireAndInitRwHeadRefAssumeCapacityLocked(self: *Self, init_value: AccountReferenceHead) *RwMux(AccountReferenceHead) {
        const elem = self.ref_head_pool.acquireUndefElemAssumeCapacity();
        elem.* = RwMux(AccountReferenceHead).init(init_value);
        return elem;
    }

    fn recycleRwHeadRef(self: *Self, head_ref_rw: *RwMux(AccountReferenceHead)) void {
        self.ref_head_pool_mtx.lock();
        defer self.ref_head_pool_mtx.unlock();
        self.ref_head_pool.recycleElem(head_ref_rw);
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.pubkey_bin_calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *RwMux(RefMap) {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *RwMux(RefMap) {
        const bin_index = self.pubkey_bin_calculator.binIndex(pubkey);
        return self.getBin(bin_index);
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }
};

pub const RefHeadPool = struct {
    store: std.SegmentedList(Elem, 0) = .{},
    free_list: FreeList = .{},

    comptime {
        std.debug.assert(@sizeOf(Elem) >= @sizeOf(Node));
    }

    pub const Elem = RwMux(AccountReferenceHead);

    /// Each `*Node` is an `*Elem` in disguise.
    pub const Node = extern struct {
        next: ?*Node align(@alignOf(Elem)) = null,

        pub fn fromUndefElem(elem: *Elem) *Node {
            const node: *Node = @ptrCast(elem);
            node.* = .{};
            return node;
        }

        pub fn toUndefElem(self: *Node) *Elem {
            const res: *Elem = @ptrCast(self);
            res.* = undefined;
            return res;
        }
    };

    pub const FreeList = struct {
        head: ?*Node = null,
        len: usize = 0,

        pub fn push(free_list: *FreeList, node: *Node) void {
            node.next = free_list.head;
            free_list.head = node;
            free_list.len += 1;
        }

        pub fn pop(free_list: *FreeList) ?*Node {
            const popped = free_list.head orelse return null;
            free_list.head = popped.next;
            popped.next = null;
            free_list.len -= 1;
            return popped;
        }
    };

    pub fn deinit(pool: *RefHeadPool, allocator: std.mem.Allocator) void {
        pool.store.deinit(allocator);
    }

    /// Create `count` new elements that can be acquired.
    pub fn prepareCapacity(pool: *RefHeadPool, allocator: std.mem.Allocator, count: usize) std.mem.Allocator.Error!void {
        try pool.store.growCapacity(allocator, pool.store.len + count);
        for (0..count) |_| {
            const new_elem = pool.store.addOne(sig.utils.allocators.failing.allocator(.{})) catch unreachable; // the call to `growCapacity` should make this impossible
            const new_node = Node.fromUndefElem(new_elem);
            pool.free_list.push(new_node);
        }
    }

    /// Ensures there are `count` minus however many elements already exist (acquired or otherwise)
    /// elements ready to be acquired, aka `count` elements in total.
    pub fn ensureTotalCapacity(pool: *RefHeadPool, allocator: std.mem.Allocator, count: usize) std.mem.Allocator.Error!void {
        if (count <= pool.store.count()) return;
        return pool.prepareCapacity(allocator, count - pool.store.count());
    }

    /// Ensures there are at least `count` elements that can be acquired.
    pub fn ensureUnusedCapacity(pool: *RefHeadPool, allocator: std.mem.Allocator, count: usize) std.mem.Allocator.Error!void {
        if (count <= pool.free_list.len) return;
        return pool.prepareCapacity(allocator, count - pool.free_list.len);
    }

    /// Caller should preempt this with a call to preallocate space for at least one element.
    pub fn acquireUndefElemAssumeCapacity(pool: *RefHeadPool) *Elem {
        return pool.free_list.pop().?.toUndefElem();
    }

    pub fn acquireUndefElem(pool: *RefHeadPool) std.mem.Allocator!*Elem {
        if (pool.free_list.pop()) |node| return node.toUndefElem();
        return try pool.store.addOne();
    }

    /// Recycle the element if it's no longer in use.
    pub fn recycleElem(pool: *RefHeadPool, elem: *Elem) void {
        pool.free_list.push(Node.fromUndefElem(elem));
    }
};

pub inline fn pubkey_hash(key: Pubkey) u64 {
    return std.mem.readInt(u64, key.data[0..8], .little);
}

pub inline fn pubkey_eql(key1: Pubkey, key2: Pubkey) bool {
    return key1.equals(&key2);
}

pub const DiskMemoryConfig = struct {
    // path to where disk files will be stored
    dir_path: []const u8,
    // size of each bins' reference arraylist to preallocate
    capacity: usize,
};

pub const RamMemoryConfig = struct {
    // size of each bins' reference arraylist to preallocate
    capacity: usize = 0,
    // we found this leads to better 'append' performance vs GPA
    allocator: std.mem.Allocator = std.heap.page_allocator,
};

/// calculator to know which bin a pubkey belongs to
/// (since the index is sharded into bins).
///
/// Analogous to [PubkeyBinCalculator24](https://github.com/anza-xyz/agave/blob/c87f9cdfc98e80077f68a3d86aefbc404a1cb4d6/accounts-db/src/pubkey_bins.rs#L4)
pub const PubkeyBinCalculator = struct {
    n_bins: usize,
    shift_bits: u6,

    pub fn init(n_bins: usize) PubkeyBinCalculator {
        // u8 * 3 (ie, we consider on the first 3 bytes of a pubkey)
        const MAX_BITS: u32 = 24;
        // within bounds
        std.debug.assert(n_bins > 0);
        std.debug.assert(n_bins <= (1 << MAX_BITS));
        // power of two
        std.debug.assert((n_bins & (n_bins - 1)) == 0);
        // eg,
        // 8 bins
        // => leading zeros = 28
        // => shift_bits = (24 - (32 - 28 - 1)) = 21
        // ie,
        // if we have the first 24 bits set (u8 << 16, 8 + 16 = 24)
        // want to consider the first 3 bits of those 24
        // 0000 ... [100]0 0000 0000 0000 0000 0000
        // then we want to shift right by 21
        // 0000 ... 0000 0000 0000 0000 0000 0[100]
        // those 3 bits can represent 2^3 (= 8) bins
        const shift_bits = @as(u6, @intCast(MAX_BITS - (32 - @clz(@as(u32, @intCast(n_bins))) - 1)));

        return PubkeyBinCalculator{
            .n_bins = n_bins,
            .shift_bits = shift_bits,
        };
    }

    pub fn binIndex(self: *const PubkeyBinCalculator, pubkey: *const Pubkey) usize {
        const data = &pubkey.data;
        return (@as(usize, data[0]) << 16 |
            @as(usize, data[1]) << 8 |
            @as(usize, data[2])) >> self.shift_bits;
    }
};

test "account index update/remove reference" {
    const allocator = std.testing.allocator;

    var index = try AccountIndex.init(allocator, allocator, 8);
    defer index.deinit(true);
    try index.ensureBinsTotalCapacity(100);

    // pubkey -> a
    var ref_a = AccountRef.default();
    try index.indexRefAssumeBinCapacity(&ref_a);

    var ref_b = AccountRef.default();
    ref_b.slot = 1;
    try index.indexRefAssumeBinCapacity(&ref_b);

    // make sure indexRef works
    {
        const ref_head, var ref_head_lg = index.getReferenceHeadRead(&ref_a.pubkey).?;
        defer ref_head_lg.unlock();
        _, const ref_max = ref_head.highestRootedSlot(10);
        try std.testing.expectEqual(1, ref_max);
    }

    // update the tail
    try std.testing.expect(ref_b.location == .Cache);
    var ref_b2 = ref_b;
    ref_b2.location = .{ .File = .{
        .file_id = FileId.fromInt(@intCast(1)),
        .offset = 10,
    } };
    try index.updateReference(&ref_b.pubkey, 1, &ref_b2);
    {
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 1).?;
        try std.testing.expect(ref.location == .File);
    }

    // update the head
    var ref_a2 = ref_a;
    ref_a2.location = .{ .File = .{
        .file_id = FileId.fromInt(1),
        .offset = 20,
    } };
    try index.updateReference(&ref_a.pubkey, 0, &ref_a2);
    {
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 0).?;
        try std.testing.expect(ref.location == .File);
    }

    // remove the head
    try index.removeReference(&ref_a2.pubkey, 0);
    try std.testing.expect(!index.exists(&ref_a2.pubkey, 0));
    try std.testing.expect(index.exists(&ref_b2.pubkey, 1));

    // remove the tail
    try index.removeReference(&ref_b2.pubkey, 1);
    try std.testing.expect(!index.exists(&ref_b2.pubkey, 1));
}
