const std = @import("std");
const Pubkey = @import("pubkey.zig").Pubkey;
const base58 = @import("base58-zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const BASE_58_ENCODER = base58.Encoder.init(.{});
const BASE_58_DECODER = base58.Decoder.init(.{});

pub const SIGNATURE_LENGTH: usize = 64;
pub const SIGNATURE_BASE58_LENGTH: usize = 88;

pub const Signature = struct {
    data: [SIGNATURE_LENGTH]u8 = [_]u8{0} ** SIGNATURE_LENGTH,

    const Self = @This();

    pub fn init(bytes: [SIGNATURE_LENGTH]u8) Self {
        return .{
            .data = bytes,
        };
    }

    pub fn default() Self {
        return .{};
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []const u8) bool {
        const sig = Ed25519.Signature.fromBytes(self.data);
        sig.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch return false;
        return true;
    }

    pub fn verifier(
        self: Self,
        pubkey: Pubkey,
    ) (e.NonCanonicalError || e.EncodingError || e.IdentityElementError)!Verifier {
        const sig = Ed25519.Signature.fromBytes(self.data);
        return sig.verifier(Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable);
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }

    pub fn toBase58EncodedString(self: *const Signature) error{EncodingError}![SIGNATURE_BASE58_LENGTH]u8 {
        var dest: [SIGNATURE_BASE58_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE_58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > SIGNATURE_BASE58_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ SIGNATURE_BASE58_LENGTH, written, dest, self.data });
        }
        return dest;
    }

    pub fn fromBase58EncodedString(encoded: []const u8) error{DecodingError}!Self {
        var dest: [SIGNATURE_LENGTH]u8 = undefined;
        const written = BASE_58_DECODER.decode(encoded, &dest) catch return error.DecodingError;
        if (written != SIGNATURE_LENGTH) {
            return error.DecodingError;
        }
        return Self.init(dest);
    }
};
