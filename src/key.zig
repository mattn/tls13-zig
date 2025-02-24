const std = @import("std");
const io = std.io;
const mem = std.mem;
const dh = std.crypto.dh;
const expect = std.testing.expect;

const crypto = @import("crypto.zig");
const Secret = @import("crypto.zig").Secret;

pub const KeyScheduler = struct {
    const Self = @This();

    secret: crypto.Secret,
    hkdf: crypto.Hkdf,
    aead: crypto.Aead,

    pub fn init(hkdf: crypto.Hkdf, aead: crypto.Aead) !Self {
        return Self{
            .secret = try crypto.Secret.init(hkdf, aead),
            .hkdf = hkdf,
            .aead = aead,
        };
    }

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn generateEarlySecrets(self: *Self, shared_key: []const u8, psk: []const u8) !void {
        self.hkdf.deriveEarlySecret(self.secret.early_secret.slice(), psk);
        try self.hkdf.deriveSecret(self.secret.hs_derived_secret.slice(), self.secret.early_secret.slice(), "derived", "");
        self.hkdf.extract(self.secret.hs_secret.slice(), self.secret.hs_derived_secret.slice(), shared_key);
    }

    pub fn generateHandshakeSecrets(self: *Self, msgs: []const u8) !void {
        const zero_bytes = &([_]u8{0} ** 64);
        try self.hkdf.deriveSecret(self.secret.s_hs_secret.slice(), self.secret.hs_secret.slice(), "s hs traffic", msgs);
        try self.hkdf.deriveSecret(self.secret.c_hs_secret.slice(), self.secret.hs_secret.slice(), "c hs traffic", msgs);
        try self.hkdf.deriveSecret(self.secret.master_derived_secret.slice(), self.secret.hs_secret.slice(), "derived", "");
        self.hkdf.extract(self.secret.master_secret.slice(), self.secret.master_derived_secret.slice(), zero_bytes[0..self.hkdf.digest_length]);
        try self.generateRecordKeys(&self.secret.s_hs_keys, self.secret.s_hs_secret.slice());
        try self.generateRecordKeys(&self.secret.c_hs_keys, self.secret.c_hs_secret.slice());
        try self.hkdf.hkdfExpandLabel(self.secret.s_hs_finished_secret.slice(), self.secret.s_hs_secret.slice(), "finished", "", self.hkdf.digest_length);
        try self.hkdf.hkdfExpandLabel(self.secret.c_hs_finished_secret.slice(), self.secret.c_hs_secret.slice(), "finished", "", self.hkdf.digest_length);
    }

    pub fn generateApplicationSecrets(self: *Self, msgs: []const u8) !void {
        try self.hkdf.deriveSecret(self.secret.s_ap_secret.slice(), self.secret.master_secret.slice(), "s ap traffic", msgs);
        try self.hkdf.deriveSecret(self.secret.c_ap_secret.slice(), self.secret.master_secret.slice(), "c ap traffic", msgs);

        try self.generateRecordKeys(&self.secret.s_ap_keys, self.secret.s_ap_secret.slice());
        try self.generateRecordKeys(&self.secret.c_ap_keys, self.secret.c_ap_secret.slice());

        try self.hkdf.deriveSecret(self.secret.exp_master_secret.slice(), self.secret.master_secret.slice(), "exp master", msgs);
    }

    fn generateRecordKeys(self: Self, record_keys: *Secret.RecordKeys, secret: []const u8) !void {
        try self.hkdf.hkdfExpandLabel(record_keys.key.slice(), secret, "key", "", self.aead.key_length);
        try self.hkdf.hkdfExpandLabel(record_keys.iv.slice(), secret, "iv", "", self.aead.nonce_length);
    }

    pub fn generateResumptionMasterSecret(self: *Self, msgs: []const u8) !void {
        try self.hkdf.deriveSecret(self.secret.res_master_secret.slice(), self.secret.master_secret.slice(), "res master", msgs);
    }

    pub fn printKeys(self: Self, random: []const u8) void {
        std.debug.print("SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n", .{ std.fmt.fmtSliceHexLower(random), &std.fmt.fmtSliceHexLower(self.secret.s_hs_secret.slice()) });
        std.debug.print("EXPORTER_SECRET {} {}\n", .{ std.fmt.fmtSliceHexLower(random), std.fmt.fmtSliceHexLower(self.secret.exp_master_secret.slice()) });
        std.debug.print("SERVER_TRAFFIC_SECRET_0 {} {}\n", .{ std.fmt.fmtSliceHexLower(random), std.fmt.fmtSliceHexLower(self.secret.s_ap_secret.slice()) });
        std.debug.print("CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n", .{ std.fmt.fmtSliceHexLower(random), std.fmt.fmtSliceHexLower(self.secret.c_hs_secret.slice()) });
        std.debug.print("CLIENT_TRAFFIC_SECRET_0 {} {}\n", .{ std.fmt.fmtSliceHexLower(random), std.fmt.fmtSliceHexLower(self.secret.c_ap_secret.slice()) });
    }
};

test "KeyScheduler AES128GCM-SHA256" {
    const Handshake = @import("handshake.zig").Handshake;
    const RecordPayloadProtector = @import("protector.zig").RecordPayloadProtector;

    var msgs_bytes = [_]u8{0} ** (1024 * 32);
    var msgs_stream = io.fixedBufferStream(&msgs_bytes);

    const dhe_shared_key = [_]u8{ 0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };

    var hkdf = crypto.Hkdf.Sha256.hkdf;
    var aead = crypto.Aead.Aes128Gcm.aead;

    var ks = try KeyScheduler.init(hkdf, aead);
    defer ks.deinit();
    try ks.generateEarlySecrets(&dhe_shared_key, &([_]u8{0} ** 32));

    const early_secret_ans = [_]u8{ 0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a };
    const hs_derived_secret_ans = [_]u8{ 0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba };
    const hs_secret_ans = [_]u8{ 0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac };
    try expect(std.mem.eql(u8, ks.secret.early_secret.slice(), &early_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.hs_derived_secret.slice(), &hs_derived_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.hs_secret.slice(), &hs_secret_ans));

    const ch_bytes = [_]u8{ 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };
    const sh_bytes = [_]u8{ 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
    var stream = io.fixedBufferStream(&sh_bytes);
    const sh = (try Handshake.decode(stream.reader(), std.testing.allocator, null)).server_hello;
    defer sh.deinit();

    _ = try msgs_stream.write(&ch_bytes);
    _ = try msgs_stream.write(&sh_bytes);

    try ks.generateHandshakeSecrets(msgs_stream.getWritten());
    var hs_protector = RecordPayloadProtector.init(@import("crypto.zig").Aead.Aes128Gcm.aead, ks.secret.c_hs_keys, ks.secret.s_hs_keys);

    const c_hs_secret_ans = [_]u8{ 0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f, 0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21 };
    const s_hs_secret_ans = [_]u8{ 0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4, 0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38 };
    const master_derived_secret_ans = [_]u8{ 0x43, 0xde, 0x77, 0xe0, 0xc7, 0x77, 0x13, 0x85, 0x9a, 0x94, 0x4d, 0xb9, 0xdb, 0x25, 0x90, 0xb5, 0x31, 0x90, 0xa6, 0x5b, 0x3e, 0xe2, 0xe4, 0xf1, 0x2d, 0xd7, 0xa0, 0xbb, 0x7c, 0xe2, 0x54, 0xb4 };
    const master_secret_ans = [_]u8{ 0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f, 0x8a, 0x47, 0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8, 0xd0, 0x40, 0x29, 0x19 };
    const hs_read_key_ans = [_]u8{ 0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc };
    const hs_read_iv_ans = [_]u8{ 0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30 };
    try expect(std.mem.eql(u8, ks.secret.c_hs_secret.slice(), &c_hs_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.s_hs_secret.slice(), &s_hs_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.master_derived_secret.slice(), &master_derived_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.master_secret.slice(), &master_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.s_hs_keys.key.slice(), &hs_read_key_ans));
    try expect(std.mem.eql(u8, ks.secret.s_hs_keys.iv.slice(), &hs_read_iv_ans));

    const enc_data = [_]u8{ 0x17, 0x03, 0x03, 0x02, 0xA2, 0xD1, 0xFF, 0x33, 0x4A, 0x56, 0xF5, 0xBF, 0xF6, 0x59, 0x4A, 0x07, 0xCC, 0x87, 0xB5, 0x80, 0x23, 0x3F, 0x50, 0x0F, 0x45, 0xE4, 0x89, 0xE7, 0xF3, 0x3A, 0xF3, 0x5E, 0xDF, 0x78, 0x69, 0xFC, 0xF4, 0x0A, 0xA4, 0x0A, 0xA2, 0xB8, 0xEA, 0x73, 0xF8, 0x48, 0xA7, 0xCA, 0x07, 0x61, 0x2E, 0xF9, 0xF9, 0x45, 0xCB, 0x96, 0x0B, 0x40, 0x68, 0x90, 0x51, 0x23, 0xEA, 0x78, 0xB1, 0x11, 0xB4, 0x29, 0xBA, 0x91, 0x91, 0xCD, 0x05, 0xD2, 0xA3, 0x89, 0x28, 0x0F, 0x52, 0x61, 0x34, 0xAA, 0xDC, 0x7F, 0xC7, 0x8C, 0x4B, 0x72, 0x9D, 0xF8, 0x28, 0xB5, 0xEC, 0xF7, 0xB1, 0x3B, 0xD9, 0xAE, 0xFB, 0x0E, 0x57, 0xF2, 0x71, 0x58, 0x5B, 0x8E, 0xA9, 0xBB, 0x35, 0x5C, 0x7C, 0x79, 0x02, 0x07, 0x16, 0xCF, 0xB9, 0xB1, 0x18, 0x3E, 0xF3, 0xAB, 0x20, 0xE3, 0x7D, 0x57, 0xA6, 0xB9, 0xD7, 0x47, 0x76, 0x09, 0xAE, 0xE6, 0xE1, 0x22, 0xA4, 0xCF, 0x51, 0x42, 0x73, 0x25, 0x25, 0x0C, 0x7D, 0x0E, 0x50, 0x92, 0x89, 0x44, 0x4C, 0x9B, 0x3A, 0x64, 0x8F, 0x1D, 0x71, 0x03, 0x5D, 0x2E, 0xD6, 0x5B, 0x0E, 0x3C, 0xDD, 0x0C, 0xBA, 0xE8, 0xBF, 0x2D, 0x0B, 0x22, 0x78, 0x12, 0xCB, 0xB3, 0x60, 0x98, 0x72, 0x55, 0xCC, 0x74, 0x41, 0x10, 0xC4, 0x53, 0xBA, 0xA4, 0xFC, 0xD6, 0x10, 0x92, 0x8D, 0x80, 0x98, 0x10, 0xE4, 0xB7, 0xED, 0x1A, 0x8F, 0xD9, 0x91, 0xF0, 0x6A, 0xA6, 0x24, 0x82, 0x04, 0x79, 0x7E, 0x36, 0xA6, 0xA7, 0x3B, 0x70, 0xA2, 0x55, 0x9C, 0x09, 0xEA, 0xD6, 0x86, 0x94, 0x5B, 0xA2, 0x46, 0xAB, 0x66, 0xE5, 0xED, 0xD8, 0x04, 0x4B, 0x4C, 0x6D, 0xE3, 0xFC, 0xF2, 0xA8, 0x94, 0x41, 0xAC, 0x66, 0x27, 0x2F, 0xD8, 0xFB, 0x33, 0x0E, 0xF8, 0x19, 0x05, 0x79, 0xB3, 0x68, 0x45, 0x96, 0xC9, 0x60, 0xBD, 0x59, 0x6E, 0xEA, 0x52, 0x0A, 0x56, 0xA8, 0xD6, 0x50, 0xF5, 0x63, 0xAA, 0xD2, 0x74, 0x09, 0x96, 0x0D, 0xCA, 0x63, 0xD3, 0xE6, 0x88, 0x61, 0x1E, 0xA5, 0xE2, 0x2F, 0x44, 0x15, 0xCF, 0x95, 0x38, 0xD5, 0x1A, 0x20, 0x0C, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8A, 0x26, 0x4E, 0xD6, 0x54, 0x0C, 0x84, 0x83, 0x8D, 0x89, 0xF7, 0x2C, 0x24, 0x46, 0x1A, 0xAD, 0x6D, 0x26, 0xF5, 0x9E, 0xCA, 0xBA, 0x9A, 0xCB, 0xBB, 0x31, 0x7B, 0x66, 0xD9, 0x02, 0xF4, 0xF2, 0x92, 0xA3, 0x6A, 0xC1, 0xB6, 0x39, 0xC6, 0x37, 0xCE, 0x34, 0x31, 0x17, 0xB6, 0x59, 0x62, 0x22, 0x45, 0x31, 0x7B, 0x49, 0xEE, 0xDA, 0x0C, 0x62, 0x58, 0xF1, 0x00, 0xD7, 0xD9, 0x61, 0xFF, 0xB1, 0x38, 0x64, 0x7E, 0x92, 0xEA, 0x33, 0x0F, 0xAE, 0xEA, 0x6D, 0xFA, 0x31, 0xC7, 0xA8, 0x4D, 0xC3, 0xBD, 0x7E, 0x1B, 0x7A, 0x6C, 0x71, 0x78, 0xAF, 0x36, 0x87, 0x90, 0x18, 0xE3, 0xF2, 0x52, 0x10, 0x7F, 0x24, 0x3D, 0x24, 0x3D, 0xC7, 0x33, 0x9D, 0x56, 0x84, 0xC8, 0xB0, 0x37, 0x8B, 0xF3, 0x02, 0x44, 0xDA, 0x8C, 0x87, 0xC8, 0x43, 0xF5, 0xE5, 0x6E, 0xB4, 0xC5, 0xE8, 0x28, 0x0A, 0x2B, 0x48, 0x05, 0x2C, 0xF9, 0x3B, 0x16, 0x49, 0x9A, 0x66, 0xDB, 0x7C, 0xCA, 0x71, 0xE4, 0x59, 0x94, 0x26, 0xF7, 0xD4, 0x61, 0xE6, 0x6F, 0x99, 0x88, 0x2B, 0xD8, 0x9F, 0xC5, 0x08, 0x00, 0xBE, 0xCC, 0xA6, 0x2D, 0x6C, 0x74, 0x11, 0x6D, 0xBD, 0x29, 0x72, 0xFD, 0xA1, 0xFA, 0x80, 0xF8, 0x5D, 0xF8, 0x81, 0xED, 0xBE, 0x5A, 0x37, 0x66, 0x89, 0x36, 0xB3, 0x35, 0x58, 0x3B, 0x59, 0x91, 0x86, 0xDC, 0x5C, 0x69, 0x18, 0xA3, 0x96, 0xFA, 0x48, 0xA1, 0x81, 0xD6, 0xB6, 0xFA, 0x4F, 0x9D, 0x62, 0xD5, 0x13, 0xAF, 0xBB, 0x99, 0x2F, 0x2B, 0x99, 0x2F, 0x67, 0xF8, 0xAF, 0xE6, 0x7F, 0x76, 0x91, 0x3F, 0xA3, 0x88, 0xCB, 0x56, 0x30, 0xC8, 0xCA, 0x01, 0xE0, 0xC6, 0x5D, 0x11, 0xC6, 0x6A, 0x1E, 0x2A, 0xC4, 0xC8, 0x59, 0x77, 0xB7, 0xC7, 0xA6, 0x99, 0x9B, 0xBF, 0x10, 0xDC, 0x35, 0xAE, 0x69, 0xF5, 0x51, 0x56, 0x14, 0x63, 0x6C, 0x0B, 0x9B, 0x68, 0xC1, 0x9E, 0xD2, 0xE3, 0x1C, 0x0B, 0x3B, 0x66, 0x76, 0x30, 0x38, 0xEB, 0xBA, 0x42, 0xF3, 0xB3, 0x8E, 0xDC, 0x03, 0x99, 0xF3, 0xA9, 0xF2, 0x3F, 0xAA, 0x63, 0x97, 0x8C, 0x31, 0x7F, 0xC9, 0xFA, 0x66, 0xA7, 0x3F, 0x60, 0xF0, 0x50, 0x4D, 0xE9, 0x3B, 0x5B, 0x84, 0x5E, 0x27, 0x55, 0x92, 0xC1, 0x23, 0x35, 0xEE, 0x34, 0x0B, 0xBC, 0x4F, 0xDD, 0xD5, 0x02, 0x78, 0x40, 0x16, 0xE4, 0xB3, 0xBE, 0x7E, 0xF0, 0x4D, 0xDA, 0x49, 0xF4, 0xB4, 0x40, 0xA3, 0x0C, 0xB5, 0xD2, 0xAF, 0x93, 0x98, 0x28, 0xFD, 0x4A, 0xE3, 0x79, 0x4E, 0x44, 0xF9, 0x4D, 0xF5, 0xA6, 0x31, 0xED, 0xE4, 0x2C, 0x17, 0x19, 0xBF, 0xDA, 0xBF, 0x02, 0x53, 0xFE, 0x51, 0x75, 0xBE, 0x89, 0x8E, 0x75, 0x0E, 0xDC, 0x53, 0x37, 0x0D, 0x2B };
    const pt_misc = try hs_protector.decryptFromCipherBytes(&enc_data, std.testing.allocator);
    defer pt_misc.deinit();

    _ = try msgs_stream.write(pt_misc.content);
    try ks.generateApplicationSecrets(msgs_stream.getWritten());

    const c_hs_finished_secret_ans = [_]u8{ 0xb8, 0x0a, 0xd0, 0x10, 0x15, 0xfb, 0x2f, 0x0b, 0xd6, 0x5f, 0xf7, 0xd4, 0xda, 0x5d, 0x6b, 0xf8, 0x3f, 0x84, 0x82, 0x1d, 0x1f, 0x87, 0xfd, 0xc7, 0xd3, 0xc7, 0x5b, 0x5a, 0x7b, 0x42, 0xd9, 0xc4 };
    const c_ap_secret_ans = [_]u8{ 0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5 };
    const s_ap_secret_ans = [_]u8{ 0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56, 0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9, 0x50, 0x32, 0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a, 0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43 };
    const hs_write_key_ans = [_]u8{ 0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b, 0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25, 0x8d, 0x01 };
    const hs_write_iv_ans = [_]u8{ 0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76, 0xbb, 0x73, 0x26, 0x5f };
    const s_ap_key_ans = [_]u8{ 0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56 };
    const s_ap_iv_ans = [_]u8{ 0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84 };
    const c_ap_key_ans = [_]u8{ 0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f, 0x50, 0x51 };
    const c_ap_iv_ans = [_]u8{ 0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9 };
    try expect(std.mem.eql(u8, ks.secret.c_hs_finished_secret.slice(), &c_hs_finished_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.c_ap_secret.slice(), &c_ap_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.s_ap_secret.slice(), &s_ap_secret_ans));
    try expect(std.mem.eql(u8, ks.secret.c_hs_keys.key.slice(), &hs_write_key_ans));
    try expect(std.mem.eql(u8, ks.secret.c_hs_keys.iv.slice(), &hs_write_iv_ans));
    try expect(std.mem.eql(u8, ks.secret.s_ap_keys.key.slice(), &s_ap_key_ans));
    try expect(std.mem.eql(u8, ks.secret.s_ap_keys.iv.slice(), &s_ap_iv_ans));
    try expect(std.mem.eql(u8, ks.secret.c_ap_keys.key.slice(), &c_ap_key_ans));
    try expect(std.mem.eql(u8, ks.secret.c_ap_keys.iv.slice(), &c_ap_iv_ans));

    const c_finished = [_]u8{ 0x14, 0x0, 0x0, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2, 0xed, 0xd5, 0xce, 0x61 };
    _ = try msgs_stream.write(&c_finished);
    try ks.generateResumptionMasterSecret(msgs_stream.getWritten());

    const res_master_secret_ans = [_]u8{ 0x7d, 0xf2, 0x35, 0xf2, 0x03, 0x1d, 0x2a, 0x05, 0x12, 0x87, 0xd0, 0x2b, 0x02, 0x41, 0xb0, 0xbf, 0xda, 0xf8, 0x6c, 0xc8, 0x56, 0x23, 0x1f, 0x2d, 0x5a, 0xba, 0x46, 0xc4, 0x34, 0xec, 0x19, 0x6c };
    try expect(std.mem.eql(u8, ks.secret.res_master_secret.slice(), &res_master_secret_ans));
}

test "X25519 key pair deriviation" {
    const s_key = [_]u8{ 0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05 };
    const p_key_ans = [_]u8{ 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c };
    const p_key = try dh.X25519.recoverPublicKey(s_key);

    try expect(std.mem.eql(u8, &p_key, &p_key_ans));
}
