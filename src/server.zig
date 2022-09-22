const std = @import("std");
const io = std.io;
const net = std.net;
const dh = std.crypto.dh;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const random = std.crypto.random;
const ArrayList = std.ArrayList;

const msg = @import("msg.zig");
const key = @import("key.zig");
const extension = @import("extension.zig");
const certificate = @import("certificate.zig");
const key_share = @import("key_share.zig");
const SupportedVersions = @import("supported_versions.zig").SupportedVersions;
const signature_scheme = @import("signature_scheme.zig");
const server_name = @import("server_name.zig");
const crypto = @import("crypto.zig");
const x509 = @import("x509.zig");
const ServerHello = @import("server_hello.zig").ServerHello;
const ClientHello = @import("client_hello.zig").ClientHello;
const Handshake = @import("handshake.zig").Handshake;
const EncryptedExtensions = @import("encrypted_extensions.zig").EncryptedExtensions;
const Finished = @import("finished.zig").Finished;
const Alert = @import("alert.zig").Alert;
const ApplicationData = @import("application_data.zig").ApplicationData;
const CertificateVerify = @import("certificate_verify.zig").CertificateVerify;
const NamedGroup = @import("supported_groups.zig").NamedGroup;
const NamedGroupList = @import("supported_groups.zig").NamedGroupList;
const RecordPayloadProtector = @import("protector.zig").RecordPayloadProtector;
const TLSPlainText = @import("tls_plain.zig").TLSPlainText;
const TLSCipherText = @import("tls_cipher.zig").TLSCipherText;
const TLSInnerPlainText = @import("tls_cipher.zig").TLSInnerPlainText;

const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const rsa = @import("rsa.zig");

pub const TLSServerTCP = TLSServerImpl(net.Stream.Reader, net.Stream.Writer, true);

pub fn TLSServerImpl(comptime ReaderType: type, comptime WriterType: type, comptime is_tcp: bool) type {
    return struct {
        // io
        io_init: bool = false,
        reader: ReaderType = undefined,
        writer: WriterType = undefined,
        writeBuffer: io.BufferedWriter(4096, WriterType) = undefined,
        tcp_server: net.StreamServer = undefined,

        // session related
        random: [32]u8,
        session_id: msg.SessionID,
        host: []u8 = &([_]u8{}),

        // message buffer for KeySchedule
        msgs_bytes: []u8,
        msgs_stream: io.FixedBufferStream([]u8),

        // state machine
        state: State = State.START,
        already_recv_hrr: bool = false,

        // certificate
        cert: certificate.CertificateEntry,

        // private keys
        cert_secp256r1_key: P256.KeyPair,

        // key_share
        supported_groups: ArrayList(NamedGroup),
        key_share: NamedGroup,

        // X25519 DH keys
        x25519_priv_key: [32]u8 = [_]u8{0} ** 32,
        x25519_pub_key: [32]u8 = [_]u8{0} ** 32,

        // secp256r1 DH keys
        secp256r1_key: P256.KeyPair = undefined,

        // payload protection
        cipher_suites: ArrayList(msg.CipherSuite),
        ks: key.KeyScheduler,
        hs_protector: RecordPayloadProtector,
        ap_protector: RecordPayloadProtector,

        // certificate
        signature_schems: ArrayList(signature_scheme.SignatureScheme),
        cert_pubkeys: ArrayList(x509.PublicKey),

        // Misc
        allocator: std.mem.Allocator,

        // logoutput
        print_keys: bool = false,

        const State = enum { START, RECV_CH, NEGOTIATED, WAIT_FLIGHT2, WAIT_FINISHED, CONNECTED };

        const Self = @This();

        const Error = error{
            IllegalParameter,
            UnexpectedMessage,
            IoNotConfigured,
            InvalidServerHello,
            UnsupportedCertificateAlgorithm,
            UnsupportedCipherSuite,
            UnsupportedKeyShareAlgorithm,
            UnsupportedSignatureScheme,
            CertificateNotFound,
            FailedToConnect,
            UnsupportedPrivateKey,
        };

        pub fn init(allocator: std.mem.Allocator) !Self {
            var session_id = try msg.SessionID.init(32);
            var msgs_bytes = try allocator.alloc(u8, 1024 * 32);
            errdefer allocator.free(msgs_bytes);

            var rand: [32]u8 = undefined;
            random.bytes(&rand);
            random.bytes(session_id.session_id.slice());

            const cert_keys = try x509.ECPrivateKey.fromDer("./test/prikey.der", allocator);
            if (cert_keys.namedCurve) |n| {
                if (!std.mem.eql(u8, n.id, "1.2.840.10045.3.1.7")) {
                    // currently, only accepts secp256r1.
                    return Error.UnsupportedPrivateKey;
                }
            } else {
                return Error.UnsupportedPrivateKey;
            }
            const cert_priv_key = try P256.SecretKey.fromBytes(cert_keys.privateKey[0..P256.SecretKey.encoded_length].*);

            var res = Self{
                .random = rand,
                .session_id = session_id,
                .msgs_bytes = msgs_bytes,
                .msgs_stream = io.fixedBufferStream(msgs_bytes),
                .cert = try certificate.CertificateEntry.fromDerFile("./test/cert.der", allocator),
                .cert_secp256r1_key = try P256.KeyPair.fromSecretKey(cert_priv_key),
                .supported_groups = ArrayList(NamedGroup).init(allocator),
                .key_share = .x25519,
                .cipher_suites = ArrayList(msg.CipherSuite).init(allocator),
                .ks = undefined,
                .hs_protector = undefined,
                .ap_protector = undefined,
                .signature_schems = ArrayList(signature_scheme.SignatureScheme).init(allocator),
                .cert_pubkeys = ArrayList(x509.PublicKey).init(allocator),

                .allocator = allocator,
            };

            random.bytes(&res.x25519_priv_key);
            res.x25519_pub_key = try dh.X25519.recoverPublicKey(res.x25519_priv_key);

            var skey_bytes: [P256.SecretKey.encoded_length]u8 = undefined;
            random.bytes(skey_bytes[0..]);
            var skey = try P256.SecretKey.fromBytes(skey_bytes);
            res.secp256r1_key = try P256.KeyPair.fromSecretKey(skey);

            try res.supported_groups.append(.x25519);
            try res.supported_groups.append(.secp256r1);

            try res.cipher_suites.append(.TLS_AES_128_GCM_SHA256);
            try res.cipher_suites.append(.TLS_AES_256_GCM_SHA384);
            try res.cipher_suites.append(.TLS_CHACHA20_POLY1305_SHA256);

            try res.signature_schems.append(.ecdsa_secp256r1_sha256);
            try res.signature_schems.append(.rsa_pss_rsae_sha256);

            return res;
        }

        pub fn initWithIo(reader: ReaderType, writer: WriterType, allocator: std.mem.Allocator) !Self {
            var res = try Self.init(allocator);
            res.io_init = true;
            res.reader = reader;
            res.writer = writer;

            return res;
        }

        pub fn deinit(self: Self) void {
            self.allocator.free(self.msgs_bytes);
            for (self.cert_pubkeys.items) |c| {
                c.deinit();
            }
            if (self.host.len != 0) {
                self.allocator.free(self.host);
            }
            self.cert_pubkeys.deinit();
            self.supported_groups.deinit();
            self.cipher_suites.deinit();
            self.ks.deinit();
            self.signature_schems.deinit();
        }

        pub fn listen(self: *Self, port: u16) !void {
            if (is_tcp) {
                self.tcp_server = net.StreamServer.init(.{
                    .reuse_address = true,
                });
                const addr = try net.Address.parseIp("127.0.0.1", port);
                try self.tcp_server.listen(addr);
            }
        }

        pub fn accept(self: *Self) !net.StreamServer.Connection {
            std.log.info("accept", .{});
            return try self.tcp_server.accept();
        }

        fn createServerHello(self: Self) !ServerHello {
            var server_hello = ServerHello.init(self.random, self.session_id, .TLS_AES_128_GCM_SHA256, self.allocator);

            // Extension SupportedVresions
            var sv = try SupportedVersions.init(.server_hello);
            try sv.versions.append(0x0304); //TLSv1.3
            try server_hello.extensions.append(.{ .supported_versions = sv });

            // Extension KeyShare
            var ks = key_share.KeyShare.init(self.allocator, .server_hello, false);
            switch (self.key_share) {
                .x25519 => {
                    var entry_x25519 = try key_share.KeyShareEntry.init(.x25519, 32, self.allocator);
                    std.mem.copy(u8, entry_x25519.key_exchange, &self.x25519_pub_key);
                    try ks.entries.append(entry_x25519);
                },
                .secp256r1 => {
                    var entry_secp256r1 = try key_share.KeyShareEntry.init(.secp256r1, P256.PublicKey.uncompressed_sec1_encoded_length, self.allocator);
                    std.mem.copy(u8, entry_secp256r1.key_exchange, &self.secp256r1_key.public_key.toUncompressedSec1());
                    try ks.entries.append(entry_secp256r1);
                },
                else => unreachable,
            }
            try server_hello.extensions.append(.{ .key_share = ks });

            return server_hello;
        }

        pub fn handleConnection(self: *Self, con: net.StreamServer.Connection) !void {
            self.msgs_stream.reset();
            self.reader = con.stream.reader();
            var t = try con.stream.reader().readEnum(ContentType, .Big);
            self.writeBuffer = io.bufferedWriter(con.stream.writer());
            const ch = try TLSPlainText.decode(con.stream.reader(), t, self.allocator, null, self.msgs_stream.writer());
            std.log.info("HOGEHOGE", .{});

            self.session_id = ch.content.handshake.client_hello.legacy_session_id;
            const sh = try self.createServerHello();
            const hs_sh = Handshake{ .server_hello = sh };
            _ = try hs_sh.encode(self.msgs_stream.writer());

            const record_sh = TLSPlainText{ .content = Content{ .handshake = hs_sh } };
            defer record_sh.deinit();
            _ = try record_sh.encode(self.writeBuffer.writer());

            const hkdf = crypto.Hkdf.Sha256.hkdf;
            const aead = crypto.Aead.Aes128Gcm.aead;
            self.ks = try key.KeyScheduler.init(hkdf, aead);
            const ks = (try msg.getExtension(ch.content.handshake.client_hello.extensions, .key_share)).key_share;
            if (ks.entries.items.len == 0) {
                return Error.InvalidServerHello;
            }

            const key_entry = ks.entries.items[0];
            if (key_entry.group != .x25519 and key_entry.group != .secp256r1) {
                return Error.UnsupportedKeyShareAlgorithm;
            }

            const zero_bytes = &([_]u8{0} ** 64);
            const client_pubkey = key_entry.key_exchange;
            switch (key_entry.group) {
                .x25519 => {
                    const shared_key = try dh.X25519.scalarmult(self.x25519_priv_key, client_pubkey[0..32].*);
                    try self.ks.generateEarlySecrets(&shared_key, zero_bytes[0..self.ks.hkdf.digest_length]);
                },
                .secp256r1 => {
                    const pubkey = try P256.PublicKey.fromSec1(client_pubkey);
                    const mul = try pubkey.p.mulPublic(self.secp256r1_key.secret_key.bytes, .Big);
                    const shared_key = mul.affineCoordinates().x.toBytes(.Big);
                    try self.ks.generateEarlySecrets(&shared_key, zero_bytes[0..self.ks.hkdf.digest_length]);
                },
                else => unreachable,
            }

            try self.ks.generateHandshakeSecrets(self.msgs_stream.getWritten());

            self.hs_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.s_hs_keys, self.ks.secret.c_hs_keys);

            const ee = EncryptedExtensions.init(self.allocator);
            const cont_ee = Content{ .handshake = .{ .encrypted_extensions = ee } };
            defer cont_ee.deinit();
            _ = try cont_ee.encode(self.msgs_stream.writer());

            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_ee, self.allocator, self.writeBuffer.writer());

            var c = try certificate.Certificate.init(0, self.allocator);
            try c.cert_list.append(self.cert);
            const cont_c = Content{ .handshake = .{ .certificate = c } };
            //defer cont_c.deinit();
            _ = try cont_c.encode(self.msgs_stream.writer());
            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_c, self.allocator, self.writeBuffer.writer());
            _ = c.cert_list.pop();

            var hash_out: [crypto.Hkdf.MAX_DIGEST_LENGTH]u8 = undefined;
            std.log.info("LEN={}", .{try self.msgs_stream.getPos()});
            self.ks.hkdf.hash(&hash_out, self.msgs_stream.getWritten());

            var verify_bytes: [1000]u8 = undefined;
            var verify_stream = io.fixedBufferStream(&verify_bytes);
            _ = try verify_stream.write(&([_]u8{0x20} ** 64));
            _ = try verify_stream.write("TLS 1.3, server CertificateVerify");
            _ = try verify_stream.write(&([_]u8{0x00}));
            _ = try verify_stream.write(hash_out[0..self.ks.hkdf.digest_length]);

            const verify_sig = try self.cert_secp256r1_key.sign(verify_stream.getWritten(), null);
            var sig_buf: [P256.Signature.der_encoded_max_length]u8 = undefined;
            const sig_bytes = verify_sig.toDer(&sig_buf);
            const cv = try CertificateVerify.init(.ecdsa_secp256r1_sha256, sig_bytes.len, self.allocator);
            std.mem.copy(u8, cv.signature, sig_bytes);
            const cont_cv = Content{ .handshake = .{ .certificate_verify = cv } };
            defer cont_cv.deinit();
            _ = try cont_cv.encode(self.msgs_stream.writer());
            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_cv, self.allocator, self.writeBuffer.writer());

            const fin = try Finished.fromMessageBytes(self.msgs_stream.getWritten(), self.ks.secret.s_hs_finished_secret.slice(), self.ks.hkdf);
            const cont_fin = Content{ .handshake = Handshake{ .finished = fin } };
            defer cont_fin.deinit();
            _ = try cont_fin.encode(self.msgs_stream.writer());

            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_fin, self.allocator, self.writeBuffer.writer());

            try self.writeBuffer.flush();

            try self.ks.generateApplicationSecrets(self.msgs_stream.getWritten());
            self.ap_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.s_ap_keys, self.ks.secret.c_ap_keys);
            self.ks.printKeys(&self.random);

            t = try con.stream.reader().readEnum(ContentType, .Big);
            while (t != .application_data) {
                const recv_record = (try TLSPlainText.decode(self.reader, t, self.allocator, null, null));
                defer recv_record.deinit();
                t = try con.stream.reader().readEnum(ContentType, .Big);
            }

            while (true) {
                const recv_record = try TLSCipherText.decode(self.reader, t, self.allocator);
                defer recv_record.deinit();

                var plain_record = try self.hs_protector.decrypt(recv_record, self.allocator);
                defer plain_record.deinit();

                if (plain_record.content_type != .handshake) {
                    if (plain_record.content_type == .alert) {
                        const alert = (try plain_record.decodeContent(self.allocator, null)).alert;
                        std.log.err("alert = {}", .{alert});
                        t = try con.stream.reader().readEnum(ContentType, .Big);
                        continue;
                    } else {
                        return Error.FailedToConnect;
                    }
                }

                const c_fin = (try plain_record.decodeContent(self.allocator, self.ks.hkdf)).handshake.finished;
                if (!c_fin.verify(self.msgs_stream.getWritten(), self.ks.secret.c_hs_finished_secret.slice())) {
                    return Error.FailedToConnect;
                }
                break;
            }

            std.log.info("HOGEHOGE", .{});

            t = try con.stream.reader().readEnum(ContentType, .Big);
            while (t != .application_data) {
                const recv_record2 = (try TLSPlainText.decode(self.reader, t, self.allocator, null, null));
                defer recv_record2.deinit();
                t = try con.stream.reader().readEnum(ContentType, .Big);
            }

            const recv_record2 = try TLSCipherText.decode(self.reader, t, self.allocator);
            defer recv_record2.deinit();
            var plain_record2 = try self.ap_protector.decrypt(recv_record2, self.allocator);
            defer plain_record2.deinit();

            std.log.info("RECV=\n {s}", .{plain_record2.content});

            const send_data = "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY>tls13-zig</BODY></HTML>";
            const app_c = Content{ .application_data = try ApplicationData.initAsView(send_data) };
            defer app_c.deinit();
            _ = try self.ap_protector.encryptFromMessageAndWrite(app_c, self.allocator, self.writeBuffer.writer());
            try self.writeBuffer.flush();
        }
    };
}
