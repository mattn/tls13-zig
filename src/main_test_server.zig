const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const allocator = std.heap.page_allocator;

const server = @import("server.zig");

pub fn main() !void {
    log.info("started.", .{});
    var tls_server = try server.TLSServerTCP.init(allocator);
    defer tls_server.deinit();
    tls_server.print_keys = true;
    try tls_server.listen(8443);
    while (true) {
        var con = try tls_server.accept();
        tls_server.handleConnection(con) catch {
            con.stream.close();
            continue;
        };
        con.stream.close();
    }

    return;
}
