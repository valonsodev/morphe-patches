// Host-only tests for pvhook.zig. NOT part of the shipped library.
// See PRIME_VIDEO_LOOP_HANDOFF_2026-08-08.md section 9 for how to run:
//   copy pvhook.zig, replace the four `extern fn` decls with local no-op
//   stubs so it links on the host, append this file, then `zig test`.
// ── host diagnostic tests (not part of the shipped library) ───────────────────
const rego_json =
    "{\"description\":{\"adDeliverySessionId\":\"7f3a91c2-aaaa-bbbb-cccc-1234567890ab_PBP_EXPL_9f8e7d6c5b4a\"," ++
    "\"adMarkerId\":\"PRE_ROLL\"}," ++
    "\"playlist\":[{\"type\":\"Ad\",\"durationMs\":15000},{\"type\":\"Ad\",\"durationMs\":30000}]," ++
    "\"measurement\":{\"beaconUrl\":\"https://s.amazon-adsystem.com/impression\"}}";

fn runCase(name: []const u8, total_len: usize, fill: u8, lead: usize) void {
    var buf: [65536]u8 = undefined;
    @memset(buf[0..total_len], fill);
    @memcpy(buf[lead .. lead + rego_json.len], rego_json);
    const r = filterRegolith(buf[0..total_len]);
    std.debug.print(
        "{s:<46} buf_len={d:<6} outcome={s:<16} emptied={:<5} items={d}\n",
        .{ name, total_len, @tagName(r.outcome), r.outcome == .emptied, r.item_count },
    );
}

test "regolith gate matrix" {
    std.debug.print("\njson_len={d}\n", .{rego_json.len});
    runCase("A exact buffer (len == json len)", rego_json.len, ' ', 0);
    runCase("B trailing NUL padding (+64)", rego_json.len + 64, 0, 0);
    runCase("C trailing space padding (+64)", rego_json.len + 64, ' ', 0);
    runCase("D trailing NUL padding (+1)", rego_json.len + 1, 0, 0);
    runCase("E dest buffer exactly 4096 (pow2)", 4096, 0, 0);
    runCase("F dest buffer 8192 (pow2)", 8192, 0, 0);
    runCase("G dest buffer 5000 (non-pow2, NUL pad)", 5000, 0, 0);
    runCase("H leading junk byte (offset 1)", rego_json.len + 1, ' ', 1);
}

const prs_body =
    "{\"intraTitlePlaylist\":[{\"type\":\"Remote\",\"durationMs\":15000}," ++
    "{\"type\":\"Feature\",\"durationMs\":1500000}]," ++
    "\"adDeliverySessionId\":\"abc_PBP_EXPL_def\",\"measurement\":{\"a\":1}," ++
    "\"padpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpad\":1}";

test "output is valid JSON with an empty playlist and unchanged length" {
    var buf: [4096]u8 = undefined;
    const total = rego_json.len + 37; // realistic trailing padding
    @memset(buf[0..total], 0);
    @memcpy(buf[0..rego_json.len], rego_json);

    const r = filterRegolith(buf[0..total]);
    try std.testing.expectEqual(RegolithOutcome.emptied, r.outcome);
    try std.testing.expectEqual(@as(u32, 2), r.item_count);

    // brackets survive in place, only the interior was blanked
    const open = std.mem.indexOf(u8, buf[0..total], "\"playlist\":[").? + 11;
    const close = std.mem.indexOfScalarPos(u8, buf[0..total], open, ']').?;
    try std.testing.expect(std.mem.indexOfNone(u8, buf[open + 1 .. close], " ") == null);

    // the JSON prefix still parses, and playlist is now empty
    const json_end = std.mem.lastIndexOfScalar(u8, buf[0..rego_json.len], '}').? + 1;
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        buf[0..json_end],
        .{},
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(usize, 0), root.get("playlist").?.array.items.len);
    try std.testing.expect(root.get("measurement") != null);
    try std.testing.expect(root.get("description") != null);
}

test "PRS body is left for filterPrs, not touched here" {
    var buf: [4096]u8 = undefined;
    @memset(buf[0..prs_body.len], 0);
    @memcpy(buf[0..prs_body.len], prs_body);
    const before = buf[0..prs_body.len].*;
    const r = filterRegolith(buf[0..prs_body.len]);
    try std.testing.expectEqual(RegolithOutcome.prs_body, r.outcome);
    try std.testing.expect(r.outcome != .emptied);
    try std.testing.expectEqualSlices(u8, &before, buf[0..prs_body.len]);
}

test "truncated array is left untouched" {
    // all three markers present, but the playlist array never closes in this buffer
    const truncated =
        "{\"description\":{\"adDeliverySessionId\":\"7f3a91c2-aaaa-bbbb-cccc-1234567890ab_PBP_EXPL_9f8e\"}," ++
        "\"measurement\":{\"beaconUrl\":\"https://s.amazon-adsystem.com/impression\"}," ++
        "\"playlist\":[{\"type\":\"Ad\",\"durationMs\":15000},{\"type\":\"Ad\",\"durat";
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..truncated.len], truncated);
    const before = buf[0..truncated.len].*;
    const r = filterRegolith(buf[0..truncated.len]);
    try std.testing.expect(r.outcome != .emptied);
    try std.testing.expectEqualSlices(u8, &before, buf[0..truncated.len]);
}

test "second pass is a no-op" {
    var buf: [4096]u8 = undefined;
    const total = rego_json.len + 16;
    @memset(buf[0..total], 0);
    @memcpy(buf[0..rego_json.len], rego_json);
    try std.testing.expectEqual(RegolithOutcome.emptied, filterRegolith(buf[0..total]).outcome);
    const after_first = buf[0..total].*;
    const second = filterRegolith(buf[0..total]);
    try std.testing.expectEqual(RegolithOutcome.already_empty, second.outcome);
    try std.testing.expectEqualSlices(u8, &after_first, buf[0..total]);
}
test "empty pauseAdsResolution object no longer corrupts the buffer" {
    const body = "{\"pauseAdsResolution\":{},\"intraTitlePlaylist\":[],\"z\":1}";
    var buf: [512]u8 = undefined;
    @memcpy(buf[0..body.len], body);
    const r = filterPrs(buf[0..body.len]);
    try std.testing.expectEqualStrings(body, buf[0..body.len]); // "{}" -> "{}", byte-identical
    try std.testing.expectEqual(@as(u32, 1), r.pause_ads);
}

test "populated pauseAdsResolution is replaced and stays valid JSON" {
    const body = "{\"pauseAdsResolution\":{\"pauseAdsResolutionUrl\":\"https://aax.amazon-adsystem.com/x\"}," ++
        "\"intraTitlePlaylist\":[],\"z\":1}";
    var buf: [512]u8 = undefined;
    @memcpy(buf[0..body.len], body);
    const r = filterPrs(buf[0..body.len]);
    try std.testing.expectEqual(@as(u32, 1), r.pause_ads);
    try std.testing.expectEqual(body.len, buf[0..body.len].len);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buf[0..body.len], .{});
    defer parsed.deinit();
    const par = parsed.value.object.get("pauseAdsResolution").?;
    try std.testing.expectEqual(@as(usize, 0), par.object.count()); // now {}
}
