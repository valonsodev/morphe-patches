const std = @import("std");
const builtin = @import("builtin");

const log_tag: [*:0]const u8 = "PVHook";
const ignite_library = "libignite.so";
const diagnostic_build = "primehook-20260813.01-deep-diagnostics";

const diagnostic_log_name = "pvhook-diagnostics.log";
const diagnostic_raw_name = "pvhook-candidate-buffers.bin";
const proc_self_cmdline = "/proc/self/cmdline";
const proc_self_maps = "/proc/self/maps";

const arm_prs_copy_signature = [_]u8{
    0x00, 0x20, 0x60, 0x55, 0x40, 0x46, 0x31, 0x46,
    0x07, 0xf0, 0xc6, 0xfc, 0xdd, 0xed, 0x02, 0x0b,
    0x04, 0x98, 0xc9, 0xf8, 0x08, 0x00, 0x01, 0x20,
    0x89, 0xf8, 0x0c, 0x00, 0xc9, 0xed, 0x00, 0x0b,
};
const aarch64_prs_copy_signature = [_]u8{
    0xff, 0x6a, 0x36, 0x38, 0xe0, 0x03, 0x14, 0xaa,
    0xe1, 0x03, 0x15, 0xaa, 0x1f, 0x27, 0x00, 0x94,
    0xe0, 0x83, 0xc0, 0x3c, 0xe8, 0x0f, 0x40, 0xf9,
    0x29, 0x00, 0x80, 0x52, 0x69, 0x62, 0x00, 0x39,
};
const min_prs_length = 512;
const min_regolith_length = 128;
const max_prs_length = 262144;
const min_bundle_length = 256 * 1024;
const max_bundle_length = 32 * 1024 * 1024;
const max_playlist_items = 256;
const max_metadata_edits = 256;
const max_json_depth = 64;
// Bounded backing storage for Scanner's nesting BitStack, including its reserve capacity.
const json_stack_storage_bytes = 256;

const android_log_info = 4;
const android_log_error = 6;
const jni_version_1_6 = 0x00010006;

// Zig 0.16's std.elf does not expose ARM or AArch64 relocation constants.
const r_arm_jump_slot = 22;
const r_aarch64_jump_slot = 1026;
const prot_read = 1;
const prot_write = 2;
const sc_pagesize = 39;
const o_read_only = 0;
const o_write_only = 1;
const o_create = 0x40;
const o_append = 0x400;
const o_close_on_exec = 0x80000;
const private_file_mode = 0o600;

const DlPhdrInfo = extern struct {
    dlpi_addr: usize,
    dlpi_name: ?[*:0]const u8,
    dlpi_phdr: [*]const std.elf.ElfN.Phdr,
    dlpi_phnum: u16,
};

const DlIterateCallback = *const fn (
    info: *const DlPhdrInfo,
    size: usize,
    context: ?*anyopaque,
) callconv(.c) c_int;

extern fn dl_iterate_phdr(callback: DlIterateCallback, context: ?*anyopaque) c_int;
extern fn mprotect(address: *anyopaque, length: usize, protection: c_int) c_int;
extern fn sysconf(name: c_int) isize;
extern fn __android_log_write(priority: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern fn read(fd: c_int, buffer: [*]u8, length: usize) isize;
extern fn write(fd: c_int, buffer: [*]const u8, length: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn gettid() c_int;

const CopyFn = *const fn (
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
) callconv(.c) ?*anyopaque;

const CheckedCopyFn = *const fn (
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
    destination_length: usize,
) callconv(.c) ?*anyopaque;

const FilterResult = struct {
    found_playlist: bool = false,
    complete: bool = false,
    total_items: u32 = 0,
    remote_items: u32 = 0,
    pause_ads: u32 = 0,
    non_linear_ads: u32 = 0,
    modified: bool = false,
    /// Set when the body could not be analyzed, which disables the strip
    /// entirely. Reported so a limit that starts biting is visible on device.
    parse_error: ?anyerror = null,
};

var regolith_skip_logs = std.atomic.Value(u32).init(0);
var prs_length_skip_logs = std.atomic.Value(u32).init(0);
var prs_parse_skip_logs = std.atomic.Value(u32).init(0);

fn shouldLogDiagnostic(counter: *std.atomic.Value(u32)) bool {
    _ = counter;
    // This is intentionally an uncapped diagnostic build. Persistent files can
    // grow without a hook-imposed ceiling; the user explicitly prefers complete
    // evidence over bounded storage for this investigation.
    return true;
}

var real_memcpy: ?*anyopaque = null;
var real_memmove: ?*anyopaque = null;
var real_memcpy_chk: ?*anyopaque = null;
var real_memmove_chk: ?*anyopaque = null;
var ignite_base: usize = 0;
var prs_copy_return_address: usize = 0;
var diagnostic_fd: c_int = -1;
var diagnostic_raw_fd: c_int = -1;
var diagnostic_write_lock = std.atomic.Value(bool).init(false);
var diagnostic_sequence = std.atomic.Value(u32).init(0);
var copy_sequence = std.atomic.Value(u32).init(0);
var install_state = std.atomic.Value(u8).init(0);
var rust_probe_lock = std.atomic.Value(bool).init(false);
var rust_runtime_base = std.atomic.Value(usize).init(0);
var rust_probe_attempts = std.atomic.Value(u32).init(0);
var maps_storage: [256 * 1024]u8 = undefined;
threadlocal var inside_copy_hook = false;

fn prsCopySignature() []const u8 {
    return switch (builtin.cpu.arch) {
        .arm => &arm_prs_copy_signature,
        .aarch64 => &aarch64_prs_copy_signature,
        else => &.{},
    };
}

const JsonRange = struct {
    start: usize,
    end: usize,
};

const JsonKind = enum {
    object,
    array,
    string,
    scalar,
};

const ValueInfo = struct {
    range: JsonRange,
    kind: JsonKind,
    array_items: usize = 0,
    string_is_remote: bool = false,
    object_type_is_remote: bool = false,
};

const KeyKind = enum {
    other,
    intra_title_playlist,
    regolith_playlist,
    pause_ads,
    non_linear_ads,
    item_type,
    ad_delivery_session_id,
};

const EditKind = enum {
    pause_ads,
    non_linear_ads,
};

const MetadataEdit = struct {
    range: JsonRange,
    kind: EditKind,
};

const PlaylistCapture = struct {
    found: bool = false,
    complete: bool = false,
    array_start: usize = 0,
    array_end: usize = 0,
    item_count: usize = 0,
    remote_count: usize = 0,
    starts: [max_playlist_items]usize = undefined,
    ends: [max_playlist_items]usize = undefined,
    remote: [max_playlist_items]bool = undefined,
};

const RegolithCapture = struct {
    found: bool = false,
    range: JsonRange = .{ .start = 0, .end = 0 },
    item_count: usize = 0,
};

const ParseContext = struct {
    scanner: *std.json.Scanner,
    diagnostics: *std.json.Diagnostics,
    edits: [max_metadata_edits]MetadataEdit = undefined,
    edit_count: usize = 0,
    playlist: PlaylistCapture = .{},
    regolith: RegolithCapture = .{},
    saw_intra_title_playlist: bool = false,
    saw_ad_delivery_session_id: bool = false,

    fn byteOffset(self: *const ParseContext) usize {
        return @intCast(self.diagnostics.getByteOffset());
    }

    fn addEdit(self: *ParseContext, kind: EditKind, range: JsonRange) !void {
        if (self.edit_count == self.edits.len) return error.TooManyMetadataEdits;
        self.edits[self.edit_count] = .{ .kind = kind, .range = range };
        self.edit_count += 1;
    }
};

const Analysis = struct {
    edits: [max_metadata_edits]MetadataEdit = undefined,
    edit_count: usize = 0,
    playlist: PlaylistCapture = .{},
    regolith: RegolithCapture = .{},
    saw_intra_title_playlist: bool = false,
    saw_ad_delivery_session_id: bool = false,
};

const key_names = [_][]const u8{
    "intraTitlePlaylist",
    "playlist",
    "pauseAdsResolution",
    "nonLinearAds",
    "type",
    "adDeliverySessionId",
};

fn updateStringMatches(
    fragment: []const u8,
    expected: []const []const u8,
    candidates: []bool,
    offset: usize,
) void {
    for (expected, candidates) |text, *candidate| {
        if (!candidate.* or
            offset + fragment.len > text.len or
            !std.mem.eql(u8, fragment, text[offset .. offset + fragment.len]))
        {
            candidate.* = false;
        }
    }
}

fn consumeStringMatching(
    scanner: *std.json.Scanner,
    expected: []const []const u8,
) !?usize {
    var candidates = [_]bool{true} ** key_names.len;
    if (expected.len > candidates.len) return error.TooManyStringCandidates;
    var offset: usize = 0;

    while (true) {
        const token = try scanner.next();
        const final = switch (token) {
            .string => |fragment| blk: {
                updateStringMatches(fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk true;
            },
            .partial_string => |fragment| blk: {
                updateStringMatches(fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk false;
            },
            .partial_string_escaped_1 => |fragment| blk: {
                updateStringMatches(&fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk false;
            },
            .partial_string_escaped_2 => |fragment| blk: {
                updateStringMatches(&fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk false;
            },
            .partial_string_escaped_3 => |fragment| blk: {
                updateStringMatches(&fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk false;
            },
            .partial_string_escaped_4 => |fragment| blk: {
                updateStringMatches(&fragment, expected, candidates[0..expected.len], offset);
                offset += fragment.len;
                break :blk false;
            },
            else => return error.ExpectedString,
        };
        if (!final) continue;

        for (expected, candidates[0..expected.len], 0..) |text, candidate, index| {
            if (candidate and offset == text.len) return index;
        }
        return null;
    }
}

fn consumeKey(scanner: *std.json.Scanner) !KeyKind {
    const match = try consumeStringMatching(scanner, &key_names) orelse return .other;
    return switch (match) {
        0 => .intra_title_playlist,
        1 => .regolith_playlist,
        2 => .pause_ads,
        3 => .non_linear_ads,
        4 => .item_type,
        5 => .ad_delivery_session_id,
        else => unreachable,
    };
}

fn consumeRemoteString(scanner: *std.json.Scanner) !bool {
    const remote = [_][]const u8{"Remote"};
    return (try consumeStringMatching(scanner, &remote)) != null;
}

fn consumeNumber(scanner: *std.json.Scanner) !void {
    while (true) {
        switch (try scanner.next()) {
            .partial_number => continue,
            .number => return,
            else => return error.ExpectedNumber,
        }
    }
}

fn parseValue(
    context: *ParseContext,
    depth: usize,
    collect: bool,
    capture_playlist_items: bool,
) anyerror!ValueInfo {
    if (depth >= max_json_depth) return error.JsonTooDeep;

    const token_type = try context.scanner.peekNextTokenType();
    const start = context.byteOffset();
    return switch (token_type) {
        .object_begin => parseObject(context, depth, collect, start),
        .array_begin => parseArray(
            context,
            depth,
            collect,
            capture_playlist_items,
            start,
        ),
        .string => blk: {
            const is_remote = try consumeRemoteString(context.scanner);
            break :blk .{
                .range = .{ .start = start, .end = context.byteOffset() },
                .kind = .string,
                .string_is_remote = is_remote,
            };
        },
        .number => blk: {
            try consumeNumber(context.scanner);
            break :blk .{
                .range = .{ .start = start, .end = context.byteOffset() },
                .kind = .scalar,
            };
        },
        .true, .false, .null => blk: {
            _ = try context.scanner.next();
            break :blk .{
                .range = .{ .start = start, .end = context.byteOffset() },
                .kind = .scalar,
            };
        },
        .object_end, .array_end, .end_of_document => error.ExpectedValue,
    };
}

fn parseObject(
    context: *ParseContext,
    depth: usize,
    collect: bool,
    start: usize,
) anyerror!ValueInfo {
    if (try context.scanner.next() != .object_begin) return error.ExpectedObject;
    var direct_type_is_remote = false;

    while (true) {
        if (try context.scanner.peekNextTokenType() == .object_end) {
            _ = try context.scanner.next();
            return .{
                .range = .{ .start = start, .end = context.byteOffset() },
                .kind = .object,
                .object_type_is_remote = direct_type_is_remote,
            };
        }

        const key = try consumeKey(context.scanner);
        const value_type = try context.scanner.peekNextTokenType();
        if (collect) {
            switch (key) {
                .intra_title_playlist => context.saw_intra_title_playlist = true,
                .ad_delivery_session_id => context.saw_ad_delivery_session_id = true,
                else => {},
            }
        }
        const pause_target = collect and key == .pause_ads and value_type == .object_begin;
        const non_linear_target =
            collect and key == .non_linear_ads and value_type == .array_begin;
        const playlist_target =
            collect and
            key == .intra_title_playlist and
            value_type == .array_begin and
            !context.playlist.found;
        const regolith_target =
            collect and
            key == .regolith_playlist and
            value_type == .array_begin and
            !context.regolith.found;

        const value = try parseValue(
            context,
            depth + 1,
            collect and !pause_target and !non_linear_target,
            playlist_target,
        );

        if (collect and key == .item_type and value.string_is_remote) {
            direct_type_is_remote = true;
        }
        if (pause_target) {
            try context.addEdit(.pause_ads, value.range);
        } else if (non_linear_target and value.array_items > 0) {
            try context.addEdit(.non_linear_ads, value.range);
        } else if (regolith_target) {
            context.regolith = .{
                .found = true,
                .range = value.range,
                .item_count = value.array_items,
            };
        }
    }
}

fn parseArray(
    context: *ParseContext,
    depth: usize,
    collect: bool,
    capture_items: bool,
    start: usize,
) anyerror!ValueInfo {
    if (try context.scanner.next() != .array_begin) return error.ExpectedArray;
    if (capture_items) {
        context.playlist.found = true;
        context.playlist.array_start = start;
    }
    var item_count: usize = 0;

    while (true) {
        if (try context.scanner.peekNextTokenType() == .array_end) {
            const array_end = context.byteOffset();
            _ = try context.scanner.next();
            if (capture_items) {
                context.playlist.complete = true;
                context.playlist.array_end = array_end;
            }
            return .{
                .range = .{ .start = start, .end = context.byteOffset() },
                .kind = .array,
                .array_items = item_count,
            };
        }

        const item = try parseValue(context, depth + 1, collect, false);
        if (capture_items) {
            if (context.playlist.item_count == max_playlist_items) {
                return error.TooManyPlaylistItems;
            }
            const index = context.playlist.item_count;
            context.playlist.starts[index] = item.range.start;
            context.playlist.ends[index] = item.range.end;
            context.playlist.remote[index] = item.object_type_is_remote;
            context.playlist.item_count += 1;
            if (item.object_type_is_remote) context.playlist.remote_count += 1;
        }
        item_count += 1;
    }
}

/// Returns the error rather than null so callers can report which limit or
/// syntax problem rejected the body. Every bail here silently disables the whole
/// PRS strip, so the reason needs to be visible.
fn analyzeJson(buffer: []const u8) anyerror!Analysis {
    var nesting_storage: [json_stack_storage_bytes]u8 = undefined;
    var fixed_allocator = std.heap.FixedBufferAllocator.init(&nesting_storage);
    var scanner = std.json.Scanner.initCompleteInput(fixed_allocator.allocator(), buffer);
    defer scanner.deinit();
    try scanner.ensureTotalStackCapacity(max_json_depth);

    var diagnostics = std.json.Diagnostics{};
    scanner.enableDiagnostics(&diagnostics);
    var context = ParseContext{
        .scanner = &scanner,
        .diagnostics = &diagnostics,
    };
    _ = try parseValue(&context, 0, true, false);
    if (try scanner.next() != .end_of_document) return error.TrailingBytesAfterJson;

    return .{
        .edits = context.edits,
        .edit_count = context.edit_count,
        .playlist = context.playlist,
        .regolith = context.regolith,
        .saw_intra_title_playlist = context.saw_intra_title_playlist,
        .saw_ad_delivery_session_id = context.saw_ad_delivery_session_id,
    };
}

/// Overwrites `range` with `replacement`, space-padding the remainder so the
/// buffer keeps its original length. Returns false without writing anything when
/// the replacement is longer than the range: these buffers belong to the app, so
/// a replacement that does not fit must be skipped rather than allowed to run
/// past the value it is replacing.
fn replaceRange(buffer: []u8, range: JsonRange, replacement: []const u8) bool {
    if (range.end < range.start or range.end - range.start < replacement.len) return false;
    @memcpy(buffer[range.start .. range.start + replacement.len], replacement);
    @memset(buffer[range.start + replacement.len .. range.end], ' ');
    return true;
}

fn filterPrs(buffer: []u8) FilterResult {
    var result = FilterResult{};
    if (buffer.len == 0) return result;
    const analysis = analyzeJson(buffer) catch |err| {
        result.parse_error = err;
        return result;
    };

    for (analysis.edits[0..analysis.edit_count]) |edit| {
        switch (edit.kind) {
            // An empty object, not null: the runtime reads properties off this
            // value, so keeping its type means those reads yield undefined
            // instead of throwing on a null dereference. "{}" also always fits,
            // since the shortest object it can replace is "{}" itself.
            .pause_ads => {
                if (replaceRange(buffer, edit.range, "{}")) {
                    result.pause_ads += 1;
                    result.modified = true;
                }
            },
            .non_linear_ads => {
                if (replaceRange(buffer, edit.range, "[]")) {
                    result.non_linear_ads += 1;
                    result.modified = true;
                }
            },
        }
    }

    const playlist = analysis.playlist;
    result.found_playlist = playlist.found;
    result.complete = playlist.complete;
    result.total_items = @intCast(playlist.item_count);
    result.remote_items = @intCast(playlist.remote_count);

    // The Remote-item strip that used to live here is deliberately gone. Remote
    // entries in intraTitlePlaylist are the ad-break SKELETON, not playable ad
    // content (the media comes from the regolith response). The app indexes off
    // them - translateAdBreakIndexToIntraTitlePlaylist, translateToRelativeAdBreakIndex,
    // hasRemoteItemBefore, hasPrerollAdBreak, and a +0/+1 offset - and
    // createAdPreloadMonitorIfTrailedByRemoteItem throws outright when the index
    // no longer resolves. Deleting them left an item with a null end, which made
    // the position translator return Infinity, which the app clamps to 0: the
    // playback loop. Ads are removed in filterRegolith instead, which leaves the
    // skeleton intact so every index translation still resolves.
    return result;
}

const RegolithOutcome = enum {
    /// The playlist array was emptied.
    emptied,
    /// No ad-decision response here. By far the common case, never logged.
    not_candidate,
    /// The PRS body, which filterPrs owns.
    prs_body,
    /// Outside the size window this filter inspects.
    length_rejected,
    /// A session-bearing candidate has no syntactically valid playlist array.
    playlist_missing,
    /// The playlist array does not close inside this buffer.
    truncated,
    /// A repeat copy of a response already emptied.
    already_empty,
};

const RegolithResult = struct {
    outcome: RegolithOutcome = .not_candidate,
    item_count: u32 = 0,

    /// A buffer that looked like an ad-decision response but was left untouched.
    /// This is what a silently dead filter looks like from the outside, so these
    /// are the outcomes worth a log line.
    fn isNearMiss(self: RegolithResult) bool {
        return switch (self.outcome) {
            .playlist_missing, .truncated => true,
            else => false,
        };
    }
};

const regolith_playlist_marker = "\"playlist\":[";
const regolith_playlist_key = "\"playlist\"";
const regolith_session_marker = "\"adDeliverySessionId\"";
const regolith_measurement_marker = "\"measurement\"";
const prs_playlist_marker = "\"intraTitlePlaylist\"";
const adbreak_period_marker = "Adbreak0_Ad";
const online_fulfilment_definition = ".prototype.reportAssetFulfilment";
const online_fulfilment_fallback = "reportAssetFulfilment = freeOnUnref(function";
const expl_preroll_definition = ".prototype.createPrerollPeriods";
const expl_preroll_fallback = "createPrerollPeriods = freeOnUnref(function";

const MarkerBits = struct {
    const session: u32 = 1 << 0;
    const intra_title: u32 = 1 << 1;
    const measurement: u32 = 1 << 2;
    const playlist_key: u32 = 1 << 3;
    const playlist_exact: u32 = 1 << 4;
    const playlist_open: u32 = 1 << 5;
    const playlist_close: u32 = 1 << 6;
    const bundle_online: u32 = 1 << 7;
    const bundle_expl: u32 = 1 << 8;
    const adbreak_period: u32 = 1 << 9;
};

const MarkerScan = struct {
    bits: u32 = 0,
    session_offset: ?usize = null,
    playlist_key_offset: ?usize = null,
    playlist_open: ?usize = null,
    playlist_close: ?usize = null,
};

fn skipJsonWhitespace(buffer: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < buffer.len) : (cursor += 1) {
        switch (buffer[cursor]) {
            ' ', '\t', '\r', '\n' => {},
            else => return cursor,
        }
    }
    return cursor;
}

fn findPlaylistArray(buffer: []const u8) struct { key: usize, open: usize } {
    var cursor: usize = 0;
    while (std.mem.findPos(u8, buffer, cursor, regolith_playlist_key)) |key| {
        var after = skipJsonWhitespace(buffer, key + regolith_playlist_key.len);
        if (after < buffer.len and buffer[after] == ':') {
            after = skipJsonWhitespace(buffer, after + 1);
            if (after < buffer.len and buffer[after] == '[') {
                return .{ .key = key, .open = after };
            }
        }
        cursor = key + regolith_playlist_key.len;
    }
    return .{ .key = std.math.maxInt(usize), .open = std.math.maxInt(usize) };
}

fn scanMarkers(buffer: []const u8) MarkerScan {
    var scan = MarkerScan{};
    if (std.mem.indexOf(u8, buffer, regolith_session_marker)) |offset| {
        scan.bits |= MarkerBits.session;
        scan.session_offset = offset;
    }
    if (std.mem.indexOf(u8, buffer, prs_playlist_marker) != null)
        scan.bits |= MarkerBits.intra_title;
    if (std.mem.indexOf(u8, buffer, regolith_measurement_marker) != null)
        scan.bits |= MarkerBits.measurement;
    if (std.mem.indexOf(u8, buffer, regolith_playlist_marker) != null)
        scan.bits |= MarkerBits.playlist_exact;
    if (std.mem.indexOf(u8, buffer, adbreak_period_marker) != null)
        scan.bits |= MarkerBits.adbreak_period;
    if (std.mem.indexOf(u8, buffer, online_fulfilment_definition) != null)
        scan.bits |= MarkerBits.bundle_online;
    if (std.mem.indexOf(u8, buffer, expl_preroll_definition) != null)
        scan.bits |= MarkerBits.bundle_expl;

    const playlist = findPlaylistArray(buffer);
    if (playlist.key != std.math.maxInt(usize)) {
        scan.bits |= MarkerBits.playlist_key | MarkerBits.playlist_open;
        scan.playlist_key_offset = playlist.key;
        scan.playlist_open = playlist.open;
        if (matchingBracket(buffer, playlist.open)) |closing_offset| {
            scan.bits |= MarkerBits.playlist_close;
            scan.playlist_close = closing_offset;
        }
    } else if (std.mem.indexOf(u8, buffer, regolith_playlist_key)) |key| {
        scan.bits |= MarkerBits.playlist_key;
        scan.playlist_key_offset = key;
    }
    return scan;
}

/// Index of the bracket closing the one that opens at `open`, or null when the
/// value is truncated within this buffer. String- and escape-aware, so brackets
/// inside JSON string literals do not affect nesting.
fn matchingBracket(buffer: []const u8, opening_offset: usize) ?usize {
    if (opening_offset >= buffer.len or
        (buffer[opening_offset] != '[' and buffer[opening_offset] != '{')) return null;

    var stack: [max_json_depth]u8 = undefined;
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (buffer[opening_offset..], opening_offset..) |byte, index| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else switch (byte) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (byte) {
            '"' => in_string = true,
            '[', '{' => {
                if (depth == stack.len) return null;
                stack[depth] = byte;
                depth += 1;
            },
            ']', '}' => {
                if (depth == 0) return null;
                const expected: u8 = if (stack[depth - 1] == '[') ']' else '}';
                if (byte != expected) return null;
                depth -= 1;
                if (depth == 0) return index;
            },
            else => {},
        }
    }
    return null;
}

/// Number of top-level elements in the array whose interior spans
/// `buffer[open + 1 .. close]`. Counts depth-1 commas, so nested arrays and
/// objects inside an element do not inflate the total.
fn countArrayItems(buffer: []const u8, opening_offset: usize, closing_offset: usize) u32 {
    if (std.mem.indexOfNone(u8, buffer[opening_offset + 1 .. closing_offset], " \t\r\n") == null) return 0;
    var count: u32 = 1;
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (buffer[opening_offset..closing_offset]) |byte| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else switch (byte) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (byte) {
            '"' => in_string = true,
            '[', '{' => depth += 1,
            ']', '}' => depth -= 1,
            ',' => if (depth == 1) {
                count += 1;
            },
            else => {},
        }
    }
    return count;
}

/// Empties the `playlist` array of a regolith `getVideoAds` response so the app
/// takes its own designed empty-ad-break path: no ad periods are inserted and
/// the playlist index it unblocks afterwards is still the correct one, which
/// keeps the content timeline intact.
///
/// This deliberately does NOT require the whole buffer to be one valid JSON
/// document. These buffers are `memcpy` destinations, so the response is
/// routinely followed by padding or stale bytes; demanding a clean
/// end-of-document made this filter silently never fire on device. Only the
/// array interior is blanked, in place and at the same length, and only once a
/// matching `]` proves the array is complete in this buffer.
fn filterRegolith(buffer: []u8) RegolithResult {
    if (buffer.len < min_regolith_length or buffer.len > max_prs_length) {
        return .{ .outcome = .length_rejected };
    }

    const markers = scanMarkers(buffer);
    if (markers.bits & MarkerBits.session == 0) {
        return .{ .outcome = .not_candidate };
    }
    if (markers.bits & MarkerBits.intra_title != 0) {
        return .{ .outcome = .prs_body };
    }

    // The decompression-chunk heuristic is NOT applied here. Measured on device
    // 2026-08-08: real ad-decision responses are 11.6-15 KB and land in 4096 and
    // 16384 byte buffers, so this guard was discarding them - a chunk_skipped at
    // 16384 landed 0.75s before an ad break played. The guard exists to avoid
    // editing zlib's CRC-checked scratch buffers; that risk is already covered
    // here by requiring three independent markers plus a balanced bracket before
    // any write, which no compressed chunk satisfies. (filterPrs never had this
    // guard; it relies on the signature-matched caller filter instead.)

    // The player accepts legal JSON whitespace and does not require measurement.
    // Locate `playlist` structurally instead of requiring the minified spelling
    // `"playlist":[`. This also records the exact-vs-flexible distinction in the
    // diagnostics without making it an enforcement gate.
    const opening_offset = markers.playlist_open orelse {
        return .{ .outcome = .playlist_missing };
    };
    const closing_offset = markers.playlist_close orelse {
        return .{ .outcome = .truncated };
    };

    const interior = buffer[opening_offset + 1 .. closing_offset];
    if (interior.len == 0 or
        std.mem.indexOfNone(u8, interior, " \t\r\n") == null)
    {
        return .{ .outcome = .already_empty };
    }

    // The same response can pass through the copy seam more than once; treat an
    // already-blanked array as done so repeat copies stay writes-free.
    const items = countArrayItems(buffer, opening_offset, closing_offset);
    @memset(interior, ' ');
    return .{ .outcome = .emptied, .item_count = items };
}

const SourcePatchOutcome = enum {
    not_present,
    patched,
    ambiguous,
    structure_changed,
    replacement_too_long,
};

const BundlePatchResult = struct {
    candidate: bool = false,
    online: SourcePatchOutcome = .not_present,
    expl: SourcePatchOutcome = .not_present,

    fn modified(self: BundlePatchResult) bool {
        return self.online == .patched or self.expl == .patched;
    }
};

fn identifierStart(buffer: []const u8, end: usize) usize {
    var cursor = end;
    while (cursor > 0) {
        const byte = buffer[cursor - 1];
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '$') break;
        cursor -= 1;
    }
    return cursor;
}

fn identifierEnd(buffer: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < buffer.len) : (cursor += 1) {
        const byte = buffer[cursor];
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '$') break;
    }
    return cursor;
}

fn uniqueOffset(buffer: []const u8, needle: []const u8) ?usize {
    const first = std.mem.indexOf(u8, buffer, needle) orelse return null;
    const rest = first + needle.len;
    if (rest < buffer.len and std.mem.indexOf(u8, buffer[rest..], needle) != null) return null;
    return first;
}

/// Locate a local assigned from `<response>.playlist`, then find a later loop
/// comparison against that local's `.length`. Replacing the whole comparison
/// with `<local>.length=0` empties the original array and evaluates false. The
/// transformation is independent of minified local-variable names and keeps the
/// source buffer exactly the same size.
fn patchPlaylistLoop(
    buffer: []u8,
    definition_marker: []const u8,
    maximum_span: usize,
) SourcePatchOutcome {
    const definition = uniqueOffset(buffer, definition_marker) orelse {
        return if (std.mem.indexOf(u8, buffer, definition_marker) == null)
            .not_present
        else
            .ambiguous;
    };
    const window_end = @min(buffer.len, definition + maximum_span);
    const window = buffer[definition..window_end];
    const playlist_relative = std.mem.indexOf(u8, window, ".playlist") orelse
        return .structure_changed;
    const playlist = definition + playlist_relative;

    var equals = playlist;
    while (equals > definition and buffer[equals - 1] != '=') : (equals -= 1) {}
    if (equals == definition) return .structure_changed;
    equals -= 1;

    var lhs_end = equals;
    while (lhs_end > definition and std.ascii.isWhitespace(buffer[lhs_end - 1])) lhs_end -= 1;
    const lhs_start = identifierStart(buffer, lhs_end);
    if (lhs_start == lhs_end) return .structure_changed;
    const local = buffer[lhs_start..lhs_end];

    var length_needle_storage: [128]u8 = undefined;
    const length_needle = std.fmt.bufPrint(
        &length_needle_storage,
        "{s}.length",
        .{local},
    ) catch return .structure_changed;

    var search = playlist + ".playlist".len;
    while (search < window_end) {
        const relative = std.mem.indexOf(u8, buffer[search..window_end], length_needle) orelse
            return .structure_changed;
        const length_start = search + relative;
        var less = length_start;
        while (less > definition and std.ascii.isWhitespace(buffer[less - 1])) less -= 1;
        if (less == definition or buffer[less - 1] != '<') {
            search = length_start + length_needle.len;
            continue;
        }
        less -= 1;
        var counter_end = less;
        while (counter_end > definition and std.ascii.isWhitespace(buffer[counter_end - 1]))
            counter_end -= 1;
        const counter_start = identifierStart(buffer, counter_end);
        if (counter_start == counter_end) {
            search = length_start + length_needle.len;
            continue;
        }

        const original = JsonRange{
            .start = counter_start,
            .end = length_start + length_needle.len,
        };
        var replacement_storage: [128]u8 = undefined;
        const replacement = std.fmt.bufPrint(
            &replacement_storage,
            "{s}.length=0",
            .{local},
        ) catch return .structure_changed;
        if (replacement.len > original.end - original.start) return .replacement_too_long;
        return if (replaceRange(buffer, original, replacement)) .patched else .structure_changed;
    }
    return .structure_changed;
}

fn patchPlayerBundle(buffer: []u8) BundlePatchResult {
    var result = BundlePatchResult{};
    if (buffer.len < min_bundle_length or buffer.len > max_bundle_length) return result;

    const has_online = std.mem.indexOf(u8, buffer, online_fulfilment_definition) != null;
    const has_expl = std.mem.indexOf(u8, buffer, expl_preroll_definition) != null;
    result.candidate = has_online or has_expl or
        std.mem.indexOf(u8, buffer, online_fulfilment_fallback) != null or
        std.mem.indexOf(u8, buffer, expl_preroll_fallback) != null;
    if (!result.candidate) return result;

    result.online = patchPlaylistLoop(buffer, online_fulfilment_definition, 8192);
    if (result.online == .not_present)
        result.online = patchPlaylistLoop(buffer, online_fulfilment_fallback, 8192);
    result.expl = patchPlaylistLoop(buffer, expl_preroll_definition, 16384);
    if (result.expl == .not_present)
        result.expl = patchPlaylistLoop(buffer, expl_preroll_fallback, 16384);
    return result;
}

fn lockDiagnosticWriter() void {
    while (diagnostic_write_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
}

fn unlockDiagnosticWriter() void {
    diagnostic_write_lock.store(false, .release);
}

fn writeAll(fd: c_int, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (written <= 0) return;
        offset += @intCast(written);
    }
}

fn openDiagnosticFile(package_name: []const u8, file_name: []const u8) c_int {
    var path_storage: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(
        &path_storage,
        "/data/user/0/{s}/files/{s}",
        .{ package_name, file_name },
    ) catch return -1;
    return open(
        path.ptr,
        o_write_only | o_create | o_append | o_close_on_exec,
        @as(c_uint, private_file_mode),
    );
}

fn initPersistentLogging() void {
    var package_storage: [256]u8 = undefined;
    var package_name: []const u8 = "com.amazon.amazonvideo.livingroom.dev";
    const cmdline_fd = open(proc_self_cmdline, o_read_only | o_close_on_exec);
    if (cmdline_fd >= 0) {
        const count = read(cmdline_fd, &package_storage, package_storage.len - 1);
        _ = close(cmdline_fd);
        if (count > 0) {
            var length: usize = @intCast(count);
            if (std.mem.indexOfScalar(u8, package_storage[0..length], 0)) |nul| {
                length = nul;
            }
            if (std.mem.indexOfScalar(u8, package_storage[0..length], ':')) |colon| {
                length = colon;
            }
            if (length > 0) package_name = package_storage[0..length];
        }
    }

    diagnostic_fd = openDiagnosticFile(package_name, diagnostic_log_name);
    diagnostic_raw_fd = openDiagnosticFile(package_name, diagnostic_raw_name);
}

fn appendPersistentLine(text: []const u8) void {
    if (diagnostic_fd < 0) return;
    lockDiagnosticWriter();
    defer unlockDiagnosticWriter();
    writeAll(diagnostic_fd, text);
    writeAll(diagnostic_fd, "\n");
}

fn logMessage(priority: c_int, comptime format: []const u8, arguments: anytype) void {
    var storage: [1024]u8 = undefined;
    const sequence = diagnostic_sequence.fetchAdd(1, .monotonic) + 1;
    const text = std.fmt.bufPrintZ(
        &storage,
        "seq={d} tid={d} " ++ format,
        .{ sequence, gettid() } ++ arguments,
    ) catch return;
    _ = __android_log_write(priority, log_tag, text.ptr);
    appendPersistentLine(text[0..text.len]);
}

fn hashBytes(bytes: []const u8) u64 {
    var hash: u64 = 14695981039346656037;
    for (bytes) |byte| {
        hash = (hash ^ byte) *% 1099511628211;
    }
    return hash;
}

fn dumpCandidateBuffer(
    candidate_copy_sequence: u32,
    kind: []const u8,
    caller: usize,
    source: ?*const anyopaque,
    destination: ?*anyopaque,
    bytes: []const u8,
    marker_bits: u32,
) void {
    if (diagnostic_raw_fd < 0) return;
    var header_storage: [512]u8 = undefined;
    const header = std.fmt.bufPrint(
        &header_storage,
        "\nPVHOOK_RAW_BEGIN copy_seq={d} tid={d} kind={s} caller=0x{x} src=0x{x} dst=0x{x} length={d} markers=0x{x} hash=0x{x}\n",
        .{
            candidate_copy_sequence,
            gettid(),
            kind,
            caller,
            if (source) |pointer| @intFromPtr(pointer) else 0,
            if (destination) |pointer| @intFromPtr(pointer) else 0,
            bytes.len,
            marker_bits,
            hashBytes(bytes),
        },
    ) catch return;
    lockDiagnosticWriter();
    defer unlockDiagnosticWriter();
    writeAll(diagnostic_raw_fd, header);
    writeAll(diagnostic_raw_fd, bytes);
    writeAll(diagnostic_raw_fd, "\nPVHOOK_RAW_END\n");
}

const rust_content_type_signature = [_]u8{
    0xf0, 0xb5, 0x89, 0xb0, 0x04, 0x46, 0x06, 0xa8, 0x0d, 0x46,
};
const rust_content_type_offset = 0x123bd90;

/// Telemetry only. The Rust player is an anonymously mapped ELF, so it cannot
/// be found by the existing named-module lookup. This scans readable executable
/// mappings for the IDA-verified ContentType parser prologue and publishes the
/// inferred load base. It deliberately does not modify Rust code.
fn probeRustRuntime() void {
    if (rust_runtime_base.load(.acquire) != 0) return;
    const attempt = rust_probe_attempts.fetchAdd(1, .monotonic) + 1;
    if (attempt > 32 and (attempt & (attempt - 1)) != 0) return;
    if (rust_probe_lock.cmpxchgStrong(false, true, .acquire, .monotonic) != null) return;
    defer rust_probe_lock.store(false, .release);
    if (rust_runtime_base.load(.acquire) != 0) return;

    const maps_fd = open(proc_self_maps, o_read_only | o_close_on_exec);
    if (maps_fd < 0) {
        logMessage(android_log_error, "RUST_PROBE attempt={d} maps_open_failed=1", .{attempt});
        return;
    }
    defer _ = close(maps_fd);
    var used: usize = 0;
    while (used < maps_storage.len) {
        const count = read(maps_fd, maps_storage[used..].ptr, maps_storage.len - used);
        if (count <= 0) break;
        used += @intCast(count);
    }

    var matches: u32 = 0;
    var first_base: usize = 0;
    var cursor: usize = 0;
    while (cursor < used) {
        const relative_end = std.mem.indexOfScalar(u8, maps_storage[cursor..used], '\n') orelse
            used - cursor;
        const line = maps_storage[cursor .. cursor + relative_end];
        cursor += relative_end + @intFromBool(cursor + relative_end < used);

        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const after_dash = dash + 1;
        const end_space_relative = std.mem.indexOfScalar(u8, line[after_dash..], ' ') orelse continue;
        const end_space = after_dash + end_space_relative;
        const permissions_start = skipJsonWhitespace(line, end_space);
        if (permissions_start + 3 > line.len or
            !std.mem.eql(u8, line[permissions_start .. permissions_start + 3], "r-x"))
        {
            continue;
        }
        const start_address = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const end_address = std.fmt.parseInt(usize, line[after_dash..end_space], 16) catch continue;
        if (end_address <= start_address) continue;
        const mapping_length = end_address - start_address;
        if (mapping_length < 1024 * 1024 or mapping_length > 64 * 1024 * 1024) continue;

        const mapping_pointer: [*]const u8 = @ptrFromInt(start_address);
        const mapping = mapping_pointer[0..mapping_length];
        var match_cursor: usize = 0;
        while (std.mem.findPos(u8, mapping, match_cursor, &rust_content_type_signature)) |match| {
            const match_address = start_address + match;
            if (match_address >= rust_content_type_offset) {
                matches += 1;
                if (matches == 1) first_base = match_address - rust_content_type_offset;
                logMessage(
                    android_log_info,
                    "RUST_PROBE_MATCH attempt={d} match=0x{x} inferred_base=0x{x} map_start=0x{x} map_end=0x{x}",
                    .{ attempt, match_address, match_address - rust_content_type_offset, start_address, end_address },
                );
            }
            match_cursor = match + 1;
        }
    }

    if (matches == 1) rust_runtime_base.store(first_base, .release);
    logMessage(
        if (matches == 1) android_log_info else android_log_error,
        "RUST_PROBE_DONE attempt={d} matches={d} inferred_base=0x{x} maps_bytes={d} maps_truncated={d}",
        .{ attempt, matches, if (matches == 1) first_base else 0, used, @intFromBool(used == maps_storage.len) },
    );
}

fn dynamicPointer(base: usize, value: usize) usize {
    if (value == 0) return 0;
    const address: usize = value;
    return if (address >= base) address else base + address;
}

fn libraryNameMatches(name: ?[*:0]const u8, expected: []const u8) bool {
    const path = name orelse return false;
    return std.mem.indexOf(u8, std.mem.span(path), expected) != null;
}

const SignatureSearch = struct {
    library_name: []const u8,
    base: usize = 0,
    address: usize = 0,
    matches: usize = 0,
};

fn findSignatureCallback(
    info: *const DlPhdrInfo,
    _: usize,
    context: ?*anyopaque,
) callconv(.c) c_int {
    const search: *SignatureSearch = @ptrCast(@alignCast(context orelse return 0));
    if (!libraryNameMatches(info.dlpi_name, search.library_name)) return 0;

    const signature = prsCopySignature();
    if (signature.len == 0) return 1;
    search.base = info.dlpi_addr;
    for (0..info.dlpi_phnum) |index| {
        const header = info.dlpi_phdr[index];
        if (header.type != .LOAD or !header.flags.X or header.filesz < signature.len) {
            continue;
        }

        const segment_address = info.dlpi_addr + header.vaddr;
        const segment_pointer: [*]const u8 = @ptrFromInt(segment_address);
        const segment = segment_pointer[0..header.filesz];
        var cursor: usize = 0;
        while (std.mem.findPos(u8, segment, cursor, signature)) |match| {
            search.matches += 1;
            if (search.matches == 1) search.address = segment_address + match;
            cursor = match + 1;
        }
    }
    return 1;
}

fn findSignature(library_name: []const u8) SignatureSearch {
    var search = SignatureSearch{ .library_name = library_name };
    _ = dl_iterate_phdr(findSignatureCallback, &search);
    return search;
}

const ImportSearch = struct {
    library_name: []const u8,
    symbol_name: []const u8,
    slot: ?**anyopaque = null,
};

fn findRelocationSlot(
    comptime Relocation: type,
    base: usize,
    relocation_address: usize,
    relocations_size: usize,
    symbol_table: [*]const std.elf.ElfN.Sym,
    string_table: [*]const u8,
    symbol_name: []const u8,
    relocation_type: u32,
) ?**anyopaque {
    const relocations: [*]const Relocation = @ptrFromInt(relocation_address);
    for (0..relocations_size / @sizeOf(Relocation)) |index| {
        const relocation = relocations[index];
        if (@as(u32, @intCast(relocation.info.type)) != relocation_type) continue;
        const symbol_index: usize = @intCast(relocation.info.sym);
        const name: [*:0]const u8 =
            @ptrCast(string_table + symbol_table[symbol_index].name);
        if (!std.mem.eql(u8, std.mem.span(name), symbol_name)) continue;
        return @ptrFromInt(base + relocation.offset);
    }
    return null;
}

fn findImportCallback(
    info: *const DlPhdrInfo,
    _: usize,
    context: ?*anyopaque,
) callconv(.c) c_int {
    const search: *ImportSearch = @ptrCast(@alignCast(context orelse return 0));
    if (!libraryNameMatches(info.dlpi_name, search.library_name)) return 0;

    const base = info.dlpi_addr;
    var dynamic: ?[*]const std.elf.Dyn = null;
    for (0..info.dlpi_phnum) |index| {
        const header = info.dlpi_phdr[index];
        if (header.type == .DYNAMIC) {
            dynamic = @ptrFromInt(base + header.vaddr);
            break;
        }
    }
    var entry = dynamic orelse return 1;
    var symbols: ?[*]const std.elf.ElfN.Sym = null;
    var strings: ?[*]const u8 = null;
    var relocation_address: usize = 0;
    var relocations_size: usize = 0;
    var relocation_format: usize = 0;

    while (entry[0].d_tag != std.elf.DT_NULL) : (entry += 1) {
        switch (entry[0].d_tag) {
            std.elf.DT_SYMTAB => symbols =
                @ptrFromInt(dynamicPointer(base, @intCast(entry[0].d_val))),
            std.elf.DT_STRTAB => strings =
                @ptrFromInt(dynamicPointer(base, @intCast(entry[0].d_val))),
            std.elf.DT_JMPREL => relocation_address =
                dynamicPointer(base, @intCast(entry[0].d_val)),
            std.elf.DT_PLTRELSZ => relocations_size = entry[0].d_val,
            std.elf.DT_PLTREL => relocation_format = @intCast(entry[0].d_val),
            else => {},
        }
    }

    const symbol_table = symbols orelse return 1;
    const string_table = strings orelse return 1;
    if (relocation_address == 0 or relocations_size == 0) return 1;

    switch (builtin.cpu.arch) {
        .arm => {
            if (relocation_format != std.elf.DT_REL) return 1;
            search.slot = findRelocationSlot(
                std.elf.Elf32.Rel,
                base,
                relocation_address,
                relocations_size,
                symbol_table,
                string_table,
                search.symbol_name,
                r_arm_jump_slot,
            );
        },
        .aarch64 => {
            if (relocation_format != std.elf.DT_RELA) return 1;
            search.slot = findRelocationSlot(
                std.elf.Elf64.Rela,
                base,
                relocation_address,
                relocations_size,
                symbol_table,
                string_table,
                search.symbol_name,
                r_aarch64_jump_slot,
            );
        },
        else => {},
    }
    return 1;
}

fn hookImport(
    library_name: []const u8,
    symbol_name: []const u8,
    replacement: *const anyopaque,
    original: *?*anyopaque,
) bool {
    var search = ImportSearch{
        .library_name = library_name,
        .symbol_name = symbol_name,
    };
    _ = dl_iterate_phdr(findImportCallback, &search);
    const slot = search.slot orelse return false;

    const page_size_signed = sysconf(sc_pagesize);
    if (page_size_signed <= 0) return false;
    const page_size: usize = @intCast(page_size_signed);
    const page = @intFromPtr(slot) & ~(page_size - 1);
    if (mprotect(@ptrFromInt(page), page_size, prot_read | prot_write) != 0) return false;

    const previous = @atomicLoad(*anyopaque, slot, .acquire);
    if (previous == replacement) {
        return @atomicLoad(?*anyopaque, original, .acquire) != null;
    }
    @atomicStore(?*anyopaque, original, previous, .release);
    @atomicStore(*anyopaque, slot, @constCast(replacement), .release);
    return true;
}

fn loadOriginal(comptime Function: type, original: *const ?*anyopaque) ?Function {
    const pointer = @atomicLoad(?*anyopaque, original, .acquire) orelse return null;
    return @ptrCast(@alignCast(pointer));
}

const CopyKind = enum {
    memcpy,
    memmove,
    memcpy_chk,
    memmove_chk,
};

fn optionalOffset(value: ?usize) usize {
    return value orelse std.math.maxInt(usize);
}

fn normalizedCallerOffset(caller: usize) usize {
    return if (ignite_base != 0 and caller >= ignite_base) caller - ignite_base else caller;
}

fn inspectCopiedBuffer(
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
    destination_length: usize,
    caller: usize,
    kind: CopyKind,
) void {
    const pointer = destination orelse return;
    const copy_seq = copy_sequence.fetchAdd(1, .monotonic) + 1;
    if (length == 0) return;

    const authoritative_quickjs_copy =
        prs_copy_return_address != 0 and caller == prs_copy_return_address;
    const inspectable = length <= max_prs_length or
        (length >= min_bundle_length and length <= max_bundle_length) or
        (authoritative_quickjs_copy and length <= max_bundle_length);
    if (!inspectable) {
        if (copy_seq <= 64 or (copy_seq & 0xfff) == 0) {
            logMessage(
                android_log_info,
                "COPY_SAMPLE copy_seq={d} kind={s} caller=0x{x} length={d} dst_length={d} inspectable=0",
                .{ copy_seq, @tagName(kind), normalizedCallerOffset(caller), length, destination_length },
            );
        }
        return;
    }

    const bytes: [*]u8 = @ptrCast(pointer);
    const buffer = bytes[0..length];
    const markers = scanMarkers(buffer);
    const interesting = markers.bits != 0 or
        (authoritative_quickjs_copy and length >= max_prs_length);
    if (interesting) {
        logMessage(
            android_log_info,
            "COPY_CANDIDATE copy_seq={d} kind={s} caller=0x{x} src=0x{x} dst=0x{x} length={d} dst_length={d} markers=0x{x} session_off=0x{x} playlist_key_off=0x{x} open=0x{x} close=0x{x} hash=0x{x}",
            .{
                copy_seq,
                @tagName(kind),
                normalizedCallerOffset(caller),
                if (source) |address| @intFromPtr(address) else 0,
                @intFromPtr(pointer),
                length,
                destination_length,
                markers.bits,
                optionalOffset(markers.session_offset),
                optionalOffset(markers.playlist_key_offset),
                optionalOffset(markers.playlist_open),
                optionalOffset(markers.playlist_close),
                hashBytes(buffer),
            },
        );
        dumpCandidateBuffer(
            copy_seq,
            @tagName(kind),
            normalizedCallerOffset(caller),
            source,
            destination,
            buffer,
            markers.bits,
        );
        if (markers.bits & (MarkerBits.session |
            MarkerBits.bundle_online |
            MarkerBits.bundle_expl |
            MarkerBits.adbreak_period) != 0)
        {
            probeRustRuntime();
        }
    } else if (copy_seq <= 64 or (copy_seq & 0xfff) == 0) {
        logMessage(
            android_log_info,
            "COPY_SAMPLE copy_seq={d} kind={s} caller=0x{x} length={d} dst_length={d} inspectable=1 markers=0",
            .{ copy_seq, @tagName(kind), normalizedCallerOffset(caller), length, destination_length },
        );
    }

    const bundle = patchPlayerBundle(buffer);
    if (bundle.candidate) {
        logMessage(
            if (bundle.modified()) android_log_info else android_log_error,
            "PLAYER_BUNDLE candidate=1 writes={d} copy_seq={d} kind={s} caller=0x{x} length={d} online={s} expl={s} hash_after=0x{x}",
            .{
                @intFromBool(bundle.modified()),
                copy_seq,
                @tagName(kind),
                normalizedCallerOffset(caller),
                length,
                @tagName(bundle.online),
                @tagName(bundle.expl),
                hashBytes(buffer),
            },
        );
    } else if (authoritative_quickjs_copy and length >= max_prs_length) {
        logMessage(
            android_log_error,
            "PLAYER_BUNDLE candidate=0 writes=0 copy_seq={d} kind={s} caller=0x{x} length={d} reason=semantic_anchors_missing markers=0x{x} hash=0x{x}",
            .{
                copy_seq,
                @tagName(kind),
                normalizedCallerOffset(caller),
                length,
                markers.bits,
                hashBytes(buffer),
            },
        );
    }

    if (length < min_regolith_length or length > max_prs_length) return;
    const filtered = filterRegolith(buffer);
    if (filtered.outcome != .not_candidate and filtered.outcome != .length_rejected) {
        logMessage(
            if (filtered.outcome == .emptied or filtered.outcome == .already_empty)
                android_log_info
            else
                android_log_error,
            "REGOLITH_RESULT copy_seq={d} outcome={s} writes={d} length={d} items={d} markers=0x{x} caller=0x{x} hash_after=0x{x}",
            .{
                copy_seq,
                @tagName(filtered.outcome),
                @intFromBool(filtered.outcome == .emptied),
                length,
                filtered.item_count,
                markers.bits,
                normalizedCallerOffset(caller),
                hashBytes(buffer),
            },
        );
    }
}

fn proxyMemcpy(
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
) callconv(.c) ?*anyopaque {
    const original = loadOriginal(CopyFn, &real_memcpy) orelse return destination;
    if (inside_copy_hook) return original(destination, source, length);
    inside_copy_hook = true;
    defer inside_copy_hook = false;
    const caller = @returnAddress() & ~@as(usize, @intFromBool(builtin.cpu.arch == .arm));
    const result = original(destination, source, length);
    inspectCopiedBuffer(destination, source, length, length, caller, .memcpy);
    return result;
}

fn proxyMemmove(
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
) callconv(.c) ?*anyopaque {
    const caller = switch (builtin.cpu.arch) {
        .arm => @returnAddress() & ~@as(usize, 1),
        else => @returnAddress(),
    };
    const original = loadOriginal(CopyFn, &real_memmove) orelse return destination;
    if (inside_copy_hook) return original(destination, source, length);
    inside_copy_hook = true;
    defer inside_copy_hook = false;
    const result = original(destination, source, length);
    inspectCopiedBuffer(destination, source, length, length, caller, .memmove);

    if (caller == prs_copy_return_address and destination != null) {
        if (length < min_prs_length or length > max_prs_length) {
            // Only the ceiling is worth reporting: a body above the window is a
            // PRS response the strip silently skipped, which is the measurement
            // behind max_prs_length. Copies below the floor are ordinary small
            // copies through the same call site, not candidates.
            if (length > max_prs_length and shouldLogDiagnostic(&prs_length_skip_logs)) {
                logMessage(
                    android_log_info,
                    "PRS_SKIP reason=length length={d} min={d} max={d}",
                    .{ length, min_prs_length, max_prs_length },
                );
            }
        } else {
            const bytes: [*]u8 = @ptrCast(destination.?);
            const filtered = filterPrs(bytes[0..length]);
            if (filtered.parse_error) |err| {
                // Report only bodies that actually look like PRS. The caller
                // filter also catches unrelated copies, and their SyntaxError
                // would drown out a real limit being hit on the real body.
                const looks_like_prs =
                    std.mem.indexOf(u8, bytes[0..length], prs_playlist_marker) != null;
                if (looks_like_prs and shouldLogDiagnostic(&prs_parse_skip_logs)) {
                    logMessage(
                        android_log_error,
                        "PRS_SKIP reason=parse error={s} length={d}",
                        .{ @errorName(err), length },
                    );
                }
            } else if (filtered.found_playlist or
                filtered.pause_ads > 0 or
                filtered.non_linear_ads > 0)
            {
                logMessage(
                    android_log_info,
                    "PRS_MATCH writes={d} length={d} complete={d} items={d} remote_items={d} pause_ads={d} non_linear_ads={d}",
                    .{
                        @intFromBool(filtered.modified),
                        length,
                        @intFromBool(filtered.complete),
                        filtered.total_items,
                        filtered.remote_items,
                        filtered.pause_ads,
                        filtered.non_linear_ads,
                    },
                );
            }
        }
    }
    return result;
}

fn proxyMemcpyChk(
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
    destination_length: usize,
) callconv(.c) ?*anyopaque {
    const original = loadOriginal(CheckedCopyFn, &real_memcpy_chk) orelse return destination;
    if (inside_copy_hook) return original(destination, source, length, destination_length);
    inside_copy_hook = true;
    defer inside_copy_hook = false;
    const caller = @returnAddress() & ~@as(usize, @intFromBool(builtin.cpu.arch == .arm));
    const result = original(destination, source, length, destination_length);
    inspectCopiedBuffer(destination, source, length, destination_length, caller, .memcpy_chk);
    return result;
}

fn proxyMemmoveChk(
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
    destination_length: usize,
) callconv(.c) ?*anyopaque {
    const original = loadOriginal(CheckedCopyFn, &real_memmove_chk) orelse return destination;
    if (inside_copy_hook) return original(destination, source, length, destination_length);
    inside_copy_hook = true;
    defer inside_copy_hook = false;
    const caller = @returnAddress() & ~@as(usize, @intFromBool(builtin.cpu.arch == .arm));
    const result = original(destination, source, length, destination_length);
    inspectCopiedBuffer(destination, source, length, destination_length, caller, .memmove_chk);
    return result;
}

fn jniOnLoad() c_int {
    const prior_state = install_state.cmpxchgStrong(0, 1, .acq_rel, .acquire);
    if (prior_state != null) {
        logMessage(
            android_log_info,
            "JNI_OnLoad repeated install_state={d}",
            .{prior_state.?},
        );
        return jni_version_1_6;
    }
    defer install_state.store(2, .release);
    initPersistentLogging();

    logMessage(
        android_log_info,
        "JNI_OnLoad build={s} persistent_log_fd={d} raw_fd={d} log=files/{s} raw=files/{s}",
        .{ diagnostic_build, diagnostic_fd, diagnostic_raw_fd, diagnostic_log_name, diagnostic_raw_name },
    );
    if (builtin.cpu.arch != .arm and builtin.cpu.arch != .aarch64) {
        logMessage(android_log_error, "unsupported architecture", .{});
        return jni_version_1_6;
    }

    const signature_search = findSignature(ignite_library);
    if (signature_search.base == 0) {
        logMessage(android_log_error, "libignite.so is not loaded", .{});
        return jni_version_1_6;
    }

    ignite_base = signature_search.base;
    const signature_matches = signature_search.matches == 1;
    prs_copy_return_address = if (signature_matches) signature_search.address else 0;

    const memmove_hooked = hookImport(
        ignite_library,
        "memmove",
        @ptrCast(&proxyMemmove),
        &real_memmove,
    );
    const memcpy_hooked = hookImport(
        ignite_library,
        "memcpy",
        @ptrCast(&proxyMemcpy),
        &real_memcpy,
    );
    const memcpy_chk_hooked = hookImport(
        ignite_library,
        "__memcpy_chk",
        @ptrCast(&proxyMemcpyChk),
        &real_memcpy_chk,
    );
    const memmove_chk_hooked = hookImport(
        ignite_library,
        "__memmove_chk",
        @ptrCast(&proxyMemmoveChk),
        &real_memmove_chk,
    );
    // Widen before summing: @intFromBool yields u1, so adding four of them
    // together wraps mod 2 and reports 0 when every hook succeeded.
    const copy_hook_count: u32 =
        @as(u32, @intFromBool(memcpy_hooked)) +
        @as(u32, @intFromBool(memmove_hooked)) +
        @as(u32, @intFromBool(memcpy_chk_hooked)) +
        @as(u32, @intFromBool(memmove_chk_hooked));
    logMessage(
        if (copy_hook_count == 0) android_log_error else android_log_info,
        "installed copy_hooks={d}/4 memcpy={d} memmove={d} memcpy_chk={d} memmove_chk={d}",
        .{
            copy_hook_count,
            @intFromBool(memcpy_hooked),
            @intFromBool(memmove_hooked),
            @intFromBool(memcpy_chk_hooked),
            @intFromBool(memmove_chk_hooked),
        },
    );

    if (signature_matches and memmove_hooked) {
        const caller_offset = prs_copy_return_address - ignite_base;
        const logged_caller_offset =
            if (builtin.cpu.arch == .arm) caller_offset | 1 else caller_offset;
        logMessage(
            android_log_info,
            "PRS enabled caller_filter=+0x{x}",
            .{logged_caller_offset},
        );
    } else {
        prs_copy_return_address = 0;
        logMessage(
            android_log_error,
            "PRS disabled signature_matches={d} memmove_hooked={d}",
            .{ signature_search.matches, @intFromBool(memmove_hooked) },
        );
    }
    return jni_version_1_6;
}

export fn JNI_OnLoad(_: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    if (builtin.abi != .android and builtin.abi != .androideabi) {
        return jni_version_1_6;
    }
    return jniOnLoad();
}

test "tolerant online bundle patch empties renamed playlist local" {
    const source =
        "(x.prototype.reportAssetFulfilment = freeOnUnref(function (response) {" ++
        "for (var events = [], index = 0, ads = response.playlist; index < ads.length; index++) { events.push(ads[index]); }" ++
        "}));";
    var buffer: [source.len]u8 = source.*;
    const outcome = patchPlaylistLoop(&buffer, online_fulfilment_definition, buffer.len);
    try std.testing.expectEqual(SourcePatchOutcome.patched, outcome);
    try std.testing.expectEqual(source.len, buffer.len);
    try std.testing.expect(std.mem.indexOf(u8, &buffer, "ads.length=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, &buffer, "index < ads.length") == null);
}

test "tolerant EXPL patch skips the log length and patches loop condition" {
    const source =
        "(u.prototype.createPrerollPeriods = freeOnUnref(function (out, title, response) {" ++
        "var creativeList = response.playlist;" ++
        "this.log.info(\"Creating preroll periods with \" + creativeList.length + \" ad(s)\");" ++
        "for (var cursor = 0; cursor < creativeList.length; cursor++) out.append(creativeList[cursor]);" ++
        "}));";
    var buffer: [source.len]u8 = source.*;
    const outcome = patchPlaylistLoop(&buffer, expl_preroll_definition, buffer.len);
    try std.testing.expectEqual(SourcePatchOutcome.patched, outcome);
    try std.testing.expect(std.mem.indexOf(u8, &buffer, "creativeList.length=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, &buffer, "Creating preroll periods with") != null);
}

test "ambiguous source definition fails closed" {
    const one =
        "(x.prototype.reportAssetFulfilment=function(e){var r=e.playlist;for(var n=0;n<r.length;n++){};});";
    const source = one ++ one;
    var buffer: [source.len]u8 = source.*;
    const before = buffer;
    const outcome = patchPlaylistLoop(&buffer, online_fulfilment_definition, buffer.len);
    try std.testing.expectEqual(SourcePatchOutcome.ambiguous, outcome);
    try std.testing.expectEqualSlices(u8, &before, &buffer);
}

test "regolith accepts whitespace and absent measurement" {
    const json =
        "{\"description\":{\"adDeliverySessionId\":\"test\"}," ++
        "\"playlist\" : [ {\"type\":\"Ad\"} ],\"padding\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\"}";
    var buffer: [json.len]u8 = json.*;
    const result = filterRegolith(&buffer);
    try std.testing.expectEqual(RegolithOutcome.emptied, result.outcome);
    try std.testing.expectEqual(@as(u32, 1), result.item_count);
    const markers = scanMarkers(&buffer);
    try std.testing.expect(markers.bits & MarkerBits.playlist_key != 0);
    try std.testing.expect(markers.bits & MarkerBits.playlist_exact == 0);
}

test "mismatched nested bracket is never modified" {
    const json =
        "{\"adDeliverySessionId\":\"test\",\"playlist\":[{\"type\":\"Ad\"]],\"padding\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\"}";
    var buffer: [json.len]u8 = json.*;
    const before = buffer;
    const result = filterRegolith(&buffer);
    try std.testing.expectEqual(RegolithOutcome.truncated, result.outcome);
    try std.testing.expectEqualSlices(u8, &before, &buffer);
}

test "captured production bundle matches online and EXPL semantic patches" {
    const io = std.testing.io;
    var file = std.Io.Dir.cwd().openFile(io, "../jsanalysis/ATVUnfPlayerBundle-prod.js", .{}) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer file.close(io);
    const size = (try file.stat(io)).size;
    var reader_storage: [4096]u8 = undefined;
    var file_reader = file.reader(io, &reader_storage);
    const buffer = try file_reader.interface.readAlloc(std.testing.allocator, @intCast(size));
    defer std.testing.allocator.free(buffer);

    const before_length = buffer.len;
    const result = patchPlayerBundle(buffer);
    try std.testing.expect(result.candidate);
    try std.testing.expectEqual(SourcePatchOutcome.patched, result.online);
    try std.testing.expectEqual(SourcePatchOutcome.patched, result.expl);
    try std.testing.expect(result.modified());
    try std.testing.expectEqual(before_length, buffer.len);
}
