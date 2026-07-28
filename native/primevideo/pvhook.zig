const std = @import("std");
const builtin = @import("builtin");

const log_tag: [*:0]const u8 = "PVHook";
const ignite_library = "libignite.so";

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
const max_prs_length = 262144;
const max_playlist_items = 256;
const max_metadata_edits = 256;
const max_json_depth = 64;
// Bounded backing storage for Scanner's nesting BitStack, including its reserve capacity.
const json_stack_storage_bytes = 256;

const android_log_info = 4;
const android_log_error = 6;
const jni_version_1_6 = 0x00010006;
const jni_err = -1;

// Zig 0.16's std.elf does not expose ARM or AArch64 relocation constants.
const r_arm_jump_slot = 22;
const r_aarch64_jump_slot = 1026;
const prot_read = 1;
const prot_write = 2;
const sc_pagesize = 39;

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

const MemmoveFn = *const fn (
    destination: ?*anyopaque,
    source: ?*const anyopaque,
    length: usize,
) callconv(.c) ?*anyopaque;

const FilterResult = struct {
    found_playlist: bool = false,
    complete: bool = false,
    total_items: u32 = 0,
    remote_items: u32 = 0,
    pause_ads: u32 = 0,
    non_linear_ads: u32 = 0,
    modified: bool = false,
};

var real_memmove: ?MemmoveFn = null;
var ignite_base: usize = 0;
var prs_copy_return_address: usize = 0;

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
    playlist,
    pause_ads,
    non_linear_ads,
    item_type,
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

const ParseContext = struct {
    scanner: *std.json.Scanner,
    diagnostics: *std.json.Diagnostics,
    edits: [max_metadata_edits]MetadataEdit = undefined,
    edit_count: usize = 0,
    playlist: PlaylistCapture = .{},

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
};

const key_names = [_][]const u8{
    "intraTitlePlaylist",
    "pauseAdsResolution",
    "nonLinearAds",
    "type",
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
        0 => .playlist,
        1 => .pause_ads,
        2 => .non_linear_ads,
        3 => .item_type,
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
        const pause_target = collect and key == .pause_ads and value_type == .object_begin;
        const non_linear_target =
            collect and key == .non_linear_ads and value_type == .array_begin;
        const playlist_target =
            collect and
            key == .playlist and
            value_type == .array_begin and
            !context.playlist.found;

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

fn analyzeJson(buffer: []const u8) ?Analysis {
    var nesting_storage: [json_stack_storage_bytes]u8 = undefined;
    var fixed_allocator = std.heap.FixedBufferAllocator.init(&nesting_storage);
    var scanner = std.json.Scanner.initCompleteInput(fixed_allocator.allocator(), buffer);
    defer scanner.deinit();
    scanner.ensureTotalStackCapacity(max_json_depth) catch return null;

    var diagnostics = std.json.Diagnostics{};
    scanner.enableDiagnostics(&diagnostics);
    var context = ParseContext{
        .scanner = &scanner,
        .diagnostics = &diagnostics,
    };
    _ = parseValue(&context, 0, true, false) catch return null;
    const final = scanner.next() catch return null;
    if (final != .end_of_document) return null;

    return .{
        .edits = context.edits,
        .edit_count = context.edit_count,
        .playlist = context.playlist,
    };
}

fn replaceRange(buffer: []u8, range: JsonRange, replacement: []const u8) void {
    @memcpy(buffer[range.start .. range.start + replacement.len], replacement);
    @memset(buffer[range.start + replacement.len .. range.end], ' ');
}

fn filterPrs(buffer: []u8) FilterResult {
    var result = FilterResult{};
    if (buffer.len == 0) return result;
    const analysis = analyzeJson(buffer) orelse return result;

    for (analysis.edits[0..analysis.edit_count]) |edit| {
        switch (edit.kind) {
            .pause_ads => {
                replaceRange(buffer, edit.range, "null");
                result.pause_ads += 1;
            },
            .non_linear_ads => {
                replaceRange(buffer, edit.range, "[]");
                result.non_linear_ads += 1;
            },
        }
    }
    result.modified = analysis.edit_count > 0;

    const playlist = analysis.playlist;
    result.found_playlist = playlist.found;
    result.complete = playlist.complete;
    result.total_items = @intCast(playlist.item_count);
    result.remote_items = @intCast(playlist.remote_count);

    if (playlist.complete and playlist.remote_count > 0) {
        var write = playlist.array_start + 1;
        var kept: usize = 0;
        for (0..playlist.item_count) |item| {
            if (playlist.remote[item]) continue;
            if (kept > 0) {
                buffer[write] = ',';
                write += 1;
            }
            const item_length = playlist.ends[item] - playlist.starts[item];
            std.mem.copyForwards(
                u8,
                buffer[write .. write + item_length],
                buffer[playlist.starts[item]..playlist.ends[item]],
            );
            write += item_length;
            kept += 1;
        }
        @memset(buffer[write..playlist.array_end], ' ');
        result.modified = true;
    }
    return result;
}

fn logMessage(priority: c_int, comptime format: []const u8, arguments: anytype) void {
    var storage: [384]u8 = undefined;
    const text = std.fmt.bufPrintZ(&storage, format, arguments) catch return;
    _ = __android_log_write(priority, log_tag, text.ptr);
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
) ?*anyopaque {
    var search = ImportSearch{
        .library_name = library_name,
        .symbol_name = symbol_name,
    };
    _ = dl_iterate_phdr(findImportCallback, &search);
    const slot = search.slot orelse return null;

    const page_size_signed = sysconf(sc_pagesize);
    if (page_size_signed <= 0) return null;
    const page_size: usize = @intCast(page_size_signed);
    const page = @intFromPtr(slot) & ~(page_size - 1);
    if (mprotect(@ptrFromInt(page), page_size, prot_read | prot_write) != 0) return null;

    const previous = @atomicLoad(*anyopaque, slot, .acquire);
    @atomicStore(*anyopaque, slot, @constCast(replacement), .release);
    return previous;
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
    const original = real_memmove orelse return destination;
    const result = original(destination, source, length);

    if (caller == prs_copy_return_address and
        destination != null and
        length >= min_prs_length and
        length <= max_prs_length)
    {
        const bytes: [*]u8 = @ptrCast(destination.?);
        const filtered = filterPrs(bytes[0..length]);
        if (filtered.found_playlist or filtered.pause_ads > 0 or filtered.non_linear_ads > 0) {
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
    return result;
}

fn jniOnLoad() c_int {
    logMessage(android_log_info, "JNI_OnLoad", .{});
    if (builtin.cpu.arch != .arm and builtin.cpu.arch != .aarch64) {
        logMessage(android_log_error, "unsupported architecture", .{});
        return jni_err;
    }

    const signature_search = findSignature(ignite_library);
    if (signature_search.base == 0) {
        logMessage(android_log_error, "libignite.so is not loaded", .{});
        return jni_err;
    }
    if (signature_search.matches != 1) {
        logMessage(
            android_log_error,
            "PRS signature matches={d}, expected exactly 1",
            .{signature_search.matches},
        );
        return jni_err;
    }

    ignite_base = signature_search.base;
    prs_copy_return_address = signature_search.address;
    const previous = hookImport(
        ignite_library,
        "memmove",
        @ptrCast(&proxyMemmove),
    ) orelse {
        logMessage(
            android_log_error,
            "failed to hook libignite.so!memmove",
            .{},
        );
        return jni_err;
    };
    real_memmove = @ptrCast(@alignCast(previous));
    const caller_offset = prs_copy_return_address - ignite_base;
    const logged_caller_offset =
        if (builtin.cpu.arch == .arm) caller_offset | 1 else caller_offset;
    logMessage(
        android_log_info,
        "installed libignite.so!memmove caller_filter=+0x{x}",
        .{logged_caller_offset},
    );
    return jni_version_1_6;
}

export fn JNI_OnLoad(_: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    if (builtin.abi != .android and builtin.abi != .androideabi) {
        return jni_version_1_6;
    }
    return jniOnLoad();
}
