// Link-time interface only. This file is compiled into a temporary shared
// library and is never packaged in the APK.
export fn mprotect(
    _: *anyopaque,
    _: usize,
    _: c_int,
) callconv(.c) c_int {
    return 0;
}

export fn sysconf(_: c_int) callconv(.c) isize {
    return 4096;
}

export fn open(_: [*:0]const u8, _: c_int, ...) callconv(.c) c_int {
    return -1;
}

export fn read(_: c_int, _: [*]u8, _: usize) callconv(.c) isize {
    return -1;
}

export fn write(_: c_int, _: [*]const u8, length: usize) callconv(.c) isize {
    return @intCast(length);
}

export fn close(_: c_int) callconv(.c) c_int {
    return 0;
}

export fn gettid() callconv(.c) c_int {
    return 0;
}
