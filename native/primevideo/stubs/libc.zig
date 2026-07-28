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
