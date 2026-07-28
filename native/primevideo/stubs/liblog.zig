// Link-time interface only. Android's real liblog implementation supplies
// this symbol when libpvhook is loaded on the device.
export fn __android_log_write(
    _: c_int,
    _: [*:0]const u8,
    _: [*:0]const u8,
) callconv(.c) c_int {
    return 0;
}
