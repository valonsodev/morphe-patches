// Link-time interface only. The callback's concrete layout is irrelevant to
// the stub body; libpvhook declares and uses the complete Android signature.
const Callback = *const fn (
    info: ?*anyopaque,
    size: usize,
    context: ?*anyopaque,
) callconv(.c) c_int;

export fn dl_iterate_phdr(
    _: Callback,
    _: ?*anyopaque,
) callconv(.c) c_int {
    return 0;
}
