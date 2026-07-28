const std = @import("std");

pub fn build(b: *std.Build) void {
    const android_arm = b.resolveTargetQuery(.{
        .cpu_arch = .arm,
        .os_tag = .linux,
        .abi = .androideabi,
    });
    const android_arm64 = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .android,
    });

    const update_resource = b.addUpdateSourceFiles();
    addNativeHook(
        b,
        update_resource,
        android_arm,
        "patches/src/main/resources/native/armeabi-v7a/libpvhook.so",
    );
    addNativeHook(
        b,
        update_resource,
        android_arm64,
        "patches/src/main/resources/native/arm64-v8a/libpvhook.so",
    );

    const native_step = b.step(
        "native",
        "Build the Prime Video hook and update its Morphe resources",
    );
    native_step.dependOn(&update_resource.step);
    b.default_step = native_step;
}

fn addNativeHook(
    b: *std.Build,
    update_resource: *std.Build.Step.UpdateSourceFiles,
    target: std.Build.ResolvedTarget,
    resource_output: []const u8,
) void {
    const libc_stub = addStubLibrary(
        b,
        target,
        "c",
        "native/primevideo/stubs/libc.zig",
    );
    const libdl_stub = addStubLibrary(
        b,
        target,
        "dl",
        "native/primevideo/stubs/libdl.zig",
    );
    const liblog_stub = addStubLibrary(
        b,
        target,
        "log",
        "native/primevideo/stubs/liblog.zig",
    );

    const hook_module = b.createModule(.{
        .root_source_file = b.path("native/primevideo/pvhook.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .strip = true,
        .pic = true,
    });

    // Pass generated shared libraries as linker inputs without linkLibrary(),
    // which would add build-cache paths to the final RUNPATH.
    hook_module.addObjectFile(libc_stub.getEmittedBin());
    hook_module.addObjectFile(libdl_stub.getEmittedBin());
    hook_module.addObjectFile(liblog_stub.getEmittedBin());

    const hook = b.addLibrary(.{
        .name = "pvhook",
        .linkage = .dynamic,
        .root_module = hook_module,
    });
    update_resource.addCopyFileToSource(hook.getEmittedBin(), resource_output);
}

fn addStubLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    name: []const u8,
    source: []const u8,
) *std.Build.Step.Compile {
    return b.addLibrary(.{
        .name = name,
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = target,
            .optimize = .ReleaseSmall,
            .strip = true,
            .pic = true,
        }),
    });
}
