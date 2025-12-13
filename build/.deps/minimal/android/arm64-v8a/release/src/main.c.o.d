{
    depfiles = "build/.objs/minimal/android/arm64-v8a/release/src/__cpp_main.c.c:   src/main.c\
",
    files = {
        "src/main.c"
    },
    depfiles_format = "gcc",
    values = {
        "/root/.xmake/packages/n/ndk/27.3/709b519d63f24ce5852e029a207974f8/toolchains/llvm/prebuilt/linux-x86_64/bin/clang",
        {
            "--sysroot=/root/.xmake/packages/n/ndk/27.3/709b519d63f24ce5852e029a207974f8/toolchains/llvm/prebuilt/linux-x86_64/sysroot",
            "-isystem",
            "/root/.xmake/packages/n/ndk/27.3/709b519d63f24ce5852e029a207974f8/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/aarch64-linux-android",
            "-Qunused-arguments",
            "--target=aarch64-none-linux-android23",
            "-fPIE",
            "-pie",
            "-Oz",
            "-Ibuild/.gens/minimal/android/arm64-v8a/release/rules/bpf",
            "-isystem",
            "/root/.xmake/packages/l/libbpf/v1.6.2/f984cdbbd4e549939338c240b82d55d2/include",
            "-isystem",
            "/root/.xmake/packages/l/libbpf/v1.6.2/f984cdbbd4e549939338c240b82d55d2/include/uapi",
            "-isystem",
            "/root/.xmake/packages/e/elfutils/0.190/bd8f30d7dd5e4024960a6cce0d6f8ab2/include",
            "-isystem",
            "/root/.xmake/packages/z/zstd/v1.5.7/5ef4aa4af11a4057a9f707433a303429/include",
            "-isystem",
            "/root/.xmake/packages/z/zlib/v1.3.1/eb8613809c6c4fe18aa1b626df4f3620/include",
            "-isystem",
            "/root/.xmake/packages/l/libintl/0.22.3/88dc594639b2459bb777267549a4723b/include",
            "-isystem",
            "/root/.xmake/packages/a/argp-standalone/1.3/099a3b86e9a748ab8a29ba535d43f227/include",
            "-DNDEBUG"
        }
    }
}