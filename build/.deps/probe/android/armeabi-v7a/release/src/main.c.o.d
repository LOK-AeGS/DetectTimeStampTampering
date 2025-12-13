{
    depfiles = "build/.objs/probe/android/armeabi-v7a/release/src/main.c.o: src/main.c\
",
    values = {
        "/root/.xmake/packages/n/ndk/27.0/e07657f39e114c7595f644a3a1a65030/toolchains/llvm/prebuilt/linux-x86_64/bin/clang",
        {
            "--sysroot=/root/.xmake/packages/n/ndk/27.0/e07657f39e114c7595f644a3a1a65030/toolchains/llvm/prebuilt/linux-x86_64/sysroot",
            "-isystem",
            "/root/.xmake/packages/n/ndk/27.0/e07657f39e114c7595f644a3a1a65030/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/arm-linux-androideabi",
            "-Qunused-arguments",
            "--target=armv7-none-linux-androideabi23",
            "-mthumb",
            "-fPIE",
            "-pie",
            "-fvisibility=hidden",
            "-Oz",
            "-std=gnu11",
            "-D__LIBELF64=1",
            "-D__libelf_u64_t=uint64_t",
            "-D__libelf_i64_t=int64_t",
            "-isystem",
            "/root/.xmake/packages/l/libbpf/v0.3/cf3cf1d1f041468785d35a0f5c6401a2/include",
            "-isystem",
            "/root/.xmake/packages/l/libbpf/v0.3/cf3cf1d1f041468785d35a0f5c6401a2/include/uapi",
            "-isystem",
            "/root/.xmake/packages/l/libelf/0.8.13/9f7f4d1f0b71486eaed3426ace560493/include",
            "-isystem",
            "/root/.xmake/packages/l/libelf/0.8.13/9f7f4d1f0b71486eaed3426ace560493/include/libelf",
            "-isystem",
            "/root/.xmake/packages/z/zlib/v1.3.1/351515e9dd074626b7230811e30be148/include",
            "-DNDEBUG"
        }
    },
    depfiles_format = "gcc",
    files = {
        "src/main.c"
    }
}