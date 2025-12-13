{
    files = {
        "build/.objs/probe/android/armeabi-v7a/release/src/main.c.o"
    },
    values = {
        "/root/.xmake/packages/n/ndk/27.0/e07657f39e114c7595f644a3a1a65030/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++",
        {
            "-llog",
            "--target=armv7-none-linux-androideabi23",
            "-fPIE",
            "-pie",
            "-static-libstdc++",
            "-lc++abi",
            "-mthumb",
            "-L/root/.xmake/packages/l/libbpf/v0.3/cf3cf1d1f041468785d35a0f5c6401a2/lib",
            "-L/root/.xmake/packages/l/libelf/0.8.13/9f7f4d1f0b71486eaed3426ace560493/lib",
            "-L/root/.xmake/packages/z/zlib/v1.3.1/351515e9dd074626b7230811e30be148/lib",
            "-s",
            "-lbpf",
            "-lelf",
            "-lz",
            "-lunwind",
            "-latomic"
        }
    }
}