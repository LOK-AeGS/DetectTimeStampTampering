{
    depfiles = "build/.objs/loader/android/armeabi-v7a/release/src/main.c.o: src/main.c   /home/ags/aaaa/libbpf/src/libbpf.h   /home/ags/aaaa/libbpf/src/libbpf_common.h   /home/ags/aaaa/libbpf/src/libbpf_version.h   /home/ags/aaaa/libbpf/src/libbpf_legacy.h   /home/ags/aaaa/libbpf/src/bpf.h\
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
            "/root/.xmake/packages/n/ndk/27.3/709b519d63f24ce5852e029a207974f8/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/arm-linux-androideabi",
            "-Qunused-arguments",
            "--target=armv7-none-linux-androideabi23",
            "-mthumb",
            "-fPIE",
            "-pie",
            "-fvisibility=hidden",
            "-Oz",
            "-std=gnu11",
            "-I/home/ags/aaaa/libbpf/include",
            "-I/home/ags/aaaa/libbpf/src",
            "-DNDEBUG"
        }
    }
}