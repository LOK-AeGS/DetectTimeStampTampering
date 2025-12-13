-- xmake.lua

add_rules("mode.release", "mode.debug")

add_requires("libbpf")
add_requires("linux-tools", { configs = { bpftool = true } })
add_requires("ndk >=22.x")

if is_plat("android") then
    set_toolchains("@ndk", { sdkver = "23" })
end

-- 1) BPF ºôµå (clang, no skeleton)
target("probe.bpf")
  set_kind("object")
  set_plat("linux")
  add_rules("platform.linux.bpf", { skeleton = false })
    add_packages("libbpf")
  add_files("src/probe.bpf.c")
  -- ?? ½Éº¼ ¼û±èÀ» ¹æÁö
  add_cflags("-fvisibility=default")
-- 2) Android ½ÇÇàÆÄÀÏ ºôµå
target("probe")
    set_kind("binary")
    add_deps("probe.bpf")
    add_packages("libbpf", "linux-tools")
    add_files("src/main.c")

set_languages("gnu11")
