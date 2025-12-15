// probe.bpf.c
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sys_enter_args {
    __u64 _pad;
    long id;
    unsigned long args[6];
};

#define __NR_settimeofday 170

struct event {
    __u64 ktime_ns;
    __u64 cnt;
    long  tv_sec;
    long  tz_minuteswest;
};

/* ? ARRAY map: key/value 명시 (이건 맞는 수정) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_cnt SEC(".maps");

/*
 * ? PERF_EVENT_ARRAY: Android 호환성 높이는 정의
 * - max_entries=0: libbpf가 CPU 수로 채움
 * - key_size/value_size 명시: 커널/BTF 조합 문제 회피용
 * - __type(key/value) 같은 건 굳이 안 넣는 게 안전
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 0);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (ctx->id != __NR_settimeofday)
        return 0;

    __u32 key = 0;
    __u64 *cnt_ptr = bpf_map_lookup_elem(&syscall_cnt, &key);
    __u64 cnt = 0;

    if (cnt_ptr) {
        (*cnt_ptr)++;
        cnt = *cnt_ptr;
    }

    struct event ev = {};
    ev.ktime_ns = bpf_ktime_get_ns();
    ev.cnt = cnt;
    if (ctx->args[0]) {
        if (bpf_probe_read_user(&ev.tv_sec, sizeof(ev.tv_sec),
                                (void *)ctx->args[0]) != 0)
            ev.tv_sec = -1;
    } else {
        ev.tv_sec = -1;
    }

    if (ctx->args[1]) {
        if (bpf_probe_read_user(&ev.tz_minuteswest, sizeof(ev.tz_minuteswest),
                                (void *)ctx->args[1]) != 0)
            ev.tz_minuteswest = -1;
    } else {
        ev.tz_minuteswest = 0;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
