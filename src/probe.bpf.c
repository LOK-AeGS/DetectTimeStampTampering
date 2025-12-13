// settimeofday.bpf.c

// 표준 C 및 BPF 헤더
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> // bpf_probe_read_user_kern 사용을 위해 필요할 수 있습니다.

// 라이선스 명시
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 시스템 콜 번호 (x86_64 기준)
#define __NR_settimeofday 170
#define SETTIMEOFDAY_IDX 0

// TASK_COMM_LEN 정의
#define TASK_COMM_LEN 16

// sys_enter 트레이스포인트의 인자 구조체 정의
// common fields (8 bytes) + id (8 bytes) + args[6] (48 bytes)
struct sys_enter_args {
    unsigned long long pad; 
    long id;               
    unsigned long args[6]; 
};

// 맵의 값 구조체 (main.c와 동일해야 합니다)
struct last_args_val {
    long tv_sec;            // struct timeval*의 tv_sec
    long tz_minuteswest;    // struct timezone*의 tz_minuteswest
};

// ----------------------------------------------------
// BPF 맵 정의 (.maps 섹션)
// ----------------------------------------------------

// 1. syscall 횟수 저장 맵 (키: int, 값: u64)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} syscall_cnt SEC(".maps"); 

// 2. 마지막 인자 저장 맵 (키: int, 값: struct last_args_val)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct last_args_val);
} last_args SEC(".maps"); 

// ----------------------------------------------------
// BPF 프로그램 정의 (tracepoint 섹션)
// ----------------------------------------------------

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (ctx->id != __NR_settimeofday) {
        return 0;
    }

    int key = SETTIMEOFDAY_IDX;
    __u64 *cnt_ptr;
    struct last_args_val new_args = {0};

    // 1. 횟수 카운트 증가
    cnt_ptr = bpf_map_lookup_elem(&syscall_cnt, &key);
    if (cnt_ptr) {
        __sync_fetch_and_add(cnt_ptr, 1);
    } else {
        // 맵이 초기화되지 않은 경우 (ARRAY 맵에서는 거의 발생하지 않음)
        __u64 one = 1;
        bpf_map_update_elem(&syscall_cnt, &key, &one, BPF_ANY);
    }
    
    // 2. 인자 맵 업데이트
    // sys_settimeofday(const struct timeval *tv, const struct timezone *tz)
    
    // 인자 0: tv 포인터 (struct timeval *)
    if (ctx->args[0]) {
        // struct timeval { __kernel_time_t tv_sec; ... }
        // tv_sec (long)은 구조체의 첫 번째 멤버입니다.
        // bpf_probe_read_user를 사용해 사용자 공간 메모리를 읽습니다.
        if (bpf_probe_read_user(&new_args.tv_sec, sizeof(long), (void *)ctx->args[0]) != 0) {
            new_args.tv_sec = -1; // 읽기 실패
        }
    }

    // 인자 1: tz 포인터 (struct timezone *)
    if (ctx->args[1]) {
        // struct timezone { int tz_minuteswest; ... }
        // tz_minuteswest (int)는 구조체의 첫 번째 멤버입니다.
        // main.c의 struct last_args_val에서는 long으로 정의했으므로, long 크기로 읽습니다.
        if (bpf_probe_read_user(&new_args.tz_minuteswest, sizeof(long), (void *)ctx->args[1]) != 0) {
            new_args.tz_minuteswest = -1; // 읽기 실패
        }
    }
    
    // 최종 인자 값을 맵에 업데이트
    bpf_map_update_elem(&last_args, &key, &new_args, BPF_ANY);

    return 0;
}