#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>

#if __has_include(<bpf/libbpf.h>)
  #include <bpf/libbpf.h>
#else
  #include <libbpf.h>
#endif

#if __has_include(<bpf/bpf.h>)
  #include <bpf/bpf.h>
#else
  #include <bpf.h>
#endif

#define SETTIMEOFDAY_IDX 0
#define EPSILON_SEC 60   /* ¡¾1 minute tolerance */

static volatile sig_atomic_t exiting = 0;
static void on_sig(int s) { (void)s; exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list ap) {
    (void)level;
    return vfprintf(stderr, fmt, ap);
}

/* must match BPF side */
struct last_args_val {
    long tv_sec;
    long tz_minuteswest;
};

/* Trusted timeline (keep ¡°expected/untampered¡± timeline) */
static time_t trusted_wall = 0;           /* baseline wall at trusted_boot */
static struct timespec trusted_boot = {0};

static void init_trusted(void) {
    trusted_wall = time(NULL);
    clock_gettime(CLOCK_BOOTTIME, &trusted_boot);
}

static time_t expected_wall_from_trusted(struct timespec now_boot) {
    time_t delta = now_boot.tv_sec - trusted_boot.tv_sec;
    return trusted_wall + delta;
}

static const char *classify(time_t new_wall, time_t expected, time_t *out_diff) {
    time_t diff = new_wall - expected;
    if (out_diff) *out_diff = diff;

    if (diff > EPSILON_SEC) return "FUTURE";
    if (diff < -EPSILON_SEC) return "PAST";
    return "CURRENT"; /* means ¡°aligned with expected timeline¡± */
}

int main(int argc, char **argv) {
    const char *obj_path = (argc > 1) ? argv[1] : "probe.bpf.o";

    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;

    int fd_cnt = -1;
    int fd_args = -1;

    __u64 prev_cnt = 0;
    int key = SETTIMEOFDAY_IDX;
    int err = 0;

    setrlimit(RLIMIT_MEMLOCK, &r);
    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    init_trusted();

    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        err = -errno;
        fprintf(stderr, "open %s failed: %d\n", obj_path, err);
        obj = NULL;
        goto out;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load failed: %d (%s)\n", err, strerror(-err));
        goto out;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_sys_enter");
    if (!prog) {
        fprintf(stderr, "prog handle_sys_enter not found\n");
        err = 1;
        goto out;
    }

    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");
    if (libbpf_get_error(link)) {
        err = -errno;
        fprintf(stderr, "attach tracepoint failed: %d\n", err);
        link = NULL;
        goto out;
    }

    fd_cnt  = bpf_object__find_map_fd_by_name(obj, "syscall_cnt");
    fd_args = bpf_object__find_map_fd_by_name(obj, "last_args");
    if (fd_cnt < 0 || fd_args < 0) {
        fprintf(stderr, "map fds not found (syscall_cnt=%d last_args=%d)\n", fd_cnt, fd_args);
        err = 1;
        goto out;
    }

    printf("Attached. Detecting settimeofday() time jumps. Ctrl+C to stop.\n");
    printf("Initial trusted: wall=%ld boot=%ld\n", (long)trusted_wall, (long)trusted_boot.tv_sec);

    while (!exiting) {
        __u64 cnt = 0;
        struct last_args_val a;
        memset(&a, 0, sizeof(a));

        if (bpf_map_lookup_elem(fd_cnt, &key, &cnt) != 0) {
            usleep(150 * 1000);
            continue;
        }
        (void)bpf_map_lookup_elem(fd_args, &key, &a);

        if (cnt != prev_cnt) {
    struct timespec now_boot;
    clock_gettime(CLOCK_BOOTTIME, &now_boot);

    time_t expected = expected_wall_from_trusted(now_boot);
    time_t new_wall = (time_t)a.tv_sec;

    time_t diff = 0;
    const char *cls = classify(new_wall, expected, &diff);

    printf("settimeofday: cnt=%llu new=%ld expected=%ld diff=%ld => [%s] tz_minuteswest=%ld\n",
           (unsigned long long)cnt,
           (long)new_wall,
           (long)expected,
           (long)diff,
           cls,
           (long)a.tz_minuteswest);

    trusted_wall = expected;
    trusted_boot = now_boot;

    prev_cnt = cnt;
    fflush(stdout);
}

        usleep(150 * 1000);
    }

out:
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    return err ? 1 : 0;
}
