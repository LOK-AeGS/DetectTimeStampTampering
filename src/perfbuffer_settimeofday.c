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
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EPSILON_SEC 60

static volatile sig_atomic_t exiting = 0;
static int alert_fd = -1;

/* ===== signal ===== */
static void on_sig(int sig)
{
    (void)sig;
    exiting = 1;
}

/* ===== libbpf log ===== */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list ap)
{
    (void)level;
    return vfprintf(stderr, fmt, ap);
}

/* ===== MUST match BPF side ===== */
struct event {
    __u64 ktime_ns;
    __u64 cnt;
    long  tv_sec;
    long  tz_minuteswest;
};

/* ===== trusted timeline ===== */
static time_t trusted_wall;
static struct timespec trusted_boot;

static void init_trusted(void)
{
    trusted_wall = time(NULL);
    clock_gettime(CLOCK_BOOTTIME, &trusted_boot);
}

static time_t expected_wall(struct timespec now_boot)
{
    time_t delta = now_boot.tv_sec - trusted_boot.tv_sec;
    return trusted_wall + delta;
}

static const char *classify(time_t new_wall,
                            time_t expected,
                            time_t *out_diff)
{
    time_t diff = new_wall - expected;
    if (out_diff)
        *out_diff = diff;

    if (diff > EPSILON_SEC)
        return "FUTURE";
    if (diff < -EPSILON_SEC)
        return "PAST";
    return "CURRENT";
}

/* ===== logging ===== */
static void log_alert(const char *fmt, ...)
{
    if (alert_fd < 0)
        return;

    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len > 0)
        write(alert_fd, buf, len);
}

/* ===== perf callbacks ===== */
static void handle_event(void *ctx, int cpu, void *data, unsigned int size)
{
    (void)ctx;
    (void)cpu;

    if (size < sizeof(struct event))
        return;

    const struct event *e = data;

    struct timespec now_boot;
    clock_gettime(CLOCK_BOOTTIME, &now_boot);

    time_t expected = expected_wall(now_boot);
    time_t new_wall = (time_t)e->tv_sec;

    time_t diff;
    const char *cls = classify(new_wall, expected, &diff);

    log_alert(
        "SETTIMEOFDAY cnt=%llu new=%ld expected=%ld diff=%ld state=%s tz=%ld ktime_ns=%llu\n",
        (unsigned long long)e->cnt,
        (long)new_wall,
        (long)expected,
        (long)diff,
        cls,
        (long)e->tz_minuteswest,
        (unsigned long long)e->ktime_ns
    );

    /* attacker time을 신뢰하지 않고, trusted 기준 유지 */
    trusted_wall = expected;
    trusted_boot = now_boot;
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    (void)ctx;
    log_alert("LOST_EVENTS cpu=%d lost=%llu\n",
              cpu, (unsigned long long)lost_cnt);
}

/* ===== main ===== */
int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "probe.bpf.o";
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;

    int err;

    /* open log */
    alert_fd = open("/data/local/tmp/settime_alerts.log",
                    O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (alert_fd < 0) {
        perror("open log");
        return 1;
    }

    setrlimit(RLIMIT_MEMLOCK, &rlim);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    init_trusted();
    log_alert("INIT trusted_wall=%ld trusted_boot=%ld\n",
              (long)trusted_wall, (long)trusted_boot.tv_sec);

    /* open & load BPF */
    obj = bpf_object__open_file(obj_path, NULL);
    err = libbpf_get_error(obj);
    if (err) {
        obj = NULL;
        goto out;
    }

    err = bpf_object__load(obj);
    if (err)
        goto out;

    prog = bpf_object__find_program_by_name(obj, "handle_sys_enter");
    if (!prog) {
        err = -ENOENT;
        goto out;
    }

    link = bpf_program__attach_tracepoint(
        prog, "raw_syscalls", "sys_enter");
    err = libbpf_get_error(link);
    if (err) {
        link = NULL;
        goto out;
    }

    /* perf events map */
    int fd_events = bpf_object__find_map_fd_by_name(obj, "events");
    if (fd_events < 0) {
        err = -ENOENT;
        goto out;
    }

    /* perf buffer */
    struct perf_buffer_opts pb_opts;
    memset(&pb_opts, 0, sizeof(pb_opts));
    pb_opts.sz = sizeof(pb_opts);

    pb = perf_buffer__new(fd_events, 256,
                          handle_event, handle_lost,
                          NULL, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        goto out;
    }

    /* event loop */
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            log_alert("poll error=%d\n", err);
            break;
        }
    }

    err = 0;

out:
    if (pb)
        perf_buffer__free(pb);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    if (alert_fd >= 0)
        close(alert_fd);

    return err ? 1 : 0;
}
