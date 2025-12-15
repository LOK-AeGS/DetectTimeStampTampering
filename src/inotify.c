#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN    (2048 * (EVENT_SIZE + NAME_MAX))
#define EPSILON    60   /* ±1 minute */

/* =========================================================
 *  ALERT LOG FD
 * ========================================================= */
static int alert_fd = -1;

/* =========================================================
 *  BOOTTIME anchor
 * ========================================================= */
static time_t wall_anchor;
static struct timespec boot_anchor;

static void init_anchor(void)
{
    wall_anchor = time(NULL);
    clock_gettime(CLOCK_BOOTTIME, &boot_anchor);
}

static time_t expected_wall_time(void)
{
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    return wall_anchor + (now.tv_sec - boot_anchor.tv_sec);
}

/* =========================================================
 *  FILE TIME STATE
 * ========================================================= */
enum file_time_state {
    FILE_NORMAL,
    FILE_PAST,
    FILE_FUTURE
};

static enum file_time_state
check_file_time(time_t file_time)
{
    time_t expected = expected_wall_time();
    time_t diff = file_time - expected;

    if (diff > EPSILON)
        return FILE_FUTURE;
    if (diff < -EPSILON)
        return FILE_PAST;
    return FILE_NORMAL;
}

static const char *file_state_str(enum file_time_state s)
{
    switch (s) {
    case FILE_PAST:   return "FILE_PAST";
    case FILE_FUTURE: return "FILE_FUTURE";
    default:          return "FILE_NORMAL";
    }
}

/* =========================================================
 *  SYSTEM TIME STATE (from time_changed.txt)
 * ========================================================= */
static const char *read_time_state(const char *log_path)
{
    static char state[16] = "UNKNOWN";
    char line[512];

    FILE *fp = fopen(log_path, "r");
    if (!fp)
        return state;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[FUTURE]"))
            strcpy(state, "FUTURE");
        else if (strstr(line, "[PAST]"))
            strcpy(state, "PAST");
        else if (strstr(line, "[CURRENT]"))
            strcpy(state, "CURRENT");
    }

    fclose(fp);
    return state;
}

/* =========================================================
 *  LOG HELPER (printf 대체)
 * ========================================================= */
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

/* =========================================================
 *  MAIN
 * ========================================================= */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <target_file> <time_changed.txt>\n", argv[0]);
        return 1;
    }

    const char *target_path = argv[1];
    const char *time_log    = argv[2];

    /* open alert log */
    alert_fd = open("/data/local/tmp/alerts.log",
                    O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (alert_fd < 0) {
        perror("open alerts.log");
        return 1;
    }

    char realpath_buf[PATH_MAX];
    if (!realpath(target_path, realpath_buf)) {
        perror("realpath");
        return 1;
    }

    char *p1 = strdup(realpath_buf);
    char *p2 = strdup(realpath_buf);
    char *dir  = dirname(p1);
    char *file = basename(p2);

    struct stat prev_st;
    if (stat(realpath_buf, &prev_st) != 0) {
        perror("stat");
        return 1;
    }

    init_anchor();

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init");
        return 1;
    }

    int file_wd = inotify_add_watch(
        fd,
        realpath_buf,
        IN_ATTRIB | IN_MODIFY | IN_CLOSE_WRITE |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED
    );

    int dir_wd = inotify_add_watch(
        fd,
        dir,
        IN_CREATE | IN_MOVED_TO
    );

    if (file_wd < 0 || dir_wd < 0) {
        perror("inotify_add_watch");
        return 1;
    }

    /* 감시 시작 메시지는 stdout 유지 */
    printf("[Watcher] Monitoring %s\n", realpath_buf);

    char buf[BUF_LEN];

    while (1) {
        int len = read(fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN) {
                usleep(100000);
                continue;
            }
            break;
        }

        for (int i = 0; i < len; ) {
            struct inotify_event *e =
                (struct inotify_event *)&buf[i];

            /* ----- directory: file recreated ----- */
            if (e->wd == dir_wd && e->len > 0 &&
                strcmp(e->name, file) == 0 &&
                (e->mask & IN_MOVED_TO)) {

                log_alert("[System] File recreated\n");

                int new_wd = inotify_add_watch(
                    fd,
                    realpath_buf,
                    IN_ATTRIB | IN_MODIFY | IN_CLOSE_WRITE |
                    IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED
                );
                if (new_wd >= 0)
                    file_wd = new_wd;

                stat(realpath_buf, &prev_st);
            }

            /* ----- file events ----- */
            else if (e->wd == file_wd &&
                     (e->mask & (IN_ATTRIB | IN_MODIFY | IN_CLOSE_WRITE))) {

                struct stat cur_st;
                if (stat(realpath_buf, &cur_st) == 0) {

                    const char *sys_state =
                        read_time_state(time_log);

                    if (cur_st.st_mtime != prev_st.st_mtime) {
                        enum file_time_state fs =
                            check_file_time(cur_st.st_mtime);
                        log_alert(
                            "[ALERT] mtime changed | system=%s | %s\n",
                            sys_state, file_state_str(fs)
                        );
                    }

                    if (cur_st.st_atime != prev_st.st_atime) {
                        enum file_time_state fs =
                            check_file_time(cur_st.st_atime);
                        log_alert(
                            "[ALERT] atime changed | system=%s | %s\n",
                            sys_state, file_state_str(fs)
                        );
                    }

                    prev_st = cur_st;
                }
            }

            i += EVENT_SIZE + e->len;
        }
    }

    close(fd);
    close(alert_fd);
    free(p1);
    free(p2);
    return 0;
}
