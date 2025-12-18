#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 10000
#define STEP_SECONDS (30 * 60) // 30분

int main() {
    struct timeval tv;
    struct timespec start, end;
    long long total_ns = 0;

    int fail = 0;
    int ok = 0;

    // 기준 시간 1회만 획득
    if (gettimeofday(&tv, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }

    // 측정 시작
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < ITERATIONS; i++) {
        // 30분씩 미래로 이동
        tv.tv_sec += STEP_SECONDS;

        if (settimeofday(&tv, NULL) < 0) {
            fail++;
        } else {
            ok++;
        }
    }

    // 측정 종료
    clock_gettime(CLOCK_MONOTONIC, &end);

    total_ns =
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        (end.tv_nsec - start.tv_nsec);

    printf("Iterations: %d\n", ITERATIONS);
    printf("Total Time: %lld ns\n", total_ns);
    printf("Avg Time per Call: %lld ns\n", total_ns / ITERATIONS);
    printf("success: %d\n", ok);
    printf("failed: %d\n", fail);

    return 0;
}
