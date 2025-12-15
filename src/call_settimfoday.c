#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 10000 // 횟수는 시스템 영향 고려하여 조절 (settimeofday는 시간 변경하므로 주의!)

int main() {
    struct timeval tv;
    struct timespec start, end;
    long long total_ns = 0;

    // 현재 시간 가져오기 (테스트용 더미 값)
    gettimeofday(&tv, NULL); 

    // 측정 시작
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < ITERATIONS; i++) {
        // settimeofday 호출 (권한 필요, 실제 시간 변경됨 주의)
        // 성능 측정만을 위함이라면 실패하는 호출(권한 없음 등)로도 
        // kprobe 진입 오버헤드는 측정 가능할 수 있음
        if (settimeofday(&tv, NULL) < 0) {
    // errno만 카운트
    fail++;
} else {
    ok++;
}
    }

    // 측정 종료
    clock_gettime(CLOCK_MONOTONIC, &end);

    total_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    
    printf("Iterations: %d\n", ITERATIONS);
    printf("Total Time: %lld ns\n", total_ns);
    printf("Avg Time per Call: %lld ns\n", total_ns / ITERATIONS);

    return 0;
}
