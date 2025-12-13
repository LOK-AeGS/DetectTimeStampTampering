# build-cmake/CMakeLists.txt
cmake_minimum_required(VERSION 3.1)
project(GenerateBpfSkeleton NONE)

# bpftool 경로 찾기 (linux-tools-$(uname -r) 설치 필요)
find_program(BPFTOLL_PATH
    NAMES bpftool
    HINTS /usr/bin /usr/sbin /usr/lib/linux-tools/ /usr/local/bin
)
if (NOT BPFTOLL_PATH)
    message(FATAL_ERROR "bpftool not found! Please install linux-tools-$(uname -r).")
endif()

# 1) 입력 .bpf.o 파일 (프로젝트 루트에 있어야 합니다)
set(BPF_OBJECT ${CMAKE_SOURCE_DIR}/probe.bpf.o)

# 2) 출력 스켈레톤 헤더 경로: 반드시 존재하는 CMAKE_CURRENT_BINARY_DIR 사용
set(SKEL_HDR ${CMAKE_CURRENT_BINARY_DIR}/probe.skel.h)

# 3) 스켈레톤 생성 커맨드
add_custom_command(
    OUTPUT ${SKEL_HDR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${BPFTOLL_PATH} gen skeleton ${BPF_OBJECT} > ${SKEL_HDR}
    DEPENDS ${BPF_OBJECT}
    COMMENT "Generating BPF skeleton header: ${SKEL_HDR}"
)

# 4) phony 타깃
add_custom_target(gen_skel ALL
    DEPENDS ${SKEL_HDR}
)
