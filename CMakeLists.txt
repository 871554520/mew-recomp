cmake_minimum_required(VERSION 3.20)
project(mew_recomp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 阶段 1：指令直方图扫描器
find_path(ZYDIS_INCLUDE_DIR Zydis/Zydis.h)
find_library(ZYDIS_LIBRARY NAMES Zydis zydis)
add_executable(isa_histogram tools/isa_histogram.cpp)
if (ZYDIS_INCLUDE_DIR AND ZYDIS_LIBRARY)
  target_include_directories(isa_histogram PRIVATE ${ZYDIS_INCLUDE_DIR})
  target_link_libraries(isa_histogram PRIVATE ${ZYDIS_LIBRARY})
else()
  message(WARNING "Zydis not found; isa_histogram will fail to link")
endif()
