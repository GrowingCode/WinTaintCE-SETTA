cmake_minimum_required(VERSION 3.20)
project(yyx_trace_taint)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
# specify C++20 version
set(CMAKE_CXX_STANDARD 20)

SET(VCKPG_PATH "C:/Users/86187/vcpkg" CACHE STRING "select build cpu type")
message("= In Use VCKPG_PATH:" ${VCKPG_PATH} ", if it is not desired, you should use -DVCKPG_PATH=\"your path\" to set up.")
SET(triton_lib_path "/packages/triton_x64-windows/lib/triton.lib")
string(PREPEND triton_lib_path ${VCKPG_PATH})
message("= In Use triton_lib_path:" ${triton_lib_path})
SET(triton_include_path "/packages/triton_x64-windows/include")
string(PREPEND triton_include_path ${VCKPG_PATH})
message("= In Use triton_include_path:" ${triton_include_path})
SET(z3_include_path "/packages/z3_x64-windows/include")
string(PREPEND z3_include_path ${VCKPG_PATH})
message("= In Use z3_include_path:" ${z3_include_path})

add_executable(yyx_trace_taint root_main.cpp yyx_trace_taint.cpp yyx_engine.cpp yyx_trace.cpp taint_fuzzing.cpp symbolic_execution.cpp trace_analysis.cpp yyx_global_info.cpp yyx_taint_detail.cpp yyx_taint_test.cpp test_analysis.cpp yyx_common_run.cpp)
target_include_directories(yyx_trace_taint PUBLIC ${triton_include_path} PUBILC ${z3_include_path})
target_link_libraries(yyx_trace_taint PUBLIC ${triton_lib_path})









