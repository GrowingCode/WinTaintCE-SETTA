#pragma once

#include <vector>
#include "yyx_trace.h"
#include "yyx_engine.h"

#include <triton/context.hpp>
#include <triton/ast.hpp>
#include <triton/x86Specifications.hpp>

void OneTraceSymbolicExecution(YEssenTaintedTrace* yett, const std::string& folder_put_temp_generated_seeds);
void TaintSymbolicMain(const std::string& drrun_path, const std::string& yyx_taint_dll_path,
	const std::string& exe_path, const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds, const std::string& folder_put_temp_generated_seeds);

class TritonPrintUtil {

public:

	static void print_uint512_to_console(triton::uint512 val) {
		byte* vb = (byte*)  & val;
		for (int i = 0; i < 64; i++) {
			printf("%d:%d,", i, *(vb+i));
		}
		printf("\n");
	}

	static void print_uint512_to_buffer(triton::uint512 val, char* origin_buf, int origin_buf_size) {
		byte* vb = (byte*)&val;
		char* buf = origin_buf;
		int remain_buf_size = origin_buf_size;
		for (int i = 0; i < 64; i++) {
			int c = snprintf(buf, remain_buf_size, "%u:%u,", i, *(vb + i));
			buf += c;
			remain_buf_size -= c;
			y_assert(remain_buf_size >= 0, "remain_buf_size >= 0, but wrong.", __FILE__, __LINE__);
		}
	}

};


