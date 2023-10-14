#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <windows.h>

#include "yyx_trace.h"
#include "yyx_engine.h"
#include "yyx_trace_taint.h"
#include "symbolic_execution.h"
#include "taint_fuzzing.h"
#include "yyx_global_info.h"
#include "yyx_taint_test.h"
#include "test_analysis.h"


std::string drrun_path = "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-10.0.0/bin64/drrun.exe";
std::string exe_path = "C:/Users/yangy/source/repos/TestReadFile/x64/Release/TestReadFile.exe";
std::string yyx_taint_dll_path = "C:/HomeSpace/CTaintAnalysis/yyx_taint/build/Release/yyx_taint.dll";
std::string folder_put_instr_val_trace = "C:/HomeSpace/BinaryFuzzTempEnvironment";
std::string folder_put_generated_seeds = "C:/HomeSpace/BinaryFuzzInput";
std::string folder_put_temp_generated_seeds = "C:/HomeSpace/BinaryFuzzTempInput";


//static void unit_test_set(YTaintedTrace* ytt) {
//	{
//		std::map<MCByteID, int> mp;
//		mp.insert({ {0,(1 << 8) + 0},1 });
//		//	mp.insert({{0,(1 << 8) + 1},1});
//		MCByteID k_min(0, (1 << 8) + 0);
//		MCByteID k_max(0, (1 << 8) + 32);
//		bool cover = YMapUtil<MCByteID, int>::specified_range_cover_some_key_in_map(k_min, k_max, mp);
//		printf("cover: %d.\n", cover);
//		y_assert(cover == true, "cover == true", __FILE__, __LINE__);
//	}
//	{
//		std::map<MCByteID, int> mp;
//		mp.insert({ {0,(2 << 8) + 0},1 });
//		//	mp.insert({{0,(1 << 8) + 1},1});
//		MCByteID k_min(0, (1 << 8) + 0);
//		MCByteID k_max(0, (1 << 8) + 32);
//		bool cover = YMapUtil<MCByteID, int>::specified_range_cover_some_key_in_map(k_min, k_max, mp);
//		printf("cover: %d.\n", cover);
//		y_assert(cover == false, "cover == false", __FILE__, __LINE__);
//	}
//
//	uint64_t uv = 0x80f2faa9f8010000;
//	printf("unsigned uv=%llu, ptr uv:%p.\n", uv, reinterpret_cast<byte*>(uv));
//	printf("unsigned uv+1=%llu, ptr uv+1:%p.\n", uv+1, reinterpret_cast<byte*>(uv)+1);
//}

int main(int argc, const char** argv) {
	CheckTestRunEnvironment(drrun_path, yyx_taint_dll_path, exe_path, folder_put_instr_val_trace, 
		folder_put_generated_seeds, folder_put_temp_generated_seeds);
//	YTrace* yte = new YTrace();
	// logic of taint analysis.
//	YTaint* yt = new YTaint(yte);
//	YTaintedTrace* ytt = new YTaintedTrace(yt);
//	YEssenTaintedTrace* yett = new YEssenTaintedTrace(ytt);
	//	unit_test_set(&ytt);

//	test_main();

//	YEssenTaintedTrace* yett = GetEssenTaintedTraceFromFile("C:/HomeSpace/CTaintAnalysis/yyx_taint/run-env/jpeg_trace/instr_val_trace.test_jpeg.exe.369556.0000.log");
	YEssenTaintedTrace* yett = GetEssenTaintedTraceFromFile("C:/HomeSpace/CTaintAnalysis/yyx_taint/run-env/test_read_file_trace/instr_val_trace.TestReadFile.exe.327120.0000.log");
	OneTraceSymbolicExecution(yett, folder_put_temp_generated_seeds);

	//std::set<std::string> interesting_seed_sigs;
	//std::map<std::string, int> mutated_seed_count;
	//RunEachFileCollectUniqueBitmap(drrun_path, yyx_taint_dll_path, exe_path,
	//	folder_put_instr_val_trace, folder_put_generated_seeds, 
	//	folder_put_temp_generated_seeds,
	//	"run generated seed.",
	//	interesting_seed_sigs, mutated_seed_count);

//	TaintSymbolicMain(drrun_path, yyx_taint_dll_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, folder_put_temp_generated_seeds);
//	TaintFuzzingMain(drrun_path, yyx_taint_dll_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds);

	return 0;
}



