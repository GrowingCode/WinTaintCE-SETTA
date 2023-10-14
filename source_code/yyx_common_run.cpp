#include "yyx_common_run.h"
#include <fstream>
#include <filesystem>


int TestIndex::generated_test_case_global_idx = 0;

std::string generate_bitmap(YEssenTaintedTrace* curtrace)
{
	std::map<BitmapBlockTransferPath, int> result_bitmap;
	std::string mapstr = "";
	int countnum = 0;
	int jnum = 0;

	for (int i = 0; i < curtrace->tained_slots.size(); i++)
	{
		if (curtrace->tained_slots[i].s->kind == trace_unit_type::is_op_meta)
		{
			countnum++;
			instr* curinstr = (instr*)curtrace->tained_slots[i].s->object;

			if (curinstr->opname.c_str()[0] == 'j')
			{
				BitmapBlockTransferPath curkey;
				jnum++;

				curkey.src_module = curinstr->module_name;
				curkey.src_offset = curinstr->offset;

				if ((curinstr->executed & 1) == 1)
				{
					int handled = 0;
					for (int j = 0; j < curinstr->srcs.size(); j++) {
						opnd* cj_src = curinstr->srcs.at(j);
						if (cj_src->pc_module_name != "") {
							handled++;
							curkey.dst_module = cj_src->pc_module_name;
							curkey.dst_offset = cj_src->pc_offset;
						}
					}
					y_assert(handled == 1, "handled == 1", __FILE__, __LINE__);
				}
				else
				{
					curkey.dst_module = curinstr->module_name;
					curkey.dst_offset = curinstr->offset + curinstr->inst_bytes_size;
				}
				auto it = result_bitmap.find(curkey);
				if (it != result_bitmap.end())
				{
					it->second++;
				}
				else
				{
					result_bitmap[curkey] = 1;
				}
			}
		}
	}

	for (auto iter = result_bitmap.begin(); iter != result_bitmap.end(); iter++)
	{
		const auto& transfer_path = iter->first;
		mapstr += transfer_path.to_string() + ":" + std::to_string(iter->second) + ";";
	}

	return mapstr;
}

std::string execute_and_read_trace(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& seed_path,
	const std::string& folder_put_instr_val_trace)
{
	for (const auto& entry : std::filesystem::directory_iterator(folder_put_instr_val_trace)) {
		std::filesystem::remove_all(entry.path());
	}
	// C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-9.93.19503/bin64/drrun.exe -c C:/HomeSpace/CTaintAnalysis/yyx_taint/build/Release/yyx_taint.dll
	std::string command = drrun_path + " -c " + yyx_taint_dll_path + " -- " + exe_path + " " + seed_path;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPCSTR lpCurrentDirectory = const_cast<char*>(folder_put_instr_val_trace.c_str());

	CreateProcess(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, 0, NULL, lpCurrentDirectory, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	std::string trace_path = "";
	std::filesystem::directory_iterator logfiles(folder_put_instr_val_trace);
	for (const std::filesystem::directory_entry& logfile : logfiles) {
		std::string fstr = logfile.path().filename().string();
		if (YStringUtil::startsWith(fstr, "instr_val_trace.")) {
			y_assert(trace_path == "", "trace_path must empty.", __FILE__, __LINE__);
			trace_path = fstr;
		}
	}

	std::string final_path = folder_put_instr_val_trace + "/" + trace_path;
	return final_path;
}

YEssenTaintedTrace* RunSeedAndHandleInteresting(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& seed_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace, 
	const std::string& folder_put_generated_seeds,
	const std::string& seed_info,
	std::set<std::string>& interesting_seed_sigs,
	std::map<std::string, int>& mutated_seed_count
)
{
	printf("== Running seed info:%s.\n", seed_info.c_str());
	std::string tpath = execute_and_read_trace(drrun_path, yyx_taint_dll_path, exe_path, seed_path, folder_put_instr_val_trace);
	YEssenTaintedTrace* yett = GetEssenTaintedTraceFromFile(tpath);
	std::string sig = generate_bitmap(yett);
	auto it = interesting_seed_sigs.find(sig);
	bool is_interest = false;
	if (it != interesting_seed_sigs.end()) {
		// delete the seed based on seed_path. 
		std::remove(seed_path.c_str());
	}
	else {
		// alsert, here cannot use insert_or_assign, because this function may run existing seeds. 
		mutated_seed_count.insert({ seed_path, 0 });
		interesting_seed_sigs.insert(sig);
		is_interest = true;
	}
	printf("= Paths found:%llu, Seed is interesting:%d.\n", interesting_seed_sigs.size(), is_interest);
	return yett;
}


