#pragma once
#include <string>
#include <map>
#include <set>

void ClearFilesInDir(const std::string& folder);

void CheckTestRunEnvironment(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds,
	const std::string& folder_put_temp_generated_seeds);

// for result, the map key is bitmap string, the map value is absolute path of seed. 
void RunEachFileCollectUniqueBitmap(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds,
	const std::string& input_dir_path,
	const std::string& seed_info,
	std::set<std::string>& interesting_seed_sigs, 
	std::map<std::string, int>& mutated_seed_count);


