#include "test_analysis.h"
#include "yyx_common_run.h"
#include <filesystem>


void ClearFilesInDir(const std::string& folder)
{
	for (const auto& entry : std::filesystem::directory_iterator(folder)) {
		std::filesystem::remove_all(entry.path());
	}
}

static void CheckFileExistAndFileType(const std::string& f_path, bool oracle_is_dir)
{
	auto f_status = std::filesystem::status(f_path);
	bool f_e = std::filesystem::exists(f_status);
	if (not f_e) {
		printf("file_or_dir_path %s not exist, please check that, program will exit.", f_path.c_str());
		abort();
	}
	if ((std::filesystem::is_directory(f_path) ^ oracle_is_dir) == 1) {
		printf("file_or_dir_path %s should be file or dir but its type is not consistent, program will exit.", f_path.c_str());
		abort();
	}
}

void CheckTestRunEnvironment(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds,
	const std::string& folder_put_temp_generated_seeds)
{
	CheckFileExistAndFileType(drrun_path, false);
	CheckFileExistAndFileType(yyx_taint_dll_path, false);
	CheckFileExistAndFileType(exe_path, false);
	CheckFileExistAndFileType(folder_put_instr_val_trace, true);
	CheckFileExistAndFileType(folder_put_generated_seeds, true);
	CheckFileExistAndFileType(folder_put_temp_generated_seeds, true);

}

void RunEachFileCollectUniqueBitmap(
	const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds,
	const std::string& folder_put_temp_generated_seeds,
	const std::string& seed_info,
	std::set<std::string>& interesting_seed_sigs,
	std::map<std::string, int>& mutated_seed_count)
{
	// iterate all files in dir_path
	// take each file as seed and run to collect bitmap
	// put unique bitmap and absolute path of seed into result
	for (auto& i : std::filesystem::directory_iterator(folder_put_temp_generated_seeds)) {
//		std::cout << i.path().string() << std::endl;
		YEssenTaintedTrace* yett = RunSeedAndHandleInteresting(drrun_path,
			yyx_taint_dll_path,
			i.path().string(),
			exe_path,
			folder_put_instr_val_trace,
			folder_put_generated_seeds,
			seed_info,
			interesting_seed_sigs,
			mutated_seed_count);
	}

	printf("== interesting_seed_sigs num:%lld.\n", interesting_seed_sigs.size());
}


