#pragma once

#include <string>
#include <set>
#include <map>

#include "yyx_trace.h"
#include "yyx_engine.h"
#include "trace_analysis.h"
#include "yyx_trace_taint.h"


template<typename K, typename V>
struct compare_value_in_map
{
	bool operator()(const std::pair<K, V>& left, const std::pair<K, V>& right) const
	{
		return left.second < right.second;
	}
};

class TestIndex {
public:

	static int generated_test_case_global_idx;

};

class BitmapBlockTransferPath
{
public:
	//	int keykind;
	std::string src_module;
	uint64_t src_offset = 0;
	std::string dst_module;
	uint64_t dst_offset = 0;

	//	uint64_t jtodst1;
	//	std::string jtodst2;
	//	uint64_t jnext1;
	//	uint64_t jnext2;

	BitmapBlockTransferPath()
	{
		//		keykind = -1;
		//		jtodst1 = 0;
		//		jtodst2 = "";
		//		jnext1 = 0;
		//		jnext2 = 0;
	}

	std::string to_string() const {
		std::string res = src_module + "_" + std::to_string(src_offset) + "_" + dst_module + "_" + std::to_string(dst_offset);
		return res;
	}

	bool operator <(const BitmapBlockTransferPath& b) const {
		bool src_less = (src_module < b.src_module) || (src_module == b.src_module and src_offset < b.src_offset);
		bool src_equal = (src_module == b.src_module) and (src_offset == b.src_offset);
		bool dst_less = (dst_module < b.dst_module) || (dst_module == b.dst_module and dst_offset < b.dst_offset);

		if (src_less) {
			return true;
		}
		else if (src_equal) {
			return dst_less;
		}
		else {
			return false;
		}
		/*
		if (keykind < b.keykind)
		{
			return true;
		}
		else if (keykind > b.keykind)
		{
			return false;
		}
		else
		{
			// keykind == b.keykind
			if (keykind == keykinds::jtodstk)
			{
				return (jtodst1 < b.jtodst1) || (jtodst1 == b.jtodst1 && jtodst2 < b.jtodst2);
				//return false;
			}
			else if (keykind == keykinds::jnextk)
			{
				if (jnext1 < b.jnext1)
				{
					return true;
				}
				return false;
			}
			else {
				assert(false);
				return false;
			}
		}
		*/
	}
};

std::string execute_and_read_trace(const std::string& drrun_path, const std::string& yyx_taint_dll_path,
	const std::string& exe_path, const std::string& seed_path, const std::string& folder_put_instr_val_trace);

YEssenTaintedTrace* RunSeedAndHandleInteresting(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& seed_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace, 
	const std::string& folder_put_generated_seeds,
	const std::string& seed_info,
	std::set<std::string>& interesting_seed_sigs,
	std::map<std::string, int>& mutated_seed_count);


