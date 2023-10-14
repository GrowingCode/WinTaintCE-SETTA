#pragma once

#include <string>
#include "yyx_engine.h"
#include "yyx_trace_taint.h"
#include "yyx_common_run.h"
#include "trace_analysis.h"
#include "yyx_global_info.h"

//YEssenTaintedTrace* RunSeedAndHandleInteresting(const std::string& drrun_path,
//	const std::string& seed_path,
//	const std::string& exe_path,
//	const std::string& folder_put_instr_val_trace, const std::string& folder_put_generated_seeds,
//	const std::string& seed_info);

#define NeedNewSeedMinimumThreshold 5

class ConsecutiveMCBytes {

public:

	size_t instr_index;
	MCByteID start;
	MCByteID end_inclusive;

	ConsecutiveMCBytes(size_t instr_index, MCByteID start, MCByteID end_inclusive) {
		this->instr_index = instr_index;
		this->start = start;
		this->end_inclusive = end_inclusive;
	}

	~ConsecutiveMCBytes() {
	}

	bool operator < (const ConsecutiveMCBytes& order) const {
		if ((instr_index < order.instr_index)
			|| (instr_index == order.instr_index) && (start < order.start)
			|| (instr_index == order.instr_index) && (start == order.start) && (end_inclusive < order.end_inclusive)) {
			return true;
		}
		return false;
	}

};

class TempConsecutiveTraceableByteTaintSetPosition {

public:
	TraceableByteTaintSetPosition start;
	TraceableByteTaintSetPosition curr_end;

	TempConsecutiveTraceableByteTaintSetPosition(TraceableByteTaintSetPosition start, TraceableByteTaintSetPosition curr_end) {
		this->start = start;
		this->curr_end = curr_end;
	}

	int get_consecutive_length() const {
		y_assert(curr_end.instr_index_which_set_dst_byte == start.instr_index_which_set_dst_byte, "set byte instr index wrong.", __FILE__, __LINE__);
		y_assert(curr_end.bid.byte_type == start.bid.byte_type, "bid type wrong.", __FILE__, __LINE__);
		return curr_end.bid.reg_id_or_mem_or_imm_with_byte_offset - start.bid.reg_id_or_mem_or_imm_with_byte_offset + 1;
	}

	~TempConsecutiveTraceableByteTaintSetPosition() {

	}

};

class ChangableContentLocation {
	
public:
	FileReadContent* frc = NULL;
	// changable_data_addr must be in range of FileReadContent's addr and rlen. 
	byte* changable_data_addr = NULL;
	
	ChangableContentLocation(FileReadContent* frc) {
		this->frc = frc;
	}

	void apply_modification(byte val) {
		*changable_data_addr = val;
	}

	std::string to_string() {
		int64_t offset = changable_data_addr - frc->addr;
		return std::to_string(offset) + ":" + std::to_string(*changable_data_addr) + ",";
	}

	~ChangableContentLocation() {

	}

};

//enum keykinds
//{
//	jtodstk,
//	jnextk,
//};

enum mutate_data_type {
	m_unknown,
	m_int,
	m_float,
	m_double,
};

mutate_data_type get_opnd_data_type_according_to_branch_depend_opname(std::string opname);

//std::string generate_bitmap(YEssenTaintedTrace* curtrace);

void find_file_data_offset_from_byte_taint_origin_info(YEssenTaintedTrace* yett, TraceableByteTaintSetPosition& tbtsp, ChangableContentLocation* cc);

void TaintFuzzingMain(const std::string& drrun_path,
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds);
// std::string to_test_exe_path

void find_consecutive_corresponding_bytes(InstrTaintRootInfo* depend_ss_itri, std::vector<MCByteID>& src_bts, std::vector<TempConsecutiveTraceableByteTaintSetPosition>& tctbtsp_vect);

// YEssenTaintedTrace* RunSeedAndHandleInteresting(const std::string& drrun_path, const std::string& seed_path, const std::string& exe_path, const std::string& folder_put_instr_val_trace, const std::string& folder_put_generated_seeds, const std::string& seed_info);

//void MutateManyRoundsForBinpartSearch(const std::string& drrun_path, const std::string& exe_path,
//	const std::string& folder_put_instr_val_trace, const std::string& folder_put_generated_seeds,
//	YEssenTaintedTraceWithAnalysisInfo* start_yettwai,
//	InstrID instr_id, int same_instr_index,
//	ChangableContentLocation* cc, int data_size, mutate_data_type data_type);

// std::map<InstrID, std::pair<std::vector<instr*>*, std::vector<instr*>*>> ComputeTraceDifference(YEssenTaintedTrace* t1, YEssenTaintedTrace* t2);
// std::map<InstrID, std::pair<std::vector<InstrValDifference>*, std::vector<InstrValDifference>*>> ComputeTraceValDifference(std::map<InstrID, std::pair<std::vector<instr*>*, std::vector<instr*>*>> res);
// std::map<InstrID, std::vector<Trend>*> ComputeTrendOfDiffference(std::map<InstrID, std::pair<std::vector<InstrValDifference>*, std::vector<InstrValDifference>*>> TraceValDifference);

template<typename V>
class Mutator {

public:

	const std::string& drrun_path;
	const std::string& yyx_dll_path;
	const std::string& exe_path;
	const std::string& folder_put_instr_val_trace;
	const std::string& folder_put_generated_seeds;

	std::set<std::string>& interesting_seed_sigs;
	std::map<std::string, int>& mutated_seed_count;
	
	InstrID instr_id;
	int same_instr_index;
	int opnd_index;
	ChangableContentLocation* cc;
	int mutate_byte_size;
	mutate_data_type data_type;
//	YEssenTaintedTraceWithAnalysisInfo* origin_yett;
	V origin_val;
	InstrValDifference origin_diff;

	Mutator(const std::string& drrun_path, const std::string& yyx_dll_path, const std::string& exe_path,
		const std::string& folder_put_instr_val_trace, const std::string& folder_put_generated_seeds,
		std::set<std::string>& interesting_seed_sigs, std::map<std::string, int>& mutated_seed_count,
		InstrID instr_id, int same_instr_index, int opnd_index, ChangableContentLocation* cc, int mutate_byte_size,
		mutate_data_type data_type, YEssenTaintedTraceWithAnalysisInfo* origin_yett) : drrun_path(drrun_path), 
		yyx_dll_path(yyx_dll_path), exe_path(exe_path), folder_put_instr_val_trace(folder_put_instr_val_trace), 
		folder_put_generated_seeds(folder_put_generated_seeds), interesting_seed_sigs(interesting_seed_sigs), 
		mutated_seed_count(mutated_seed_count)
	{
		this->instr_id = instr_id;
		this->same_instr_index = same_instr_index;
		this->opnd_index = opnd_index;
		this->cc = cc;
		this->mutate_byte_size = mutate_byte_size;
		this->data_type = data_type;
//		this->origin_yett = origin_yett;
		memcpy_s(&this->origin_val, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
		this->origin_diff = YTraceAnalysisUtil::GetTraceOneInstrPairDiff(instr_id, same_instr_index, origin_yett);
	}

	// use the opposite val in origin InstrValDifference as the end guess val. 
	void MutateToSearch() {
		std::string bm_info = std::to_string(origin_val);
		printf("==@ Begin mutation original seed value:%s.\n", bm_info.c_str());

		V direct_set_end_val;
		byte* val_ptr = this->origin_diff.vals[1 - opnd_index].val;
		memcpy_s(&direct_set_end_val, mutate_byte_size, val_ptr, mutate_byte_size);
		MutateDirectSetInitialEndValToSearch(direct_set_end_val);
		
		V inv_direct = origin_val < direct_set_end_val ? -1 : 1;
		MutateIncrementInitialOriginValToSetInitialEndValToSearch(inv_direct);
	}
	
	void MutateIncrementInitialOriginValToSetInitialEndValToSearch(V guess_inc_val) {
		V guess_end_val = origin_val + guess_inc_val;
		if (is_overflow(guess_end_val, origin_val)) {
			if (guess_inc_val > 0) {
				guess_end_val = (std::numeric_limits<V>::max)();
			} else if (guess_inc_val < 0) {
				guess_end_val = (std::numeric_limits<V>::lowest)();
			}
			else {
				y_assert(false, "guess_inc_val must not 0.", __FILE__, __LINE__);
			}
		}
		MutateDirectSetInitialEndValToSearch(guess_end_val);
	}

	Trend RunOneNextStep(V next_step_gap, OneDirectSearch<V>* od_search, std::map<V, InstrValDifference>& tried_val_diff) {
		Trend td;
		std::tuple<bool, V, V> next_step = od_search->compute_next_step_info(next_step_gap);
		//			std::pair<V, V> next_step = od_search->compute_next_step_info();
		if (std::get<0>(next_step)) {
			auto first_it = tried_val_diff.find(std::get<1>(next_step));
			y_assert(first_it != tried_val_diff.end(), "first_it != tried_val_diff.end()", __FILE__, __LINE__);
			InstrValDifference new_vdiff = RunSeedAndGetValDiff(std::get<2>(next_step));
			td = YTraceCompareUtil::ComputeOneValDiffPairTrend(first_it->second, new_vdiff);
			tried_val_diff.insert({ std::get<2>(next_step), new_vdiff });
		}
		return td;
	}

	void MutateDirectSetInitialEndValToSearch(V guess_end_val) {
		OneDirectSearch<V>* od_search = new OneDirectSearch<V>(origin_val, guess_end_val);
		Trend td;
		std::map<V, InstrValDifference> tried_val_diff;
		tried_val_diff.insert({ origin_val, origin_diff });
//		std::tuple<bool, V, V> next_step(0, 0, 0);
		do {
			// one direction search phase.
			td = RunOneNextStep(0, od_search, tried_val_diff);
			printf("==! Trend after one direct search try:%s.\n", Trend::get_trend_desc(td).c_str());
		} while (td.oet == TrendType::MoveToFlipButNotFlip);// std::get<0>(next_step) and 
		if (td.oet == TrendType::MoveToFlipButFlipToEqual) {
			// try to add random some data. 
			RunOneNextStep(1, od_search, tried_val_diff);
			printf("==! Trend no care, just next direction random try.\n");
			RunOneNextStep(1000, od_search, tried_val_diff);
			printf("==! Trend no care, just next direction random try.\n");
		}
		else if (td.oet == TrendType::MoveToFlipButFlip) {
			// begin binary search.
			auto start_it = tried_val_diff.find(od_search->curr_start);
			y_assert(start_it != tried_val_diff.end(), "start_it != tried_val_diff.end()", __FILE__, __LINE__);
			auto end_it = tried_val_diff.find(od_search->curr_end_inclusive);
			y_assert(end_it != tried_val_diff.end(), "end_it != tried_val_diff.end()", __FILE__, __LINE__);
			BinPartSearch<V>* bp_search = new BinPartSearch<V>(od_search->curr_start, start_it->second, od_search->curr_end_inclusive, end_it->second);
			bool ctn = true;
			while (ctn) {
				std::pair<bool, V> mid = bp_search->get_curr_mid();
				if (mid.first) {
					// mid value is valid. 
					InstrValDifference mid_vdiff = RunSeedAndGetValDiff(mid.second);
					std::tuple<bool, bool, bool> can_decide = bp_search->update_start_end_based_on_mid(mid.second, mid_vdiff);
					if (std::get<0>(can_decide)) {
						// continue;
						if (std::get<1>(can_decide)) {
							printf("==! Trend after binary direct search:fall_in_left_to_mid,left:%s,mid:%s.\n", std::to_string(bp_search->curr_start).c_str(), std::to_string(bp_search->curr_end_exclusive).c_str());
						}
						else {
							y_assert(std::get<2>(can_decide), "trend must be decided,", __FILE__, __LINE__);
							printf("==! Trend after binary direct search:fall_in_mid_to_right,mid:%s,right:%s.\n", std::to_string(bp_search->curr_start).c_str(), std::to_string(bp_search->curr_end_exclusive).c_str());
						}
					}
					else {
						// stop. 
						ctn = false;
					}
				}
				else {
					// stop. 
					ctn = false;
				}
			}
		}
		else if (td.oet == TrendType::NotMoveToFlip) {
			// stop.
		}
		else if (td.oet == TrendType::NotChange) {
			// stop.
		}
		else if (td.oet == TrendType::NoTrend) {
			// stop. 
		}
		else {
//			y_assert();
			y_assert(false, "trend wrong.", __FILE__, __LINE__);// || (not std::get<0>(next_step))
		}

		delete od_search;
	}

	InstrValDifference RunSeedAndGetValDiff(V mutated_val) {
		std::string guided_binpart_mutated_info = "guided_binpart_mutated_value:";
		// mutate seed according to increment. 
		int64_t offset = cc->changable_data_addr - cc->frc->addr;
		y_assert(offset >= 0, "offset >= 0, but wrong.", __FILE__, __LINE__);
		FileReadContent* mutate_seed = new FileReadContent(cc->frc);
		
		guided_binpart_mutated_info += "mutated:" + std::to_string(mutated_val);
		memcpy_s(mutate_seed->addr + offset, mutate_byte_size, &mutated_val, mutate_byte_size);
		
		std::string mutated_seed_path = folder_put_generated_seeds + "/" + std::to_string(TestIndex::generated_test_case_global_idx);
		TestIndex::generated_test_case_global_idx++;
		YFileUtil::write_whole_file(mutated_seed_path, mutate_seed);

		delete mutate_seed;

		YEssenTaintedTrace* t2 = RunSeedAndHandleInteresting(drrun_path, yyx_dll_path, mutated_seed_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, guided_binpart_mutated_info, interesting_seed_sigs, mutated_seed_count);
		YEssenTaintedTraceWithAnalysisInfo* t2_wai = new YEssenTaintedTraceWithAnalysisInfo(t2);

		InstrValDifference diff = YTraceAnalysisUtil::GetTraceOneInstrPairDiff(instr_id, same_instr_index, t2_wai);
		return diff;
	}
	
	//static Trend RunSeedAndComputeTrend(
	//	int64_t origin_val, 
	//	int64_t mutated_val, 
	//	YEssenTaintedTraceWithAnalysisInfo* last_trace, YEssenTaintedTraceWithAnalysisInfo** new_trace) {

	//	std::string guided_binpart_mutated_info = "guided_binpart_mutated_value:";
	//	// mutate seed according to increment. 
	//	int64_t offset = changable_data_addr->changable_data_addr - changable_data_addr->frc->addr;
	//	y_assert(offset >= 0);
	//	FileReadContent* mutate_seed = new FileReadContent(changable_data_addr->frc);
	//	if (data_type == m_int) {
	//		guided_binpart_mutated_info += "origin:" + std::to_string(origin_val) + ",mutated:" + std::to_string(mutated_val);
	//		memcpy_s(mutate_seed->addr + offset, mutate_byte_size, &mutated_val, mutate_byte_size);
	//	}
	//	else if (data_type == m_float) {
	//		if (mutate_byte_size == 4) {
	//			guided_binpart_mutated_info += "origin:" + std::to_string(origin_val_fp) + ",mutated:" + std::to_string(mutated_val_fp);
	//			memcpy_s(mutate_seed->addr + offset, mutate_byte_size, &mutated_val_fp, mutate_byte_size);
	//		}
	//		else if (mutate_byte_size == 8) {
	//			guided_binpart_mutated_info += "origin:" + std::to_string(origin_val_db) + ",mutated:" + std::to_string(mutated_val_db);
	//			memcpy_s(mutate_seed->addr + offset, mutate_byte_size, &mutated_val_db, mutate_byte_size);
	//		}
	//		else {
	//			printf("strange! float byte not correspond size,4 or 8?\n");
	//			y_assert(false);
	//		}
	//	}

	//	std::string mutated_seed_path = folder_put_generated_seeds + "/" + std::to_string(generated_test_case_global_idx);
	//	generated_test_case_global_idx++;
	//	YFileUtil::write_whole_file(mutated_seed_path, mutate_seed);

	//	delete mutate_seed;

	//	YEssenTaintedTrace* t2 = RunSeedAndHandleInteresting(drrun_path, mutated_seed_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, guided_binpart_mutated_info);
	//	YEssenTaintedTraceWithAnalysisInfo* t2_wai = new YEssenTaintedTraceWithAnalysisInfo(t2);

	//	*new_trace = t2_wai;

	//	//std::map<InstrID, std::vector<Trend>*>* trends = YTraceCompareUtil::ComputeTraceTrend(last_trace, t2_wai);
	//	//Trend trend;
	//	//auto iter = trends->find(instr_id);
	//	//if (iter != trends->end()) {
	//	//	std::vector<Trend>* targetVector = iter->second;
	//	//	if (same_instr_index < targetVector->size()) {
	//	//		trend = targetVector->at(same_instr_index);
	//	//	}
	//	//}

	//	Trend trend = YTraceCompareUtil::ComputeTraceOneInstrPairTrend(instr_id, same_instr_index, last_trace, t2_wai);

	//	return trend;
	//}

	~Mutator() {

	}

};








