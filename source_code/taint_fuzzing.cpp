#include "taint_fuzzing.h"
#include "yyx_trace.h"
#include "yyx_engine.h"
#include "trace_analysis.h"
#include "yyx_trace_taint.h"
#include "test_analysis.h"

#include <map>
#include <string>
#include <iomanip>
#include <cstdint>
#include <bitset>
#include <iostream>
#include <stdlib.h>
#include <sstream>
#include <windows.h>
#include <limits>
#include <tchar.h>
#include <atlstr.h>
#include <vector>
#include <random>
#include <filesystem>

mutate_data_type get_opnd_data_type_according_to_branch_depend_opname(std::string opname) {
	mutate_data_type mdt = m_unknown;
	if (opname == "cmp" || opname == "test") {
		mdt = m_int;
	}
	else if (opname == "comiss") {
		mdt = m_float;
	}
	else if (opname == "comisd") {
		mdt = m_double;
	}
	else {
		y_assert(false, "unknown opname: " + opname + ".", __FILE__, __LINE__);
	}
	return mdt;
}

//void MutateAccordingToDependInstruction(
//	std::string drrun_path, std::string exe_path, std::string folder_put_instr_val_trace, std::string folder_put_generated_seeds,
//	InstrID instr_id, int same_instr_index,
//	ChangableContentLocation* cc, int mutate_byte_size, mutate_data_type data_type, int initial_inc_value,
//	YEssenTaintedTraceWithAnalysisInfo* origin_yett) {
//	y_assert(initial_inc_value != 0);
//	
//	int64_t origin_val = 0;
//	float origin_val_fp = 0;
//	double origin_val_db = 0;
//
//	InstrValDifference origin_diff = YTraceAnalysisUtil::GetTraceOneInstrPairDiff(instr_id, same_instr_index, origin_yett);
//	
//	if (data_type == m_int) {
//		memcpy_s(&origin_val, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//		OneDirectSearch<int64_t>* od_search = new OneDirectSearch<int64_t>(origin_val, );
//		
//	}
//	else if (data_type == m_float) {
//		if (mutate_byte_size == 4) {
//			memcpy_s(&origin_val_fp, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//			OneDirectSearch<int64_t>* od_search = new OneDirectSearch<int64_t>(origin_val_fp, );
//
//		}
//		else if (mutate_byte_size == 8) {
//			memcpy_s(&origin_val_db, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//			OneDirectSearch<int64_t>* od_search = new OneDirectSearch<int64_t>(origin_val_db, );
//			
//		}
//		else {
//			printf("strange! float byte not correspond size,4 or 8?\n");
//			y_assert(false);
//		}
//	}
//
//	//int64_t sign = initial_inc_value > 0 ? 1 : -1;
//
//	//Trend trend;
//
//	//// the following must be ensured to be positive. 
//	//int64_t left = 0;
//	//int64_t right = sign * origin_diff.;
//	//float left_fp = 0;
//	//float right_fp = sign * initial_inc_value;
//	//double left_db = 0;
//	//double right_db = sign * initial_inc_value;
//
//	//int64_t left_min = 0;
//	//int64_t right_max = 0;
//	//if (mutate_byte_size == 1) {
//	//	left_min = (std::numeric_limits<char>::min)();
//	//	right_max = (std::numeric_limits<char>::max)();
//	//}
//	//else if (mutate_byte_size == 2) {
//	//	left_min = (std::numeric_limits<short>::min)();
//	//	right_max = (std::numeric_limits<short>::max)();
//	//}
//	//else if (mutate_byte_size == 4) {
//	//	left_min = (std::numeric_limits<int>::min)();
//	//	right_max = (std::numeric_limits<int>::max)();
//	//}
//	//else if (mutate_byte_size == 8) {
//	//	left_min = (std::numeric_limits<int64_t>::min)();
//	//	right_max = (std::numeric_limits<int64_t>::max)();
//	//}
//	//else {
//	//	y_assert(false);
//	//}
//	//constexpr float left_fp_min = (std::numeric_limits<float>::min)();
//	//constexpr float right_fp_max = (std::numeric_limits<float>::max)();
//	//constexpr double left_db_min = (std::numeric_limits<double>::min)();
//	//constexpr double right_db_max = (std::numeric_limits<double>::max)();
//
//	if (data_type == m_int) {
//		memcpy_s(&origin_val, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//	}
//	else if (data_type == m_float) {
//		if (mutate_byte_size == 4) {
//			memcpy_s(&origin_val_fp, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//		}
//		else if (mutate_byte_size == 8) {
//			memcpy_s(&origin_val_db, mutate_byte_size, cc->changable_data_addr, mutate_byte_size);
//		}
//		else {
//			printf("strange! float byte not correspond size,4 or 8?\n");
//			y_assert(false);
//		}
//	}
//
//	int64_t remain_val = 0;
//	float remain_val_fp = 0;
//	double remain_val_db = 0;
//	if (sign == 1) {
//		remain_val = origin_val >= 0 ? right_max - origin_val : right_max;
//		remain_val_fp = origin_val_fp >= 0 ? right_fp_max - origin_val_fp : right_fp_max;
//		remain_val_db = origin_val_db >= 0 ? right_db_max - origin_val_db : right_db_max;
//	}
//	else if (sign == -1) {
//		remain_val = origin_val >= 0 ? left_min : origin_val - left_min;
//		remain_val_fp = origin_val_fp >= 0 ? left_fp_min : origin_val_fp - left_fp_min;
//		remain_val_db = origin_val_db >= 0 ? left_db_min : origin_val_db - left_db_min;
//	}
//	else {
//		y_assert(false);
//	}
//	y_assert(remain_val >= 0 and remain_val_fp >= 0 and remain_val_db >= 0);
//
//	int count = 0;
//	int flag = 0;
//
//	int64_t mutated_val = 0;
//	float mutated_val_fp = 0;
//	double mutated_val_db = 0;
//
//	int64_t prev_mutated_val = 0;
//	float prev_mutated_val_fp = 0;
//	double prev_mutated_val_db = 0;
//	
//	YEssenTaintedTraceWithAnalysisInfo* last_yett = origin_yett;
//	YEssenTaintedTraceWithAnalysisInfo* new_yett = NULL;
//	YEssenTaintedTraceWithAnalysisInfo* to_delete_yett = NULL;
//	// Done. terminal condition not sufficient, will lead to infinite loop, need to judge whether the increment is equal to the last.
//	while (trend.oet != TrendType::MoveToFlipButFlipToEqual) {
//		count++;
//
//		mutated_val = origin_val;
//		mutated_val_fp = origin_val_fp;
//		mutated_val_db = origin_val_db;
//
//		if (flag == 0)
//		{
//			// Done. must use mutate_byte_size to identify the max value which does not overflow, otherwise left < right, core dump in this case. 
//			// get value of curr and add sign * right to judge whether exceeding the max. 
//			if (data_type == m_int) {
//				if (right < remain_val) {
//					int64_t inc_possible = remain_val - right;
//					mutated_val += sign * (inc_possible >= right ? right : inc_possible);
//				}
//				else {
//					y_assert(right == remain_val);
//					break;
//				}
//			}
//			else if (data_type == m_float) {
//				if (mutate_byte_size == 4) {
//					if (right_fp < remain_val_fp) {
//						float inc_possible_fp = remain_val_fp - right_fp;
//						mutated_val_fp += sign * (inc_possible_fp >= right_fp ? right_fp : inc_possible_fp);
//					}
//					else {
//						y_assert(right_fp == remain_val_fp);
//						break;
//					}
//				}
//				else if (mutate_byte_size == 8) {
//					if (right_db < remain_val_db) {
//						double inc_possible_db = remain_val_db - right_db;
//						mutated_val_db += sign * (inc_possible_db >= right_db ? right_db : inc_possible_db);
//					}
//					else {
//						y_assert(right_db == remain_val_db);
//						break;
//					}
//				}
//				else {
//					printf("strange! float byte not correspond size,4 or 8?\n");
//					y_assert(false);
//				}
//			}
//
//			trend = MutateSeedToGenarateTrace(drrun_path, exe_path, folder_put_generated_seeds, 
//				folder_put_instr_val_trace, instr_id, same_instr_index, cc, mutate_byte_size, data_type, 
//				origin_val, origin_val_fp, origin_val_db, mutated_val, mutated_val_fp, mutated_val_db, 
//				last_yett, &new_yett);
//
//			if (trend.oet == TrendType::MoveToFlipButNotFlip) {
//				left = right;
//				left_fp = right_fp;
//				left_db = right_db;
//			}
//			else if (trend.oet == TrendType::NotMoveToFlip) {
//				flag = 1;
//			}
//		}
//		else if (flag == 1) {
//			mutated_val += sign * (left + right) / 2;
//			mutated_val_fp += sign * (left_fp + right_fp) / 2;
//			mutated_val_db += sign * (left_db + right_db) / 2;
//
//			trend = MutateSeedToGenarateTrace(drrun_path, exe_path, folder_put_generated_seeds, 
//				folder_put_instr_val_trace, instr_id, same_instr_index, cc, mutate_byte_size, data_type, 
//				origin_val, origin_val_fp, origin_val_db, mutated_val, mutated_val_fp, mutated_val_db, 
//				last_yett, &new_yett);
//
//			if (trend.oet == TrendType::MoveToFlipButNotFlip) {
//				right = (left + right) / 2;
//				right_fp = (left_fp + right_fp) / 2;
//				right_db = (left_db + right_db) / 2;
//			}
//			else if (trend.oet == TrendType::NotMoveToFlip) {
//				left = (left + right) / 2;
//				left_fp = (left_fp + right_fp) / 2;
//				left_db = (left_db + right_db) / 2;
//			}
//		}
//
//		if (data_type == m_int) {
//			if (prev_mutated_val == mutated_val) {
//				break;
//			}
//		}
//		else if (data_type == m_float) {
//			// Done. the precision must be identified, actually, must preset by human. if (mutate_byte_size == 4) {
//			if (mutate_byte_size == 4) {
//				if (abs(prev_mutated_val_fp - mutated_val_fp) < 0.00001) {
//					break;
//				}
//			}
//			else if (mutate_byte_size == 8) {
//				if (abs(prev_mutated_val_db - mutated_val_db) < 0.00000001) {
//					break;
//				}
//			}
//			else {
//				printf("strange! float byte not correspond size,4 or 8?\n");
//				y_assert(false);
//			}
//		}
//		
//		prev_mutated_val = mutated_val;
//		prev_mutated_val_fp = mutated_val_fp;
//		prev_mutated_val_db = mutated_val_db;
//
//		if (to_delete_yett != NULL) {
//			delete to_delete_yett;
//			to_delete_yett = NULL;
//		}
//
//		last_yett = new_yett;
//		to_delete_yett = new_yett;
//	}
//
//	if (to_delete_yett != NULL) {
//		delete to_delete_yett;
//	}
//}

void MutateManyRoundsForBinpartSearch(const std::string& drrun_path, 
	const std::string& yyx_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace, 
	const std::string& folder_put_generated_seeds,
	std::set<std::string>& interesting_seed_sigs,
	std::map<std::string, int>& mutated_seed_count,
	YEssenTaintedTraceWithAnalysisInfo* start_yettwai,
	InstrID instr_id, int same_instr_index, int opnd_index,
	ChangableContentLocation* cc, int data_size, mutate_data_type data_type)
{
	// Done. remember to judge whether interesting and put the interesting to a global set. 
//	YEssenTaintedTrace* origin_yett = RunSeedAndHandleInteresting(drrun_path, origin_seed_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds);
//	YEssenTaintedTraceWithAnalysisInfo* origin_yettwai = new YEssenTaintedTraceWithAnalysisInfo(origin_yett);
//	MutateAccordingToDependInstruction(drrun_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, instr_id, same_instr_index, cc, data_size, data_type, 1, start_yettwai);
//	MutateAccordingToDependInstruction(drrun_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, instr_id, same_instr_index, cc, data_size, data_type, -1, start_yettwai);
	
	if (data_type == m_int) {
		if (data_size == 1) {
			Mutator<char> mt(drrun_path, yyx_dll_path, exe_path,
				folder_put_instr_val_trace, folder_put_generated_seeds,
				interesting_seed_sigs, mutated_seed_count,
				instr_id, same_instr_index, opnd_index, cc, data_size,
				data_type, start_yettwai);
			mt.MutateToSearch();
		}
		else if (data_size == 2) {
			Mutator<short> mt(drrun_path, yyx_dll_path, exe_path,
				folder_put_instr_val_trace, folder_put_generated_seeds,
				interesting_seed_sigs, mutated_seed_count,
				instr_id, same_instr_index, opnd_index, cc, data_size,
				data_type, start_yettwai);
			mt.MutateToSearch();
		}
		else if (data_size == 4) {
			Mutator<int> mt(drrun_path, yyx_dll_path, exe_path,
				folder_put_instr_val_trace, folder_put_generated_seeds,
				interesting_seed_sigs, mutated_seed_count,
				instr_id, same_instr_index, opnd_index, cc, data_size,
				data_type, start_yettwai);
			mt.MutateToSearch();
		}
		else if (data_size == 8) {
			Mutator<long long> mt(drrun_path, yyx_dll_path, exe_path,
				folder_put_instr_val_trace, folder_put_generated_seeds,
				interesting_seed_sigs, mutated_seed_count,
				instr_id, same_instr_index, opnd_index, cc, data_size,
				data_type, start_yettwai);
			mt.MutateToSearch();
		}
	}
	else if (data_type == m_float) {
		y_assert(data_size >= 4, "data_size >= 4", __FILE__, __LINE__);
		Mutator<float> mt(drrun_path, yyx_dll_path, exe_path,
			folder_put_instr_val_trace, folder_put_generated_seeds,
			interesting_seed_sigs, mutated_seed_count,
			instr_id, same_instr_index, opnd_index, cc, 4,
			data_type, start_yettwai);
		mt.MutateToSearch();
	}
	else if (data_type == m_double) {
		y_assert(data_size >= 8, "data_size >= 8", __FILE__, __LINE__);
		Mutator<double> mt(drrun_path, yyx_dll_path, exe_path,
			folder_put_instr_val_trace, folder_put_generated_seeds,
			interesting_seed_sigs, mutated_seed_count,
			instr_id, same_instr_index, opnd_index, cc, 8,
			data_type, start_yettwai);
		mt.MutateToSearch();
	}
	else {
		y_assert(false, "data_type wrong.", __FILE__, __LINE__);
	}
}

void find_consecutive_corresponding_bytes(InstrTaintRootInfo* depend_ss_itri, std::vector<MCByteID>& src_bts, std::vector<TempConsecutiveTraceableByteTaintSetPosition>& tctbtsp_vect) {
	// find consecutive bytes from 0, reg may much larger than needed, so here, we search for max consectuive tainted bytes. 
	size_t raw_sibsz = src_bts.size();
	size_t curr_sec_start = 0;
	size_t curr_sec_end_inclusive = -1;
	if (0 < raw_sibsz) {
		if (depend_ss_itri->origin_taint.find(src_bts.at(0)) != depend_ss_itri->origin_taint.end()) {
			curr_sec_end_inclusive = 0;
		}
	}
	for (size_t i = 0; i < raw_sibsz; i++) {
		if (i < raw_sibsz - 1) {
			size_t after_i = i + 1;
			// judge whether prev_i be adjacent to i;
			MCByteID& i_mbid = src_bts.at(i);
			MCByteID& after_i_mbid = src_bts.at(after_i);
			y_assert((i_mbid.byte_type == after_i_mbid.byte_type) and (i_mbid.reg_id_or_mem_or_imm_with_byte_offset + 1 == after_i_mbid.reg_id_or_mem_or_imm_with_byte_offset), "mbid byte type wrong.", __FILE__, __LINE__);
			// the tainted src byte is adjacent to prev, so extend and update the sec_end. 
			if (depend_ss_itri->origin_taint.find(after_i_mbid) != depend_ss_itri->origin_taint.end()) {
				curr_sec_end_inclusive = after_i;
			}
			else {
				break;
			}
		}
	}

	int consec_size = curr_sec_end_inclusive + 1;
	if (consec_size == 1 || consec_size == 2 || consec_size == 4 || consec_size == 8) {
		// find tainted src section, iterate from section start to end to find corresponding origin taint start end. 
		for (size_t sec_i = curr_sec_start; sec_i <= curr_sec_end_inclusive; sec_i++) {
			// consecutive bytes, find possible corresponding byte in dst_info_vect's value: std::set<TraceableByteTaintSetPosition>. 
			MCByteID& sec_i_mbid = src_bts.at(sec_i);
			auto sec_i_it = depend_ss_itri->origin_taint.find(sec_i_mbid);
			std::set<TraceableByteTaintSetPosition>& tbtsp_set = sec_i_it->second;
			if (sec_i == curr_sec_start) {
				// initialize tctbtsp_vect. 
				for (const TraceableByteTaintSetPosition& tbtsp : tbtsp_set) {
					tctbtsp_vect.push_back(TempConsecutiveTraceableByteTaintSetPosition(tbtsp, tbtsp));
				}
			}
			else {
				// for each tbtsp in tbtsp_set, find consecutive prev and now tbtsp. 
				std::vector<TempConsecutiveTraceableByteTaintSetPosition> temp;
				for (const TraceableByteTaintSetPosition& tbtsp : tbtsp_set) {
					for (const TempConsecutiveTraceableByteTaintSetPosition& tctbtsp : tctbtsp_vect) {
						if (tctbtsp.curr_end.instr_index_which_set_dst_byte == tbtsp.instr_index_which_set_dst_byte) {
							if (tctbtsp.curr_end.bid.byte_type == tbtsp.bid.byte_type) {
								if (tctbtsp.curr_end.bid.reg_id_or_mem_or_imm_with_byte_offset + 1 == tbtsp.bid.reg_id_or_mem_or_imm_with_byte_offset) {
									// found consecutive, update curr_end. 
									TempConsecutiveTraceableByteTaintSetPosition new_tctbtsp = tctbtsp;
									new_tctbtsp.curr_end = tbtsp;
									temp.push_back(new_tctbtsp);
								}
							}
						}
					}
				}
				tctbtsp_vect = temp;
			}
		}
	}

}

void find_file_data_offset_from_byte_taint_origin_info(YEssenTaintedTrace* yett, const TraceableByteTaintSetPosition& tbtsp, ChangableContentLocation* cc) {
//	assert(cc->data_addr == NULL and cc->data_addr == data_len);
	MCByteID only_origin_bid_start = tbtsp.bid;
	y_assert(only_origin_bid_start.byte_type == ByteType::mem, "only_origin_bid_start.byte_type == ByteType::mem", __FILE__, __LINE__);
	size_t origin_instr_idx = tbtsp.instr_index_which_set_dst_byte;
//	assert(origin_instr_idx == tbtsp_end_inclusive.instr_index_which_set_dst_byte);
	// find the origin instr. 
	slot* origin_s = yett->get_origin_slot_in_sliced_trace(origin_instr_idx);
	y_assert(origin_s->kind == trace_unit_type::is_high_level_op_type, "origin_s->kind == trace_unit_type::is_high_level_op_type", __FILE__, __LINE__);
	high_level_op* hop = (high_level_op*)origin_s->object;
	y_assert(hop->file_name != "", "hop->file_name must not empty.", __FILE__, __LINE__);
	byte* to_mutate_addr = cc->frc->addr + (only_origin_bid_start.reg_id_or_mem_or_imm_with_byte_offset - hop->addr);
	cc->changable_data_addr = to_mutate_addr;
}

void FuzzingForOneSeed(const std::string& drrun_path, const std::string& yyx_dll_path, 
	const std::string& exe_path, const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds, const std::string& origin_seed_path,
	std::set<std::string>& interesting_seed_sigs, std::map<std::string, int>& mutated_seed_count)
{
	FileReadContent* ori_seed = new FileReadContent();
	YFileUtil::read_whole_file(origin_seed_path, ori_seed);

	YEssenTaintedTrace* one_yett = RunSeedAndHandleInteresting(drrun_path, yyx_dll_path, origin_seed_path, 
		exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, 
		"existing seed prepare-run to begin mutation.", interesting_seed_sigs, mutated_seed_count);

	YEssenTaintedTraceWithAnalysisInfo* yettwai = new YEssenTaintedTraceWithAnalysisInfo(one_yett);

	// find all jcc (jz,jne, ...) depended cmp, comiss, test. 
	// for each cmp, comiss, test, find all root-tainted bytes which taint the src opnds of cmp, comiss, test. 
	// mutate root-tainted bytes
	//   1. directly set byte to byte. 
	//   2. guess type (int, float), mutate linearly. 
	for (SlicedSlot& ss : yettwai->yett->tained_slots) {
		size_t ss_idx = ss.idx_in_sliced_slots;
		BranchDependInfo* bd = yettwai->yett->yet->each_instr_branch_and_prev_depend_info.at(ss_idx);
		bool should_be_ignored = yettwai->should_be_ignored_based_on_module.at(ss_idx);
		if (bd != NULL and (not should_be_ignored)) {
			// if bd is not NULL, it should be branch instruction as jz, jne, jle, etc. 
//			if (bd->depends_exist_tainted) {
				y_assert(ss.s->kind == trace_unit_type::is_op_meta, "ss.s->kind == trace_unit_type::is_op_meta", __FILE__, __LINE__);
				instr* itr = (instr*)ss.s->object;
				// Predicate is which condition make the branch execute. 
				InstrPredicate inst_pred = (InstrPredicate)itr->inst_predicate;

				// bd->depend_idxes depends on instructions which set eflags, for example, cmp, cmoiss, test. 
				y_assert(bd->depend_idxes.size() == 1, "bd->depend_idxes.size() == 1", __FILE__, __LINE__);
				for (size_t origin_idx : bd->depend_idxes) {
					auto it = yettwai->yett->origin_index_to_sliced_index.find(origin_idx);
					y_assert(it != yettwai->yett->origin_index_to_sliced_index.end(), "it != yettwai->yett->origin_index_to_sliced_index.end()", __FILE__, __LINE__);
					size_t depend_sliced_index = it->second;

					SlicedSlot& depend_ss = yettwai->yett->tained_slots.at(depend_sliced_index);
					InstrTaintRootInfo* depend_ss_itri = yettwai->yett->yet->each_instr_taint_root_info.at(depend_sliced_index);
					std::pair<InstrID, int>& depend_iid_and_iidx = yettwai->sliced_slot_iid_and_same_iid_idx.at(depend_sliced_index);
					slot* depend_s = depend_ss.s;
					y_assert(depend_s->kind == trace_unit_type::is_op_meta, "depend_s->kind == trace_unit_type::is_op_meta", __FILE__, __LINE__);
					instr* depend_itr = (instr*)depend_s->object;

					// depend instructions are cmp, cmoiss, test, etc. 
					// take consequent 4 or 8 bytes as int or float, all other bytes are taken as int. 
					// consider one opnd at one time. 
					if (depend_itr->opname == "cmp" || depend_itr->opname == "test" || depend_itr->opname == "comiss" || depend_itr->opname == "comisd") {
						y_assert(depend_itr->srcs.size() == 2, "depend_itr->srcs.size() == 2", __FILE__, __LINE__);
						for (int di = 0; di < 2; di++) {
							opnd* src = depend_itr->srcs.at(di);
							opnd* to_cmp = depend_itr->srcs.at((uint64_t)1 - di);
							// judge byte directly set. 
							std::string directly_set_bytes_info = "";

							bool has_tainted_byte = false;
							std::vector<MCByteID> src_bytes;
							get_bytes_no_expand(src, -1, -1, src_bytes);
							FileReadContent* directly_set_byte_mutate_seed = new FileReadContent(ori_seed);
							for (int sb_idx = 0; sb_idx < src_bytes.size(); sb_idx++) {
								MCByteID src_byte = src_bytes.at(sb_idx);
								auto ot_it = depend_ss_itri->origin_taint.find(src_byte);
								if (ot_it != depend_ss_itri->origin_taint.end()) {
									has_tainted_byte |= true;
									std::set<TraceableByteTaintSetPosition>& origin_taint_info = ot_it->second;
									if (origin_taint_info.size() == 1) {
										// directly set byte. 
										auto only_it = origin_taint_info.begin();
										ChangableContentLocation cc(directly_set_byte_mutate_seed);
										// find the origin instr. 
										find_file_data_offset_from_byte_taint_origin_info(yettwai->yett, *only_it, &cc);
										size_t origin_instr_idx = only_it->instr_index_which_set_dst_byte;
										slot* origin_s = yettwai->yett->get_origin_slot_in_sliced_trace(origin_instr_idx);
										high_level_op* hop = (high_level_op*)origin_s->object;
										y_assert(hop->file_name != "", "hop->file_name must not empty", __FILE__, __LINE__);
										if (YStringUtil::endsWith(hop->file_name, origin_seed_path)) {
											y_assert(to_cmp->value != NULL, "to_cmp->value != NULL", __FILE__, __LINE__);
											cc.apply_modification(*(to_cmp->value + sb_idx));

											directly_set_bytes_info += cc.to_string();
										}
										else {
											y_assert(false, "hop->file_name ends wrong", __FILE__, __LINE__);
										}
									}
								}
							}

							if (directly_set_bytes_info != "") {
								std::string generated_seed_path = folder_put_generated_seeds + "/" + std::to_string(TestIndex::generated_test_case_global_idx);
								TestIndex::generated_test_case_global_idx++;

								YFileUtil::write_whole_file(generated_seed_path, directly_set_byte_mutate_seed);

								// run the generated seed and confirm whether it is interesting (use bitmap). 
								RunSeedAndHandleInteresting(drrun_path, yyx_dll_path, generated_seed_path, exe_path, 
									folder_put_instr_val_trace, folder_put_generated_seeds, 
									"directly_set_file_offset_and_byte:" + directly_set_bytes_info, 
									interesting_seed_sigs, mutated_seed_count);
							}
							else {
								y_assert(has_tainted_byte == false, "has_tainted_byte == false", __FILE__, __LINE__);
							}

							delete directly_set_byte_mutate_seed;
						}
					}
					else {
						printf("depend instruction:%s is not supported yet.\n", depend_itr->opname.c_str());
					}
					if (depend_itr->opname == "cmp" || depend_itr->opname == "comiss") {
						for (int di = 0; di < 2; di++) {
							opnd* src = depend_itr->srcs.at(di);
							opnd* to_cmp = depend_itr->srcs.at((uint64_t)(1 - di));
							// get consecutive src_bytes. 
							std::vector<MCByteID> src_bts;
							get_bytes_no_expand(src, -1, -1, src_bts);
							// find opnd src which directly match the consecutive section. 
							std::vector<TempConsecutiveTraceableByteTaintSetPosition> tctbtsp_vect;
							find_consecutive_corresponding_bytes(depend_ss_itri, src_bts, tctbtsp_vect);
							for (const TempConsecutiveTraceableByteTaintSetPosition& tctbtsp : tctbtsp_vect) {
								bool run_logic = true;
								if (depend_itr->opname == "comiss" || depend_itr->opname == "comisd") {
									if (tctbtsp.get_consecutive_length() == 4 || tctbtsp.get_consecutive_length() == 8) {
										// continue
									}
									else {
										run_logic = false;
									}
								}
								if (run_logic) {
									// take consecutive section as a whole and mutate. 
									// get int* or float* (from TempConsecutiveTraceableByteTaintSetPosition). 
									// pass copied data and int* float* as pameters. 
									FileReadContent* one_con_new_seed = new FileReadContent(ori_seed);
									ChangableContentLocation cc(one_con_new_seed);
									find_file_data_offset_from_byte_taint_origin_info(yettwai->yett, tctbtsp.start, &cc);
									mutate_data_type mdt = get_opnd_data_type_according_to_branch_depend_opname(depend_itr->opname);
//									mutate_data_type mdt = depend_itr->opname == "comiss" ? mutate_data_type::m_float : mutate_data_type::m_int;
									MutateManyRoundsForBinpartSearch(drrun_path, yyx_dll_path, exe_path, 
										folder_put_instr_val_trace,
										folder_put_generated_seeds, 
										interesting_seed_sigs, mutated_seed_count,
										yettwai, depend_iid_and_iidx.first, depend_iid_and_iidx.second, di,
										&cc, src->actual_size, mdt);

									delete one_con_new_seed;
								}
							}
						}
					}
//					if (depend_itr->opname == "cmp") {
//						// ori_seed
//						// do not use pred, just move to all flips. 
//						//switch (inst_pred) {
//						//case DR_PRED_NONE: /**< No predicate is present. */
//						//case DR_PRED_O:   /**< x86 condition: overflow (OF=1). */
//						//case DR_PRED_NO:  /**< x86 condition: no overflow (OF=0). */
//						//case DR_PRED_B:   /**< x86 condition: below (CF=1). */
//						//case DR_PRED_NB:  /**< x86 condition: not below (CF=0). */
//						//case DR_PRED_Z:   /**< x86 condition: zero (ZF=1). */
//						//case DR_PRED_NZ:  /**< x86 condition: not zero (ZF=0). */
//						//case DR_PRED_BE:  /**< x86 condition: below or equal (CF=1 or ZF=1). */
//						//case DR_PRED_NBE: /**< x86 condition: not below or equal (CF=0 and ZF=0). */
//						//case DR_PRED_S:   /**< x86 condition: sign (SF=1). */
//						//case DR_PRED_NS:  /**< x86 condition: not sign (SF=0). */
//						//case DR_PRED_P:   /**< x86 condition: parity (PF=1). */
//						//case DR_PRED_NP:  /**< x86 condition: not parity (PF=0). */
//						//case DR_PRED_L:   /**< x86 condition: less (SF != OF). */
//						//case DR_PRED_NL:  /**< x86 condition: not less (SF=OF). */
//						//case DR_PRED_LE:  /**< x86 condition: less or equal (ZF=1 or SF != OF). */
//						//case DR_PRED_NLE: /**< x86 condition: not less or equal (ZF=0 and SF=OF). */
//						//	break;
//						//}
//					}
				}
//			}
		}
	}
	delete yettwai;
	delete ori_seed;
}

void TaintFuzzingMain(const std::string& drrun_path, 
	const std::string& yyx_taint_dll_path,
	const std::string& exe_path,
	const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds) {

	std::set<std::string> interesting_seed_sigs;
	std::map<std::string, int> mutated_seed_count;
	
	for (const auto& entry : std::filesystem::directory_iterator(folder_put_generated_seeds)) {
		std::string path_ss = entry.path().string();
		YStringUtil::replace_all(path_ss, "\\", "/");
		mutated_seed_count.insert({ path_ss, 0 });
	}
	
	int min_num = 0, max_num = 1000;

	std::random_device seed;
	std::ranlux48 engine(seed());
	std::uniform_int_distribution<> distrib(min_num, max_num);

	int iturn = 0;
	int max_turn = 1000;
	while (iturn < max_turn) {
		bool gen_random_seed = false;
		if (mutated_seed_count.size() == 0) {
			gen_random_seed = true;
		}
		else {
			std::pair<std::string, int> min = *std::min_element(mutated_seed_count.begin(), mutated_seed_count.end(), compare_value_in_map<std::string, int>());
			mutated_seed_count.insert_or_assign(min.first, min.second + 1);
//			int random_num = distrib(engine);
			// 100% to generate new seed. 
//			if (random_num < max_num / 2) {
			if (min.second >= NeedNewSeedMinimumThreshold) {
				gen_random_seed = true;
			}
			//		}
			if (not gen_random_seed) {
				FuzzingForOneSeed(drrun_path, yyx_taint_dll_path, exe_path, folder_put_instr_val_trace,
					folder_put_generated_seeds, min.first, interesting_seed_sigs, mutated_seed_count);
			}
		}

		if (gen_random_seed) {
			int random_num = distrib(engine) + 1;
			byte* bs = new byte[random_num];
			FileReadContent* fri = new FileReadContent(bs, random_num);
			std::string generated_seed_path = folder_put_generated_seeds + "/" + std::to_string(TestIndex::generated_test_case_global_idx);
			TestIndex::generated_test_case_global_idx++;
			YFileUtil::write_whole_file(generated_seed_path, fri);
			delete fri;
			// run the generated seed and confirm whether it is interesting (use bitmap). 
			RunSeedAndHandleInteresting(drrun_path, yyx_taint_dll_path, generated_seed_path, exe_path, folder_put_instr_val_trace, folder_put_generated_seeds, "randomly generated seed", interesting_seed_sigs, mutated_seed_count);
		}

		iturn++;
	}
}

