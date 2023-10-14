#pragma once

#include "yyx_trace_taint.h"
#include <string>
#include <algorithm>

bool module_name_should_be_ignored_when_computing_branch(std::string module_name);

class InstrID {

public:
	std::string module_name;
	size_t offset = 0;

	InstrID() {

	}

	InstrID(std::string& module_name, size_t offset) {
		this->module_name = module_name;
		this->offset = offset;
	}

	~InstrID() {

	}

	bool operator < (const InstrID& order) const {
		if ((module_name < order.module_name)
			|| (module_name == order.module_name) && (offset < order.offset)) {
			return true;
		}
		return false;
	}

};

enum OneExist {
	OnlyLeftExist,
	OnlyRightExist,
	BothExist,
};

enum ValDiffType {
	NoDiff,
	IntDiff,
	FloatDiff,
	DoubleDiff,
};

struct InstrVal {
	byte val[8]{0};
	byte val_size = 0;
};

class InstrValDifference {

public:
//	OneExist oe = OneExist::BothExist;
	ValDiffType v_diff_type = ValDiffType::NoDiff;
//	int64_t int_diff_q = 0;
//	int64_t int_diff_r = 0;
//	bool overflow = false;
	int val_size = 0;
	InstrVal vals[2]{0};
	//int64_t int_left = 0;
	//int64_t int_right = 0;
	//float f_left = 0;
	//float f_right = 0;
	//double df_left = 0;
	//double df_right = 0;
	//	byte different_number_of_bit_1_in_xor_value_of_each_byte = 0;
	//	byte xor_of_test = 0;
	//	size_t byte_size_of_test = 0;
	//  test diff, how to set. 

	InstrValDifference() {

	}

//	InstrValDifference(
////		OneExist oe,
//		int64_t int_left,
//		int64_t int_right,
//		float f_left,
//		float f_right,
//		double df_left,
//		double df_right
////		byte* different_number_of_bit_1_in_xor_value_of_each_byte,
////		byte* xor_of_test,
////		size_t byte_size_of_test
//	) {
////		this->oe = oe;
//		this->int_left = int_left;
//		this->int_right = int_right;
//		this->f_left = f_left;
//		this->f_right = f_right;
//		this->df_left = df_left;
//		this->df_right = df_right;
////		this->different_number_of_bit_1_in_xor_value_of_each_byte = different_number_of_bit_1_in_xor_value_of_each_byte;
////		this->xor_of_test = xor_of_test;
////		this->byte_size_of_test = byte_size_of_test;
//	}

	~InstrValDifference() {
	}

};

class InstrAnalysisInfo {

public:

	instr* itr = NULL;
//	InstrValDifference* vdiff = NULL;

	InstrAnalysisInfo(instr* itr) {
		this->itr = itr;
	}

	~InstrAnalysisInfo() {

	}

};

class YEssenTaintedTraceWithAnalysisInfo {

public:

	YEssenTaintedTrace* yett = NULL;

	// the key is module_name+offset, the value is the repeated index of the same module_name+offset. 
	std::vector<std::pair<InstrID, int>> sliced_slot_iid_and_same_iid_idx;
	// try to flip each branch of yett. the yett corresponds to a trace. 
	std::vector<bool> should_be_ignored_based_on_module;

	std::map<InstrID, std::vector<InstrAnalysisInfo>*> instr_sum;
	
	YEssenTaintedTraceWithAnalysisInfo(YEssenTaintedTrace* yett) {
		this->yett = yett;
		int ts_idx = -1;

		std::map<InstrID, int> iid_idx;
		for (SlicedSlot& ts : yett->tained_slots) {
			ts_idx++;
			slot* s = ts.s;
			y_assert(ts.idx_in_sliced_slots == ts_idx and ts_idx == should_be_ignored_based_on_module.size(), "ts.idx_in_sliced_slots == ts_idx and ts_idx == should_be_ignored_based_on_module.size(), but wrong.", __FILE__, __LINE__);
			should_be_ignored_based_on_module.push_back(false);
			if (s->kind == trace_unit_type::is_op_meta) {
				instr* itr = (instr*)s->object;

				bool should_ignore = false;
				if ((itr->instr_type & is_cbr_in_type_position_and_info) == is_cbr_in_type_position_and_info) {
					// is_branch
					should_ignore |= module_name_should_be_ignored_when_computing_branch(itr->module_name);
				}

				if (should_ignore) {
					should_be_ignored_based_on_module.at(ts.idx_in_sliced_slots) = should_ignore;

					BranchDependInfo* branch_pd_info = yett->yet->each_instr_branch_and_prev_depend_info.at(ts.idx_in_sliced_slots);
					for (uint64_t depend_idx : branch_pd_info->depend_idxes) {
						uint64_t depend_sliced_idx = yett->get_sliced_index_from_origin_index(depend_idx);
						should_be_ignored_based_on_module.at(depend_sliced_idx) = should_ignore;
					}
				}
			}
			// handle instr_id and its same instr_id's repeated index. 
			if (s->kind == trace_unit_type::is_op_meta) {
				instr* itr = (instr*)s->object;
				InstrID iid(itr->module_name, itr->offset);
				int iidx = -1;
				auto iidx_it = iid_idx.find(iid);
				if (iidx_it != iid_idx.end()) {
					iidx = iidx_it->second;
				}
				iidx++;
				iid_idx.insert_or_assign(iid, iidx);
				sliced_slot_iid_and_same_iid_idx.push_back(std::pair<InstrID, int>(iid, iidx));
			}
			else {
				std::pair<InstrID, int> pr(InstrID(), 0);
				sliced_slot_iid_and_same_iid_idx.push_back(pr);
			}
			// reorganize and summary the instrctions. 
			if (s->kind == trace_unit_type::is_op_meta) {
				instr* itr = (instr*)s->object;
				InstrID iid(itr->module_name, itr->offset);
				
				std::vector<InstrAnalysisInfo>* summed_itrs = NULL;

				auto mapIt = instr_sum.find(iid);
				if (mapIt == instr_sum.end()) {
					summed_itrs = new std::vector<InstrAnalysisInfo>();
					instr_sum.insert({ iid, summed_itrs });
				}
				else {
					summed_itrs = mapIt->second;
				}

				InstrAnalysisInfo iai(itr);
				
//				iai.vdiff = diff;

				summed_itrs->push_back(iai);
			}
		}
	}

	~YEssenTaintedTraceWithAnalysisInfo() {
		if (yett != NULL) {
			delete yett;
		}
		for (auto it = instr_sum.begin(); it != instr_sum.end(); it++) {
			auto vect_ptr = it->second;
			delete vect_ptr;
		}
		instr_sum.clear();
	}

};

enum TrendType {
	NoTrend,
	NotChange, //no change
	LeftToRightNewData, //just left, no right
	LeftToRightDeleteData, //just right, no left
	MoveToFlipButNotFlip, //move to 0, but not flip
	MoveToFlipButFlipToEqual, // ==0
	MoveToFlipButFlip, //move to 0, but flip
	NotMoveToFlip, //not move to 0
};

class Trend {

public:
	TrendType oet = TrendType::NoTrend;
	// for test, record each byte's trend. 
	// byte trend for test: number of 1 after xor. 
	// MoveToFlip means number of bit 1 in xor is move to 0. 
	// NotMoveToFlip means number of bit 1 in xor is move to a larger number. 
//	TrendType* trend_for_different_bit_1_in_xor_value_of_each_byte = 0;
//	size_t byte_size_of_test = 0;

	Trend() {

	}

	Trend(TrendType oet)// , size_t byte_size_of_test
	{
		this->oet = oet;
//		this->trend_for_different_bit_1_in_xor_value_of_each_byte = trend_for_different_bit_1_in_xor_value_of_each_byte;
//		this->byte_size_of_test = byte_size_of_test;
	}

	static std::string get_trend_desc(Trend td) {
		std::string res;
		switch (td.oet) {
		case NoTrend:
			res = "NoTrend";
			break;
		case NotChange:
			res = "NotChange";
			break;
		case LeftToRightNewData:
			res = "LeftToRightNewData";
			break;
		case LeftToRightDeleteData:
			res = "LeftToRightDeleteData";
			break;
		case MoveToFlipButNotFlip:
			res = "MoveToFlipButNotFlip";
			break;
		case MoveToFlipButFlipToEqual:
			res = "MoveToFlipButFlipToEqual";
			break;
		case MoveToFlipButFlip:
			res = "MoveToFlipButFlip";
			break;
		case NotMoveToFlip:
			res = "NotMoveToFlip";
			break;
		default:
			y_assert(false, "flip direction judge.", __FILE__, __LINE__);
			break;
		}
		return res;
	}

	~Trend() {

	}

};

class YTraceAnalysisUtil {

public:

	static InstrValDifference ComputeSlefValDiffForBranchDependInstr(instr* itr) {
		y_assert(itr->srcs.size() == 2 and itr->dsts.size() == 0, "src dst num wrong.", __FILE__, __LINE__);
		
		InstrValDifference diff;
		
		auto src0 = itr->srcs.at(0);
		auto src0_as = (std::min)(8, (int)src0->actual_size);
		auto src1 = itr->srcs.at(1);
		auto src1_as = (std::min)(8, (int)src1->actual_size);
		
		if (itr->opname == "cmp" || itr->opname == "test") {
			diff.v_diff_type = ValDiffType::IntDiff;

			//int64_t cmp_src1_value = 0;
			//int64_t cmp_src2_value = 0;
			//int flag = 0;
			//for (const auto& src : itr->srcs) {
			//	int64_t cmp_temp_src_value;
			//	if (src->value != NULL) {
			//		std::memcpy(&cmp_temp_src_value, src->value, sizeof(int64_t));
			//	}
			//	else {
			//		cmp_temp_src_value = src->int_imm;
			//	}
			//	flag++;
			//	if (flag == 1) {
			//		cmp_src1_value = cmp_temp_src_value;
			//	}
			//	else if (flag == 2) {
			//		cmp_src2_value = cmp_temp_src_value;
			//	}
			//}

//			int64_t cmp_src1_value_q = cmp_src1_value / 10;
//			int64_t cmp_src1_value_r = cmp_src1_value % 10;
//			int64_t cmp_src2_value_q = cmp_src2_value / 10;
//			int64_t cmp_src2_value_r = cmp_src2_value % 10;

//			int64_t int_diff_q = cmp_src1_value_q - cmp_src2_value_q;
//			int64_t int_diff_r = cmp_src1_value_r - cmp_src2_value_r;

//			diff.int_diff_q = int_diff_q;
//			diff.int_diff_r = int_diff_r;

//			diff.int_left = cmp_src1_value;
//			diff.int_right = cmp_src2_value;
		}
		else if (itr->opname == "comiss") {
			diff.v_diff_type = ValDiffType::FloatDiff;

			src0_as = 4;
			src1_as = 4;
//			float comiss_src1_value = 0;
//			float comiss_src2_value = 0;
			//int flag = 0;
			//for (const opnd* src : itr->srcs) {
			//	src->actual_size;
			//	if (src->actual_size == 4) {
			//		float comiss_temp_src_value;
			//		std::memcpy(&comiss_temp_src_value, src->value, sizeof(float));
			//		flag++;
			//		if (flag == 1) {
			//			diff.f_left = comiss_temp_src_value;
			//		}
			//		else if (flag == 2) {
			//			diff.f_right = comiss_temp_src_value;
			//		}
			//	}
			//	else if (src->actual_size == 8) {
			//		double comiss_temp_src_value;
			//		std::memcpy(&comiss_temp_src_value, src->value, sizeof(double));
			//		flag++;
			//		if (flag == 1) {
			//			diff.df_left = comiss_temp_src_value;
			//		}
			//		else if (flag == 2) {
			//			diff.df_right = comiss_temp_src_value;
			//		}
			//	}
			//	else {
			//		y_assert(false);
			//	}
			//}
//			float f_diff = comiss_src1_value / 4 - comiss_src2_value / 4;
//			diff.f_diff = f_diff;
		}
		else if (itr->opname == "comisd") {
			diff.v_diff_type = ValDiffType::DoubleDiff;
		}
		else {
			y_assert(false, "For ValDiff, there exists unsupported opname: " + itr->opname + ".", __FILE__, __LINE__);
		}
		
		diff.vals[0].val_size = src0_as;
		diff.vals[1].val_size = src1_as;

		memcpy_s(diff.vals[0].val, 8, src0->value, src0_as);
		memcpy_s(diff.vals[1].val, 8, src1->value, src1_as);
		return diff;
	}
	
	static InstrValDifference GetTraceOneInstrPairDiff(InstrID instr_id, int same_instr_index, YEssenTaintedTraceWithAnalysisInfo* one_trace) {
		InstrValDifference diff;
		auto lt_it = one_trace->instr_sum.find(instr_id);
		if (lt_it != one_trace->instr_sum.end()) {
			std::vector<InstrAnalysisInfo>* iai_vect = lt_it->second;
			if (iai_vect != NULL) {
				if (same_instr_index < iai_vect->size()) {
					InstrAnalysisInfo iai = iai_vect->at(same_instr_index);
					diff = YTraceAnalysisUtil::ComputeSlefValDiffForBranchDependInstr(iai.itr);
				}
			}
		}
		return diff;
	}

};

class YTraceCompareUtil {

public:

	static Trend ComputeTraceOneInstrPairTrend(InstrID instr_id, int same_instr_index, YEssenTaintedTraceWithAnalysisInfo* last_trace, YEssenTaintedTraceWithAnalysisInfo* new_trace) {
		InstrValDifference diff1 = YTraceAnalysisUtil::GetTraceOneInstrPairDiff(instr_id, same_instr_index, last_trace);
		InstrValDifference diff2 = YTraceAnalysisUtil::GetTraceOneInstrPairDiff(instr_id, same_instr_index, new_trace);

		Trend trend = ComputeOneValDiffPairTrend(diff1, diff2);

		return trend;
	}

	static Trend ComputeOneValDiffPairTrend(InstrValDifference& diff1, InstrValDifference& diff2);

	//static Trend ComputeOneValDiffPairTrend(InstrValDifference& diff1, InstrValDifference& diff2) {
	//	Trend trend;
	//	if (diff1.v_diff_type == ValDiffType::NoDiff) {
	//		y_assert(diff2.v_diff_type != ValDiffType::NoDiff);
	//		trend.oet = TrendType::LeftToRightNewData;
	//	}
	//	else if (diff2.v_diff_type == ValDiffType::NoDiff) {
	//		trend.oet = TrendType::LeftToRightDeleteData;
	//	}
	//	else {
	//		y_assert(diff1.v_diff_type != ValDiffType::NoDiff and diff2.v_diff_type != ValDiffType::NoDiff);
	//		// compare diff_value and compute both-exist trend. 
	//		TrendType trendType = NotMoveToFlip;
	//		// TrendType* trend_for_different_bit_1_in_xor_value_of_each_byte = 0;

	//		if (diff1.v_diff_type == ValDiffType::IntDiff) {
	//			if (diff2.int_diff_q == 0 && diff2.int_diff_r == 0) {
	//				trendType = MoveToFlipButFlipToEqual;
	//			}
	//			else if (diff1.int_diff_q == diff2.int_diff_q && diff1.int_diff_r == diff2.int_diff_r) {
	//				trendType = NotChange;
	//			}
	//			else if (diff1.int_diff_q * diff2.int_diff_q > 0) {
	//				if ((std::abs(diff1.int_diff_q) < std::abs(diff2.int_diff_q)) || ((diff1.int_diff_q == diff2.int_diff_q) && (diff1.int_diff_r < diff2.int_diff_r))) {
	//					trendType = NotMoveToFlip;
	//				}
	//				else if ((std::abs(diff1.int_diff_q) > std::abs(diff2.int_diff_q)) || ((diff1.int_diff_q == diff2.int_diff_q) && (diff1.int_diff_r > diff2.int_diff_r))) {
	//					trendType = MoveToFlipButNotFlip;
	//				}
	//			}
	//			else if (diff1.int_diff_q * diff2.int_diff_q < 0) {
	//				trendType = MoveToFlipButFlip;
	//			}
	//		}
	//		else if (diff1.v_diff_type == ValDiffType::FloatDiff) {
	//			if (diff2.f_diff == 0) {
	//				trendType = MoveToFlipButFlipToEqual;
	//			}
	//			else if (diff1.f_diff == diff2.f_diff) {
	//				trendType = NotChange;
	//			}
	//			else if (diff1.f_diff * diff2.f_diff > 0) {
	//				if (std::abs(diff1.f_diff) < std::abs(diff2.f_diff)) {
	//					trendType = NotMoveToFlip;
	//				}
	//				else if (std::abs(diff1.f_diff) > std::abs(diff2.f_diff)) {
	//					trendType = MoveToFlipButNotFlip;
	//				}
	//			}
	//			else if (diff1.f_diff * diff2.f_diff < 0) {
	//				trendType = MoveToFlipButFlip;
	//			}
	//		}
	//		trend.oet = trendType;
	//	}
	//	return trend;
	//}

	static std::map<InstrID, std::vector<Trend>*>* ComputeTraceTrend(YEssenTaintedTraceWithAnalysisInfo* last_trace, YEssenTaintedTraceWithAnalysisInfo* new_trace)
	{
		std::map<InstrID, std::vector<Trend>*>* trends = new std::map<InstrID, std::vector<Trend>*>();
		for (auto it = last_trace->instr_sum.begin(); it != last_trace->instr_sum.end(); it++) {
			InstrID id = it->first;
			std::vector<InstrAnalysisInfo>* id_vect_ais = it->second;
			auto nt_it = new_trace->instr_sum.find(id);
			if (nt_it != new_trace->instr_sum.end()) {
				// compute real logic of trend computing. 

				// initialize return value for id. 
				std::vector<Trend>* trend_vect_for_id = NULL;
				auto mapIt = trends->find(id);
				if (mapIt == trends->end()) {
					trend_vect_for_id = new std::vector<Trend>();
					trends->insert({ id, trend_vect_for_id });
				}
				else {
					trend_vect_for_id = mapIt->second;
				}

				std::vector<InstrAnalysisInfo>* nt_id_vect_ais = nt_it->second;
				// compute trend based on id_vect_ais and nt_id_vect_ais. 
				size_t id_vect_ais_sz = id_vect_ais->size();
				size_t nt_id_vect_ais_sz = nt_id_vect_ais->size();
				size_t max_v_size = (std::max)(id_vect_ais_sz, nt_id_vect_ais_sz);
				for (int i = 0; i < max_v_size; i++) {
					InstrValDifference diff1;
					InstrValDifference diff2;
					if (i < id_vect_ais_sz) {
						diff1 = YTraceAnalysisUtil::ComputeSlefValDiffForBranchDependInstr(id_vect_ais->at(i).itr);
					}
					if (i < nt_id_vect_ais_sz) {
						diff2 = YTraceAnalysisUtil::ComputeSlefValDiffForBranchDependInstr(nt_id_vect_ais->at(i).itr);
					}
					Trend trend = ComputeOneValDiffPairTrend(diff1, diff2);
					trend_vect_for_id->push_back(trend);
				}
			}
		}
		return trends;
	}

};

template<typename V>
class OneDirectSearch {

public:
	
//	static const int MaxGapValue = 1000000;

	V start;
	V end_inclusive;
	V end_bound;
	V gap_value;
	V atom_gap_value;

	bool curr_set_up = false;
	V curr_start = 0;
	V curr_end_inclusive = 0;
	V curr_gap_value = 0;

	OneDirectSearch(V start, V end_inclusive) {
		this->start = start;
		this->end_inclusive = end_inclusive;
		
		byte search_direction = start < end_inclusive ? 1 : 0;
		bool start_sign_positive = start >= 0;
		bool end_sign_positive = end_inclusive >= 0;
		if ((start_sign_positive xor end_sign_positive) == 0) {
			// same sign, same to minus. 
			gap_value = end_inclusive - start;
		}
		else {
			// one positive, one negative. 
			V minus = end_inclusive - start;
			bool overflow = is_overflow<V>(minus, end_inclusive);
			// overflow
			if (overflow) {
				gap_value = end_inclusive / 2 - start / 2;
			}
			else {
				gap_value = minus;
			}
		}
		
		if (search_direction == 1) {
			end_bound = (std::numeric_limits<V>::max)();
			atom_gap_value = 1;
		}
		else {
			end_bound = (std::numeric_limits<V>::lowest)();
			atom_gap_value = -1;
		}
	}

	std::tuple<bool, V, V> compute_next_step_info(V inc_val) {
		if (not curr_set_up) {
			this->curr_start = start;
			this->curr_end_inclusive = end_inclusive;
			this->curr_gap_value = gap_value;
			curr_set_up = true;
		}
		else {
			V now_gap_value = inc_val * atom_gap_value;
			if (inc_val == 0) {
				now_gap_value = curr_gap_value * 10;
			}
			if (is_overflow<V>(now_gap_value, curr_gap_value)) {
				now_gap_value = end_bound;
			}
			curr_gap_value = now_gap_value;
			curr_start = curr_end_inclusive;
			V next_curr_end_inclusive = curr_end_inclusive + curr_gap_value;
			if (is_overflow<V>(next_curr_end_inclusive, curr_end_inclusive)) {
				next_curr_end_inclusive = end_bound;
			}
			curr_end_inclusive = next_curr_end_inclusive;
		}
		bool valid = false;
		if (curr_start != curr_end_inclusive) {
			valid = true;
		}
		return std::tuple<bool, V, V>(valid, curr_start, curr_end_inclusive);
	}

	~OneDirectSearch() {

	}
};

template<typename V>
class BinPartSearch {

public:

	V start;
	V end_exclusive;

	InstrValDifference start_trace_cared_diff;
	InstrValDifference end_exclusive_trace_cared_diff;

	V curr_start;
	V curr_end_exclusive;

	InstrValDifference curr_start_trace_cared_diff;
	InstrValDifference curr_end_exclusive_trace_cared_diff;

	BinPartSearch(V start, InstrValDifference start_trace_cared_diff,
		V end_exclusive, InstrValDifference end_exclusive_trace_cared_diff) {
		this->start = start;
		this->start_trace_cared_diff = start_trace_cared_diff;
		this->end_exclusive = end_exclusive;
		this->end_exclusive_trace_cared_diff = end_exclusive_trace_cared_diff;

		this->curr_start = start;
		this->curr_start_trace_cared_diff = start_trace_cared_diff;
		this->curr_end_exclusive = end_exclusive;
		this->curr_end_exclusive_trace_cared_diff = end_exclusive_trace_cared_diff;
	}

	std::pair<bool, V> get_curr_mid() {
		bool valid = true;
		V mid = (curr_start + curr_end_exclusive) / 2;
		if (mid == curr_start || mid == curr_end_exclusive) {
			valid = false;
		}
		return std::pair<bool, V>(valid, mid);
	}

	std::tuple<bool, bool, bool> update_start_end_based_on_mid(V mid, InstrValDifference& mid_trace_cared_diff) {
		bool can_decide = false;
		bool fall_in_mid_to_right = false;
		bool fall_in_left_to_mid = false;

		Trend start_to_mid_td = YTraceCompareUtil::ComputeOneValDiffPairTrend(curr_start_trace_cared_diff, mid_trace_cared_diff);
		if (start_to_mid_td.oet == TrendType::MoveToFlipButFlip || start_to_mid_td.oet == TrendType::MoveToFlipButFlipToEqual || start_to_mid_td.oet == TrendType::MoveToFlipButNotFlip) {
			// should fall in mid to right. 
			fall_in_mid_to_right = true;
		}
		Trend mid_to_end_td = YTraceCompareUtil::ComputeOneValDiffPairTrend(curr_end_exclusive_trace_cared_diff, mid_trace_cared_diff);
		if (mid_to_end_td.oet == TrendType::MoveToFlipButFlip || start_to_mid_td.oet == TrendType::MoveToFlipButFlipToEqual || start_to_mid_td.oet == TrendType::MoveToFlipButNotFlip) {
			// should fall in left to mid. 
			fall_in_left_to_mid = true;
		}
		if (fall_in_mid_to_right) {
			if (!fall_in_left_to_mid) {
				can_decide = true;
				this->curr_start = mid;
				this->curr_start_trace_cared_diff = mid_trace_cared_diff;
			}
		}
		else {
			if (fall_in_left_to_mid) {
				can_decide = true;
				this->curr_end_exclusive = mid;
				this->curr_end_exclusive_trace_cared_diff = mid_trace_cared_diff;
			}
		}
		return std::tuple<bool, bool, bool>(can_decide, fall_in_left_to_mid, fall_in_mid_to_right);
	}

	~BinPartSearch() {
	}

};






