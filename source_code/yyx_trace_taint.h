#pragma once

#include <set>
#include <vector>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <windows.h>

#include "yyx_trace.h"
#include "yyx_engine.h"
#include "yyx_taint_detail.h"

class SlicedSlot {

public:
	size_t idx_in_sliced_slots = 0;
	slot* s = NULL;

	SlicedSlot() {

	}

//	SlicedSlot(SlicedSlot* ss) {
//		if (s == NULL) {
//			printf("at debug point!");
//		}
//		assert(ss->s != NULL);
//		this->idx_in_sliced_slots = ss->idx_in_sliced_slots;
//		this->s = new slot(ss->s);
//	}

	SlicedSlot(size_t idx_in_sliced_slots, slot* s) {
		this->idx_in_sliced_slots = idx_in_sliced_slots;
		this->s = s;
	}

	~SlicedSlot() {

	}

};

class YTaintedTrace {

public:

	YTrace* te = NULL;
	YTaint* yt = NULL;
	std::vector<SlicedSlot> tained_slots;
	std::map<size_t, size_t> origin_index_to_sliced_index;

	YTaintedTrace(YTaint* tt) {
		this->yt = tt;
		this->te = tt->get_origin_trace();

		size_t vsz = te->vect.size();
		for (int i = 0; i < vsz; i++) {
			slot* s = te->vect.at(i);
			bool add_to_slot_vect = false;
			InstrTaintInfo* tt_info = tt->each_instr_taint_info.at(i);
			if (tt_info != NULL) {
				// for tt_info->DstMaxRegHasTaintBeforeInstr() is true, it is mainly used to judge whether the value is consistent. 
				if (tt_info->SrcRegOrMemOrStrictDstHaveTaintBeforeInstr() || tt_info->DstMaxRegHasTaintBeforeInstr()) {
					add_to_slot_vect = true;
				}
			}
			BranchDependInfo* branch_info = tt->each_instr_branch_and_prev_depend_info.at(i);
			if (branch_info != NULL) {
				if (branch_info->depends_exist_tainted) {
					add_to_slot_vect = true;
//					if (instr_info_handled == true) {
//						printf("already found tainted branch? brach instr:%s.\n", t->get_instr_info(i).c_str());
//					}
//					assert(instr_info_handled == false);
//					if (add_to_slot_vect == false) {
						// here, must judge, because cmov instruction (also will be taken as branch) may operate taint data. 
//						SlicedSlot ss(tained_slots.size(), s);
//						tained_slots.push_back(ss);
//					}
				}
			}
			if (add_to_slot_vect) {
				y_assert(i == s->index, "i == s->index, but wrong.", __FILE__, __LINE__);
				size_t slice_slot_index = tained_slots.size();
				SlicedSlot* ss = new SlicedSlot(slice_slot_index, s);
				origin_index_to_sliced_index.insert({ s->index, slice_slot_index });
				tained_slots.push_back(*ss);
			}
		}
	}

	~YTaintedTrace() {

	}
};

class YEssenTaint {

public:

//	YEssenTaintedTrace* yett = NULL;

	std::vector<BranchDependInfo*> each_instr_branch_and_prev_depend_info;
	std::vector<InstrTaintInfo*> each_instr_taint_info;
	std::vector<InstrTaintRootInfo*> each_instr_taint_root_info;
	
	YEssenTaint(std::vector<SlicedSlot>& tained_slots, YTaint* ytt) {
//		this->yett = yett;
		for (SlicedSlot& tained_slot : tained_slots) {
			size_t ts_idx = tained_slot.s->index;
			BranchDependInfo* exist_bdi = ytt->each_instr_branch_and_prev_depend_info.at(ts_idx);
			BranchDependInfo* bdi = exist_bdi;
			if (exist_bdi != NULL) {
				bdi = new BranchDependInfo(exist_bdi);
			}
			each_instr_branch_and_prev_depend_info.push_back(bdi);
			InstrTaintInfo* exist_iti = ytt->each_instr_taint_info.at(ts_idx);
			InstrTaintInfo* iti = exist_iti;
			if (exist_iti != NULL) {
				iti = new InstrTaintInfo(exist_iti);
			}
			each_instr_taint_info.push_back(iti);
			InstrTaintRootInfo* exist_itri = ytt->each_instr_taint_root_info.at(ts_idx);
			InstrTaintRootInfo* itri = exist_itri;
			if (exist_itri != NULL) {
				itri = new InstrTaintRootInfo(exist_itri);
			}
			each_instr_taint_root_info.push_back(itri);
		}
	}

	~YEssenTaint() {

	}

};

class YEssenTaintedTrace {

public:

	std::vector<SlicedSlot> tained_slots;
	std::map<size_t, size_t> origin_index_to_sliced_index;

	YEssenTaint* yet = NULL;

	YEssenTaintedTrace(YTaintedTrace* ytt) {
		for (SlicedSlot& ts : ytt->tained_slots) {
			SlicedSlot new_ts;
			new_ts.idx_in_sliced_slots = ts.idx_in_sliced_slots;
			new_ts.s = new slot(ts.s);
			this->tained_slots.push_back(new_ts);
		}
		this->origin_index_to_sliced_index = ytt->origin_index_to_sliced_index;

		this->yet = new YEssenTaint(this->tained_slots, ytt->yt);
	}

	size_t get_sliced_index_from_origin_index(size_t origin_idx) {
		auto it = this->origin_index_to_sliced_index.find(origin_idx);
//		if (it == this->origin_index_to_sliced_index.end()) {
//			printf("at debug point!\n");
//		}
		y_assert(it != this->origin_index_to_sliced_index.end(), "it != this->origin_index_to_sliced_index.end(), but wrong.", __FILE__, __LINE__);
		size_t sliced_idx = it->second;
		return sliced_idx;
	}

	slot* get_origin_slot_in_sliced_trace(size_t origin_idx) {
		size_t sliced_idx = get_sliced_index_from_origin_index(origin_idx);
		SlicedSlot& ss = this->tained_slots.at(sliced_idx);
		return ss.s;
	}

	~YEssenTaintedTrace() {

	}

};

YEssenTaintedTrace* GetEssenTaintedTraceFromFile(std::string tpath);







