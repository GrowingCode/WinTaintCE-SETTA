#pragma once
#include "yyx_engine.h"
#include <tuple>

struct HandleRange {
	int handle_byte_start = -1;
	int handle_byte_size = -1;
};

extern const HandleRange DefaultHandleRange;

class YTaint;

enum SpecialHandleMode {
	InvokeDirectOrNonV = 0x1,
	SplitPartsAndEachPartInvokeDirectOrNonV = 0x2,
//	HandleMask = 0x4,
//	InvokeDirectOrNonVConsiderMaskAndHandleMask = InvokeDirectOrNonVConsiderMask | HandleMask,
//	SplitPartsAndEachPartInvokeDirectOrNonVAndHandleMask = SplitPartsAndEachPartInvokeDirectOrNonV | HandleMask,
};

typedef char MaskSrcOpndNum;
typedef short MaskAtomByteSize;
typedef short SplittedPartByteSize;

extern std::map<std::string, std::tuple<SpecialHandleMode, 
	MaskSrcOpndNum, MaskAtomByteSize, SplittedPartByteSize, 
	void (*)(YTaint* yt, instr* it, 
	size_t instr_index, InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record, 
	bool has_mask,
	HandleRange hr)>> special_handling_taint_meta;

void normal_handle_op(YTaint* yt, instr* it, size_t instr_index, int src_start_relative,
	InstrTaintInfo* instr_taint_info, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	HandleRange hr);

void handle_v(instr* it, int one_rep_byte_sz, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record);

void get_bytes_no_expand_consider_range(opnd* d, HandleRange hr, std::vector<MCByteID>& d_mbids);

bool InvokeDirectOrNonVConsiderMaskOpndNumAndRange(YTaint* yt, instr* it,
	size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	HandleRange hr,
	std::tuple<SpecialHandleMode,
	MaskSrcOpndNum, MaskAtomByteSize, SplittedPartByteSize,
	void (*)(YTaint* yt, instr* it, size_t instr_index, InstrTaintInfo* instr_taint_info,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
		bool has_mask,
		HandleRange hr)>& ss);

class VirtualTaintInfo {

public:
	std::vector<MCByteID> taint_bts;

	VirtualTaintInfo(std::vector<MCByteID>& taint_bts) {
		this->taint_bts = taint_bts;
	}

	VirtualTaintInfo(const VirtualTaintInfo& vti) {
		this->taint_bts = vti.taint_bts;
	}

	~VirtualTaintInfo() {
	}

};

class YTaint {

public:

	YTrace* te = NULL;

	// each instr has the following data, if not suitable or no data, the element in vector will be NULL. 
	std::vector<BranchDependInfo*> each_instr_branch_and_prev_depend_info;
	std::vector<InstrTaintInfo*> each_instr_taint_info;
	std::vector<InstrTaintRootInfo*> each_instr_taint_root_info;

	std::map<int, VirtualTaintInfo> virtual_taint_info;

	YTaint(YTrace* te) {
		this->te = te;
		CheckAllOpCanHandle();
	}

	YTrace* get_origin_trace() {
		return te;
	}

	~YTaint() {
		for (auto piifei : each_instr_branch_and_prev_depend_info) {
			delete piifei;
		}
		each_instr_branch_and_prev_depend_info.clear();
		for (auto eiti : each_instr_taint_info) {
			delete eiti;
		}
		each_instr_taint_info.clear();
		for (auto eitri : each_instr_taint_root_info) {
			delete eitri;
		}
		each_instr_taint_root_info.clear();
		//for (auto itr = virtual_taint_info.begin(); itr != virtual_taint_info.end(); itr++) {
		//	delete itr->second;
		//}
		virtual_taint_info.clear();
	}

	//	static std::map<int, std::pair<int, int>> initialize_reg_to_belonged_max_size_reg_and_offset();

		//	static std::map<std::string, DstSrcOpndTaintType> instruction_taint_type;
	//	static std::map<int, std::pair<int, int>> reg_to_belonged_max_size_reg_and_offset;

		// for value, each bit index of 1 is the index of byte which is tainted in reg. 
	std::map<MCByteID, TraceableByteTaintSetPosition> latest_taint_record;

	std::map<byte, uint64_t> e_flag_to_modifier_instr_index;

	void CheckAllOpCanHandle() {
		// check code
		std::set<std::string> unhandle_ops;
		for (slot* s : te->vect) {
			if (s->kind == trace_unit_type::is_op_meta) {
				instr* itr = (instr*)s->object;
				auto op_itr = taint_meta.find(itr->opname);
				if (op_itr != taint_meta.end()) {
					// do nothing. 
				}
				else {
					auto op_itr_sp = special_handling_taint_meta.find(itr->opname);
					if (op_itr_sp != special_handling_taint_meta.end()) {
						// do nothing. 
					}
					else {
						unhandle_ops.insert(itr->opname);
					}
				}
			}
		}
		if (unhandle_ops.size() > 0) {
			std::string uopss = YPrintUtil::print_to_string<std::string>(unhandle_ops);
			// print to console of the set about the total unhandled for whole trace. 
			printf("Wrong! Encounter unhandled opnames:%s, the program will abort.\n", uopss.c_str());
			abort();
		}
	}

	void SetUpPreSetTaintInfoForInstruction(int instr_index, VirtualTaintInfo vti) {
		virtual_taint_info.insert({ instr_index, vti });
	}

	void HandleTaintInTrace() {// int base_idx
		size_t v_sz = this->te->vect.size();
		for (size_t i = 0; i < v_sz; i++) {
			// debug code.
			if (i % 100000 == 0 || i == (v_sz - 1)) {
				printf("taint handling milestone turn (every 100000 or last) %lld/%lld.\n", i, v_sz - 1);
			}

			BranchDependInfo* branch_depend_info = NULL;
			InstrTaintInfo* instr_taint_info = NULL;
			InstrTaintRootInfo* instr_root_taint_info = NULL;

			slot* s = this->te->vect.at(i);

			// debug code. 
			//if (i == 18306) {
			//	printf("18306, s->kind:%d,s->line_idx:%lld.\n", s->kind, s->line_idx);
			//}
			//if (i == 18289) {
			//	printf("18289, s->kind:%d,s->line_idx:%lld.\n", s->kind, s->line_idx);
			//}
			//if (i == 18310) {
			//	printf("18310 begin, s->kind:%d,s->line_idx:%lld.\n", s->kind, s->line_idx);
			//	instr* it = (instr*)s->object;
			//	opnd* src0 = it->srcs.at(0);
			//	if (src0->detail_ot == opnd_type::is_mem) {
			//		std::vector<MCByteID> src0_bts;
			//		get_bytes_no_expand(src0, -1, -1, src0_bts);
			//		for (MCByteID src0_bt : src0_bts) {
			//			bool src0_bt_tainted = is_byte_tainted(src0_bt);
			//			printf("byte %s is_tainted:%d;\n", src0_bt.to_string().c_str(), src0_bt_tainted);
			//		}
			//	}
			//}

			if (s->kind == trace_unit_type::is_op_meta) {
				instr* it = (instr*)s->object;
				this->execute_instr_handle_taint(it, /*base_idx + */i, &instr_taint_info);
				// the invoke of branch_dependency_identify must be before instr_post_eflags_influence_identify. 
				// because, instr_post_eflags_influence_identify will write eflags usage which may set this it-i as eflags writter. 
				// actualy, branch_dependency_identify must not consider itself. 
				this->branch_dependency_identify(it, /*base_idx + */i, &branch_depend_info);
				this->instr_post_eflags_influence_identify(it, /*base_idx + */i);
			}
			else if (s->kind == trace_unit_type::is_high_level_op_type) {
				auto vti_i_itr = virtual_taint_info.find(i);
				if (vti_i_itr != virtual_taint_info.end()) {
					VirtualTaintInfo& vti = vti_i_itr->second;
					instr_taint_info = new InstrTaintInfo();
					taint_bytes_for_final(vti.taint_bts, i, instr_taint_info);
				}
				else {
					high_level_op* hop = (high_level_op*)s->object;
					this->execute_high_level_op_handle_taint(hop, /*base_idx + */i, &instr_taint_info);
				}
			}
			else {
				y_assert(false, "slot kind wrong.", __FILE__, __LINE__);
			}
			//if (i == 18310) {
			//	printf("18310 end, s->kind:%d,s->line_idx:%lld.\n", s->kind, s->line_idx);
			//}
			// this must invoke here, as execute_instr_handle_taint and execute_high_level_op_handle_taint will both set up instr_taint_info. 
			this->execute_instr_handle_root_taint(s, /*base_idx + */i, instr_taint_info, &instr_root_taint_info);
			//			if (i == 32759) {
			//				printf("at debug point!");
			//			}
			each_instr_branch_and_prev_depend_info.push_back(branch_depend_info);
			each_instr_taint_info.push_back(instr_taint_info);
			each_instr_taint_root_info.push_back(instr_root_taint_info);

//			printf("instr_taint_info is not NULL:%d.\n", instr_taint_info != NULL);
		}

		// debug code. 
//		for (size_t i = 0; i < v_sz; i++) {
//			print_debug_info(i);
//		}
	}

	void find_origin_taint_src(const size_t it_index, const MCByteID& src_key, InstrTaintRootInfo* itri) {
		std::set<TraceableByteTaintSetPosition> dt_root_info;
		auto sk_it = latest_taint_record.find(src_key);
		// debug code. 
		if (sk_it == latest_taint_record.end()) {
			printf("at debug point! wrong it_index:%lld\n", it_index);
		}
		y_assert(sk_it != latest_taint_record.end(), "src_key not found.", __FILE__, __LINE__);
		find_origin_taint(sk_it->second, dt_root_info);
		itri->origin_taint.insert({ src_key, dt_root_info });
	}

	void find_origin_taint_dst(size_t instr_idx, MCByteID dst_key, DstByteTaintInfoInInstr* dst_dbt, InstrTaintRootInfo* itri) {
		std::set<TraceableByteTaintSetPosition> dt_root_info;
		if (dst_dbt == NULL) {
			// only taint to itself. 
			TraceableByteTaintSetPosition tbtsp(instr_idx, dst_key);
			dt_root_info.insert(tbtsp);
		}
		else {
			for (auto iter = dst_dbt->all_srcs_taint_set_info_which_taint_this_dst.begin(); iter != dst_dbt->all_srcs_taint_set_info_which_taint_this_dst.end(); iter++) {
				find_origin_taint(*iter, dt_root_info);
			}
		}
		itri->origin_taint.insert({ dst_key, dt_root_info });
	}

	void find_origin_taint(const TraceableByteTaintSetPosition& tbtsp, std::set<TraceableByteTaintSetPosition>& dt_root_info) {
		MCByteID src_bid = tbtsp.bid;
		size_t src_set_dst_index = tbtsp.instr_index_which_set_dst_byte;
		InstrTaintRootInfo* eitri = each_instr_taint_root_info.at(src_set_dst_index);
		if (eitri == NULL) {
			printf("at debug point! src_set_dst_index:%lld is NULL but should not.\n", src_set_dst_index);
		}
		y_assert(eitri != NULL, "src_set_dst_index not found.", __FILE__, __LINE__);
		if (eitri != NULL) {
			auto eitri_ot_itr = eitri->origin_taint.find(src_bid);
			y_assert(eitri_ot_itr != eitri->origin_taint.end(), "src_bid not found.", __FILE__, __LINE__);
			std::set<TraceableByteTaintSetPosition>& t_root_info = eitri_ot_itr->second;
			dt_root_info.insert(t_root_info.begin(), t_root_info.end());
		}
	}

	void print_debug_info(size_t i) {
		InstrTaintInfo* i_instr_taint_info = each_instr_taint_info.at(i);
		if (i_instr_taint_info != NULL) {
			//			bool exist_taint = i_instr_taint_info->instr_dsts_exist_tainted || i_instr_taint_info->instr_srcs_exist_tainted;
			bool exist_taint = i_instr_taint_info->SrcRegOrMemOrStrictDstHaveTaintBeforeInstr();
			if (exist_taint) {
				// for each instruction, print whether its src or dst exist taint. 
				printf("=== exact tainted instr_index:%llu,%s,line_idx:%llu\n", i, te->get_instr_info(i).c_str(), this->te->vect.at(i)->line_idx);
				// for each instruction, print which dst byte is tainted and the srcs set position. 
				/*
				auto it = i_instr_taint_info->tainted_dst_byte_srcs_bytes_taint_set_info.begin();
				auto itend = i_instr_taint_info->tainted_dst_byte_srcs_bytes_taint_set_info.end();
				for (; it != itend; it++) {
					MCByteID mbid = it->first;
					printf("= dst_byte:%s;", mbid.to_string().c_str());

					DstByteTaintInfoInInstr* dbt = it->second;
					if (dbt != NULL) {
						for (uint16_t dst_opnd_idx : dbt->which_dst_opnd_idx_set_byte_taint) {
							printf("byteset_dst_opnd_idx:%d,", dst_opnd_idx);
						}
						for (TraceableByteTaintSetPosition tbt : dbt->all_srcs_taint_set_info_which_taint_this_dst) {
							printf("src_topnd_instr_index:%llu,src_topnd_byte_id:%s;", tbt.instr_index_which_set_dst_byte, tbt.bid.to_string().c_str());
						}
					}
					else {
						printf("first time taint set or reset.");
					}

					printf("\n");
				}
				*/
			}
		}

		BranchDependInfo* i_instr_brach_depend = each_instr_branch_and_prev_depend_info.at(i);
		// for each instruction, print branch and dependency info. 
		if (i_instr_brach_depend != NULL) {
			if (i_instr_brach_depend->depends_exist_tainted) {
				printf("== instr_index:%llu,%s,", i, te->get_instr_info(i).c_str());
				printf("depend_instr_idx(s):");
				for (uint64_t depend_idx : i_instr_brach_depend->depend_idxes) {
					printf("%llu;", depend_idx);
				}
				printf("\n");
			}
		}
	}

	void branch_dependency_identify(instr* it, size_t it_index, BranchDependInfo** branch_depend_info) {
		// handle eflags usage read. 
		uint32_t efu = it->eflags_usage_consider_all;
		if (efu > 0) {
			bool need_handle = false;
			for (byte ef = CF; ef < NULLEF; ef++) {
				if ((efu & ((uint64_t)EFLAGS_READ_CF << ef)) > 0) {
					need_handle = true;
					break;
				}
			}

			if (need_handle) {
				*branch_depend_info = new BranchDependInfo();
				for (byte ef = CF; ef < NULLEF; ef++) {
					if ((efu & ((uint64_t)EFLAGS_READ_CF << ef)) > 0) {
						// read the specified eflag. 
						auto it = e_flag_to_modifier_instr_index.find(ef);
						if (it != e_flag_to_modifier_instr_index.end()) {
							uint64_t depend_idx = it->second;
							//							bool depend_idx_is_taint = each_instr_taint_info.at(depend_idx)->instr_srcs_exist_tainted || each_instr_taint_info.at(depend_idx)->instr_dsts_exist_tainted
							//							if (each_instr_taint_info.size() <= depend_idx) {
							//								std::string in_bug_s = get_instr_info(it_index);
							//								printf("in_bug_instr:%s,eflags_write:%d;\n", in_bug_s.c_str(), efu >> 19);
							//							}
							InstrTaintInfo* iti = each_instr_taint_info.at(depend_idx);
							if (iti != NULL) {
								bool depend_idx_is_taint = iti->SrcRegOrMemOrStrictDstHaveTaintBeforeInstr();
								bool exist_taint_status = (*branch_depend_info)->depends_exist_tainted;
								(*branch_depend_info)->depends_exist_tainted = exist_taint_status || depend_idx_is_taint;
								(*branch_depend_info)->depend_idxes.insert(depend_idx);
							}
						}
					}// instr_idx_it
				}
			}
			//			assert((*cared_instr_idxes)->size() <= 1);
		}
	}

	void instr_post_eflags_influence_identify(instr* it, size_t it_index) {
		// handle eflag usage write. 
		if ((it->executed & (1 << ExecuteState::InstrExecuteResultBase)) == 1) {
			uint32_t efu = it->eflags_usage_consider_all;
			for (byte ef = CF; ef < NULLEF; ef++) {
				if ((efu & ((uint64_t)EFLAGS_WRITE_CF << ef)) > 0) {
					e_flag_to_modifier_instr_index.insert_or_assign(ef, it_index);
				}
			}
		}
		else {
			// do nothing. 
		}
		//else if ((it->executed & (1 << 2)) == 1) {
		//}
		//else {
		//	printf("== warning, instr_post_eflags_influence_identify unexpected extra exec info:%d.\n", it->executed);
		//}
	}

	// must have the ability to handle avx simd instruction or reps. 
	void execute_instr_handle_taint(instr* it, size_t it_index, InstrTaintInfo** instr_taint_info)
	{
		//		if (it->module_name == "Resolved_ucrtbase.dll_1048577" and (it->offset == 98865 || it->offset == 100016)) {
		//			printf("at debug point.\n");
		//		}
		if ((it->executed & 1) > 0) {
			//*instr_taint_info = new InstrTaintInfo();
			//auto itr = taint_meta.find(it->opname);
			//if (itr != taint_meta.end()) {
			//	std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>& dst_to_its_srcs = itr->second;
			//}
			//else {
			//	printf("Wrong! unrecognized opname:%s, must handle it and set taint info in taint_meta.\n", it->opname.c_str());
			//	y_assert(false);
			//}
			handle_dsts_taint_info(it, it_index, instr_taint_info);// d, in_itr->second, it->srcs,  
		}
		else if ((it->executed & 1) == 0) {
		}
		else {
			printf("== warning, execute_instr_handle_taint unexpected extra exec info:%d.\n", it->executed);
			y_assert(false, "execute state wrong.", __FILE__, __LINE__);
		}
	}

	void execute_instr_handle_root_taint(slot* s, size_t it_index, InstrTaintInfo* iti, InstrTaintRootInfo** itri) {
#if taint_simplified_mode == 1
#else
		if (iti != NULL) {
			bool use_dst_srcs = false;
			if (s->kind == trace_unit_type::is_high_level_op_type) {
				use_dst_srcs = true;
			}
			else if (s->kind == trace_unit_type::is_op_meta) {
				instr* it = (instr*)s->object;
				if (it->dsts.size() > 0) {
					use_dst_srcs = true;
				}
				//else {
				//	use_dst_srcs = false;
				//}
			}
			else {
				y_assert(false, "slot kind wrong.", __FILE__, __LINE__);
			}
			bool create = false;
			if (use_dst_srcs) {
				if (iti->tainted_dst_byte_srcs_bytes_taint_set_info.size() > 0) {
					create = true;
				}
			}
			else {
				if (iti->tainted_src_reg_bytes.size() > 0 || iti->tainted_src_mem_bytes.size() > 0) {
					create = true;
				}
			}
//			if (iti->tainted_dst_byte_srcs_bytes_taint_set_info.size() > 0 || iti->tainted_src_reg_bytes.size() > 0 || iti->tainted_src_mem_bytes.size() > 0) {
			if (create) {
				*itri = new InstrTaintRootInfo();
//				if (iti->tainted_dst_byte_srcs_bytes_taint_set_info.size() > 0) {
				if (use_dst_srcs) {
					for (auto iter = iti->tainted_dst_byte_srcs_bytes_taint_set_info.begin(); iter != iti->tainted_dst_byte_srcs_bytes_taint_set_info.end(); iter++) {
						const MCByteID& dst_byte = iter->first;
						DstByteTaintInfoInInstr* dst_taint_info = iter->second;
						find_origin_taint_dst(it_index, dst_byte, dst_taint_info, *itri);
					}
					//					printf("the %d instruction:\n", i);
					//					printf("key byte: %llu, type: %d\n", initkey.reg_id_or_mem_with_byte_offset, initkey.byte_type);
					//					printf("original dst bytes:\n");
					//					for (auto iter = origin_taint[initkey].begin(); iter != origin_taint[initkey].end(); iter++)
					//					{
					//						printf("original byte: %llu, type: %d\n", iter->reg_id_or_mem_with_byte_offset, iter->byte_type);
					//					}
					//					printf("\n");
				}
				else {
					if (iti->tainted_src_reg_bytes.size() > 0) {
						for (const MCByteID& tsb : iti->tainted_src_reg_bytes) {
							find_origin_taint_src(it_index, tsb, *itri);
						}
					}
					if (iti->tainted_src_mem_bytes.size() > 0) {
						for (const MCByteID& tsb : iti->tainted_src_mem_bytes) {
							find_origin_taint_src(it_index, tsb, *itri);
						}
					}
				}
			}
		}
#endif
	}

	void execute_high_level_op_handle_taint(high_level_op* hop, int it_index, InstrTaintInfo** instr_taint_info) {
		if (hop->pre_or_post == 1 and hop->executed_successful == 1) {
			byte* addr = reinterpret_cast<byte*>(hop->addr);
			uint64_t sz = hop->num;
			if (hop->hop_name == "read_file") {
				y_assert(hop->return_reg_id > 0, "hop_name read_file wrong.", __FILE__, __LINE__);
				*instr_taint_info = new InstrTaintInfo();
				//				printf("executed!, %p, %llu.\n", addr, sz);
				taint_memory_for_final(addr, sz, it_index, *instr_taint_info);
				// here, the return xax must be untainted, as it is whether the hop is successful. 
				untaint_register(hop->return_reg_id);
			}
			else if (hop->hop_name == "heap_free") {
				y_assert(hop->return_reg_id > 0, "hop_name heap_free wrong.", __FILE__, __LINE__);
				untaint_memory(addr, sz, it_index);
				// here, the return xax must be untainted, as it is whether the hop is successful. 
				untaint_register(hop->return_reg_id);
			}
			else if (hop->hop_name == "heap_alloc") {
				y_assert(hop->return_reg_id > 0, "hop_name heap_alloc wrong.", __FILE__, __LINE__);
				untaint_memory(addr, sz, it_index);
				untaint_register(hop->return_reg_id);
			}
			else {
				y_assert(false, "hopname unseen.", __FILE__, __LINE__);
			}
		}
	}

	//void direct_taint_byte_and_initial_0th_virtual_slot_for_test(MCByteID mbid)
	//{
	//	if (each_instr_branch_and_prev_depend_info.size() == 0) {
	//		each_instr_branch_and_prev_depend_info.push_back(NULL);
	//		InstrTaintInfo* iti = new InstrTaintInfo();
	//		each_instr_taint_info.push_back(iti);
	//		InstrTaintRootInfo* itri = new InstrTaintRootInfo();
	//		each_instr_taint_root_info.push_back(itri);
	//	}
	//	
	//	y_assert(each_instr_taint_info.size() == 1);

	//	latest_taint_record.insert_or_assign(mbid, TraceableByteTaintSetPosition(0, mbid));

	//	InstrTaintInfo* iti = each_instr_taint_info.at(0);
	//	iti->PutDstByteSrcsBytesTaintSetInfo(mbid, NULL);

	//	InstrTaintRootInfo* itri = each_instr_taint_root_info.at(0);
	//	{
	//		std::set<TraceableByteTaintSetPosition> dt_root_info;
	//		// only taint to itself. 
	//		TraceableByteTaintSetPosition tbtsp(0, mbid);
	//		dt_root_info.insert(tbtsp);
	//		itri->origin_taint.insert({ mbid, dt_root_info });
	//	}
	//}

	void untaint_memory(byte* addr, size_t mlen, size_t instr_index)
	{
		for (int i = 0; i < mlen; i++) {
			byte* rm = addr + i;
			MCByteID mbid((uint64_t)rm);
			untaint_byte(mbid);
			//			latest_taint_record.erase(mbid);
		}
	}

	void untaint_register(uint16_t reg_id)
	{
		// the function may return void, in this case, the reg_id will be DR_REG_NULL. 
		// some complex return structure may also return NULL in assembly code, because it will allocate that complex structure on stack and pass stack pointer as argument. 
		if (reg_id > DR_REG_NULL) {
			std::vector<MCByteID> bids;
			get_reg_bytes(reg_id, 0, get_return_dr_reg_size_in_bytes(reg_id), bids);
			untaint_bytes(bids);
			//			for (MCByteID bid : bids) {
			//				latest_taint_record.erase(bid);
			//			}
		}
	}

	//	void handle_srcs_taint_info(std::vector<opnd*>& srcs, InstrTaintInfo* instr_taint_info) {
	//		for (auto src : srcs) {
	//			handle_src_taint_info(src, instr_taint_info);
	//		}
	//	}

//	void handle_src_taint_info(opnd* src, InstrTaintInfo* instr_taint_info) {
//		std::vector<MCByteID> bts;
//		get_bytes_no_expand(src, -1, -1, bts);
//		bool sit = false;
//		for (MCByteID bt : bts) {
//			sit = sit || is_byte_tainted(bt);
//		}
//		instr_taint_info->instr_exist_tainted = instr_taint_info->instr_exist_tainted || sit;
//	}

	void handle_one_dst_taint_info(instr* it, size_t instr_index, int dst_idx,
		std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>& dst_srcs_taint_meta, 
		int src_start_relative, InstrTaintInfo* instr_taint_info,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
		HandleRange hr = DefaultHandleRange)
	{
		auto dst_srcs_meta = dst_srcs_taint_meta.find(dst_idx);
		y_assert(dst_srcs_meta != dst_srcs_taint_meta.end(), "dst_idx not found.", __FILE__, __LINE__);

		opnd* d = it->dsts.at(dst_idx);
		size_t d_sz = d->expanded_infos.size();
		y_assert(d_sz == 0, "d_sz must == 0, but wrong.", __FILE__, __LINE__);
		update_dst_from_srcs_tainted(instr_index, dst_srcs_meta->second, src_start_relative, it->srcs, dst_idx, d, 
			instr_taint_info, curr_session_taint_record, hr);
	}

	void count_tainted_src_reg_for_opnd(opnd* opd, InstrTaintInfo* instr_taint_info) {
		if (opd->detail_ot == opnd_type::is_reg) {
			//y_assert(opd->detail_ot == opnd_type::is_reg);
			uint16_t reg_id = opd->reg_id_mem_addr;
			RegType rt = RegType::src_reg;
			if (opd->optype == trace_unit_type::is_src) {
				rt = RegType::src_reg;
			}
			//else if (opd->optype == trace_unit_type::is_dst) {
			//	rt = RegType::dst_reg;
			//}
			else {
				y_assert(false, "optype wrong, must be RegType::src_reg.", __FILE__, __LINE__);
			}
			judge_and_add_tainted_common_src_or_dst_max_reg(reg_id, opd->actual_size, rt, instr_taint_info);
		}
		else {
			// do nothing.
//			assert(false);
		}
	}

	void count_tainted_src_mem_for_opnd(opnd* opd, InstrTaintInfo* instr_taint_info) {
		if (opd->detail_ot == opnd_type::is_mem) {
			y_assert(opd->optype == trace_unit_type::is_src, "optype must is_src, but wrong.", __FILE__, __LINE__);
			//			y_assert(opd->op == "mem");
			std::vector<MCByteID> mbts;
			get_bytes_no_expand(opd, -1, -1, mbts);
			for (MCByteID mbt : mbts) {
				if (is_byte_tainted(mbt)) {
#if taint_simplified_mode == 1
					instr_taint_info->has_tainted_src_mem_bytes = true;
#else
					instr_taint_info->tainted_src_mem_bytes.insert(mbt);
#endif
//					instr_taint_info->tainted_src_bytes.insert(mbt);
				}
			}
		}
	}

	// core logic of dst taint analysis
	// int d_idx, opnd* d, std::vector<std::pair<int, DstSrcOpndTaintType>>& tainted_src_idxs, std::vector<opnd*>& srcs, 
	void handle_dsts_taint_info(instr* it, size_t instr_index,
//		std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>& dst_to_its_srcs,
		InstrTaintInfo** res_instr_taint_info)
	{
		// before any taint execution, we must handle used src, dst and in_mem_use regs. 
		// update tainted_in_use_max_reg_before_instr by iterating all src and dst's max reg and reg_use_in_mem again, but more efficiently. 
		// as here, we only need to handle reg. 
		// handle and record all tainted src mem bytes. 
//		if (it->container->line_idx == 100301) {
//			printf("at debug point\n!");
//		}
//		if (instr_index == 32883) {
//			latest_taint_record;
//			printf("at debug point.\n");
//		}
		// count code begin. 
		// the following two for loops only count whether this src (include use_in_mem) or dst (include max) has taint info. 
		// if it has, before instr execution, we should record. 
		// even if after execution, the dst is untainted, we should also record to make Triton untaint. 
		InstrTaintInfo* instr_taint_info = new InstrTaintInfo();
		for (opnd* src : it->srcs) {
			count_tainted_src_reg_for_opnd(src, instr_taint_info);
			count_tainted_src_mem_for_opnd(src, instr_taint_info);
		}
		for (reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* reg_use_im_mem_or_dst_max_reg : it->reg_use_in_mem_ref_or_dst_reg_max_reg_vect) {
			RegType rt = src_use_in_mem_reg;
			if (reg_use_im_mem_or_dst_max_reg->type == RegUseInMemOrDstMaxRegType::reg_used_in_mem_ref) {
				rt = RegType::src_use_in_mem_reg;
			}
			else if (reg_use_im_mem_or_dst_max_reg->type == RegUseInMemOrDstMaxRegType::max_reg_of_dst_reg) {
				rt = RegType::dst_max_reg;
			}
			else {
				printf("==$! assert false for RegType!");
				y_assert(false, "reg_use_im_mem_or_dst_max_reg->type wrong.", __FILE__, __LINE__);
			}
			uint16_t reg_id = reg_use_im_mem_or_dst_max_reg->reg_id;
			judge_and_add_tainted_common_src_or_dst_max_reg(reg_id, reg_use_im_mem_or_dst_max_reg->reg_val_size, rt, instr_taint_info);
		}

		//if (instr_index == 18310) {
		//	printf("tainted_src_mem_bytes_size:%lld;\n", instr_taint_info->tainted_src_mem_bytes.size());
		//	std::string str = YPrintUtil::print_to_string(instr_taint_info->tainted_src_mem_bytes);
		//	printf("tainted_src_mem_bytes detail:%s.\n", str.c_str());
		//	printf("tainted_src_reg_bytes_size:%lld;\n", instr_taint_info->tainted_src_reg_bytes.size());
		//	std::string str2 = YPrintUtil::print_to_string(instr_taint_info->tainted_src_reg_bytes);
		//	printf("tainted_src_reg_bytes detail:%s.\n", str2.c_str());
		//}
		
		// add code to invoke update_dst_srcs_byte_level_traceable_info_in_instr_taint_info 
		std::map<MCByteID, SessionByteTaintSetInfo> curr_session_taint_record;

//		if (it->container->line_idx == 155572) {
//			printf("at debug point!\n");
//		}

//		std::string no_v_opname = it->opname;
///		bool v_prefixed = YStringUtil::startsWith(it->opname, "v");
//		if (v_prefixed) {
//			auto hc_it = taint_meta.find(it->opname);
//			auto shc_it = special_handling_taint_meta.find(it->opname);
//			if (hc_it != taint_meta.end() || shc_it != special_handling_taint_meta.end()) {
//				v_prefixed = false;
//			}
//			else {
//				no_v_opname = it->opname.substr(1);
//			}
//		}
		auto nvo_s_it = special_handling_taint_meta.find(it->opname);
		if (nvo_s_it != special_handling_taint_meta.end()) {
			// logic to invoke special_handling. 
			auto& ss = nvo_s_it->second;
			SpecialHandleMode s_handle_mode = std::get<0>(ss);
			int mask_src_opnd_num = std::get<1>(ss);
			int mask_atom_byte_size = std::get<2>(ss);
			int splitted_part_byte_size = std::get<3>(ss);
			bool has_mask = false;
			if (splitted_part_byte_size > 0) {
				y_assert(mask_src_opnd_num == -1 and splitted_part_byte_size > 0, "mask_src_opnd_num or splitted_part_byte_size wrong .", __FILE__, __LINE__);
				opnd* dst = it->dsts.at(0);
				int rep_times = dst->actual_size / splitted_part_byte_size;
				for (int i = 0; i < rep_times; i++) {
					HandleRange hr = { i * splitted_part_byte_size, splitted_part_byte_size };
					has_mask = InvokeDirectOrNonVConsiderMaskOpndNumAndRange(this, it, instr_index, instr_taint_info,
						curr_session_taint_record, hr, ss);
				}
			}
			else {
				// splitted_part_byte_size <= 0
				has_mask = InvokeDirectOrNonVConsiderMaskOpndNumAndRange(this, it, instr_index, instr_taint_info,
					curr_session_taint_record, { 0, 0 }, ss);
			}
//			if ((s_handle_mode & SpecialHandleMode::InvokeDirectOrNonV) > 0) {
//			if ((s_handle_mode & SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV) > 0) {
			if (has_mask) {
				handle_v(it, mask_atom_byte_size, curr_session_taint_record);
			}
//			y_assert((s_handle_mode & SpecialHandleMode::InvokeDirectOrNonVConsiderMask) > 0 || (s_handle_mode & SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV) > 0 || (s_handle_mode & SpecialHandleMode::HandleMask) > 0);
		}
		else {
			auto nvo_it = taint_meta.find(it->opname);
			if (nvo_it != taint_meta.end()) {
				// fall into normal handling. 
				// iterate each dst to handle normal taint without pack or simd. 
				normal_handle_op(this, it, instr_index, 0, instr_taint_info, curr_session_taint_record, DefaultHandleRange);
			}
			else {
				y_assert(false, "opname in special_handling not found.", __FILE__, __LINE__);
			}
		}

		std::string instr_info = get_instr_info(it, instr_index);
		update_total_taint_with_taint_session(curr_session_taint_record, instr_info, instr_taint_info);

		// untaint logic has be reimplemented, iterate all dst opnd's bytes and judge whether it is tainted or un_changed, if not, untaint them. 
		for (opnd* dst : it->dsts) {
			std::vector<MCByteID> no_expand_bts;
			get_bytes_no_expand(dst, -1, -1, no_expand_bts);
			untaint_according_to_session_taint_info(no_expand_bts, curr_session_taint_record);
			std::vector<MCByteID> expand_bts;
			int expd_size = dst->expanded_infos.size();
			for (int ei = 0; ei < expd_size; ei++) {
				get_bytes_in_expanded(dst, ei, expand_bts);
			}
			untaint_according_to_session_taint_info(expand_bts, curr_session_taint_record);
		}

		if (instr_taint_info->SrcRegOrMemOrStrictDstHaveTaintBeforeInstr()) {
			*res_instr_taint_info = instr_taint_info;
		}
		else {
			delete instr_taint_info;
		}

		// the dst count logic must be run here, because the dst may be untainted after the taint processing. 
//		for (opnd* dst : it->dsts) {
//			count_tainted_reg_max_reg_for_opnd(dst, instr_taint_info);
//		}
		//for (reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* reg_use_im_mem_or_dst_max_reg : it->reg_use_in_mem_ref_or_dst_reg_max_reg_vect) {
		//	if (reg_use_im_mem_or_dst_max_reg->type == RegUseInMemOrDstMaxRegType::max_reg_of_dst_reg) {
		//		uint16_t reg_id = reg_use_im_mem_or_dst_max_reg->reg_id;
		//		judge_and_add_tainted_in_use_reg_and_max_reg(reg_id, reg_use_im_mem_or_dst_max_reg->reg_val_size, RegType::dst_max_reg, instr_taint_info);
		//	}
		//}
		//		for (MCByteID d_mbid : tainted_d_mbids) {
		//			bool is_tainted = tainted_d_mbids.find(d_mbid) != tainted_d_mbids.end();
		//			bool is_not_change = not_change_d_mbids.find(d_mbid) != not_change_d_mbids.end();
		//			if (!(is_tainted || is_not_change)) {
		//				untaint_byte(d_mbid);
		//			}
		//		}
		//		int dst_idx = -1;
		//		for (opnd* dst : it->dsts) {
		//			dst_idx++;
		//			auto dit = dst_to_its_srcs.find(dst_idx);
					// the dst is not set by dst_to_its_srcs meta, meaning that it is valueless for taint analysis. 
		//			if (dit == dst_to_its_srcs.end()) {
						// untaint all bytes of dst. 
		//				std::vector<MCByteID> dbts;
		//				get_bytes(dst, dbts);
		//				untaint_bytes(dbts);
		//			}
		//		}

		// judge whether src is tainted, if not, handle it. 
//		int sidx = -1;
//		for (opnd* src : it->srcs) {
//			sidx++;
//			if (handled_srcs.find(sidx) == handled_srcs.end()) {
				// not handled yet, handle it. 
//				handle_src_taint_info(src, instr_taint_info);
//			}
//		}
	}

	void set_up_tainted_src_bytes(uint16_t reg_id, int reg_size, InstrTaintInfo* instr_taint_info) {
		std::vector<MCByteID> rbts;
		get_reg_bytes(reg_id, 0, reg_size, rbts);
		for (MCByteID rbt : rbts) {
			bool ibt = is_byte_tainted(rbt);
			if (ibt) {
#if taint_simplified_mode == 1
				instr_taint_info->has_tainted_src_reg_bytes = true;
#else
				instr_taint_info->tainted_src_reg_bytes.insert(rbt);
#endif
			}
		}
	}

	// this function should assume that before instr, this handles src's reg_use_in_mem, after instr, this handles dst max reg. 
	void judge_and_add_tainted_common_src_or_dst_max_reg(uint16_t reg_id, int reg_size, RegType rt, InstrTaintInfo* instr_taint_info) {
		std::pair<int, int> max_reg_and_offset = get_belonged_max_size_reg_id_and_offset(reg_id);
		//this function should be split into two parts, one for in_use_mem and dst_max, another for common src. 
		uint16_t max_reg_id = max_reg_and_offset.first;
		{
			// here, judge all possible dst max reg's bytes. 
			MCByteID reg_min_inclusive(max_reg_id, 0, false);
			MCByteID reg_max_exclusive(max_reg_id, -1, true);
			// if the latest_taint_record contains element in the specified range, we think max_reg is tainted. 
			if (judge_at_least_one_reg_byte_in_byte_range_is_tainted(reg_min_inclusive, reg_max_exclusive)) {
				switch (rt) {
//				case RegType::src_reg:
				//case RegType::src_use_in_mem_reg:
				//	instr_taint_info->tainted_src_and_use_in_mem_max_reg_before_instr.insert(max_reg_id);
				//	break;
//				case RegType::dst_reg:
				case RegType::dst_max_reg:
#if taint_simplified_mode == 1
					instr_taint_info->has_tainted_dst_max_reg_before_instr = true;
#else
					instr_taint_info->tainted_dst_max_reg_before_instr.insert(max_reg_id);
#endif
					break;
				//default:
				//	y_assert(false, "reg type wrong.", __FILE__, __LINE__);
				//	break;
				}
			}
		}
		{
			// here, judge only the reg_id's bytes. 
			MCByteID reg_min_inclusive(max_reg_id, max_reg_and_offset.second, false);
			MCByteID reg_max_exclusive(max_reg_id, max_reg_and_offset.second + reg_size, false);
			if (judge_at_least_one_reg_byte_in_byte_range_is_tainted(reg_min_inclusive, reg_max_exclusive)) {
				switch (rt) {
				case RegType::src_reg:
//				case RegType::src_use_in_mem_reg:
#if taint_simplified_mode == 1
					instr_taint_info->has_tainted_src_reg_before_instr = true;
#else
					instr_taint_info->tainted_src_reg_before_instr.insert(reg_id);
#endif
//					instr_taint_info->tainted_src_and_use_in_mem_reg_before_instr.insert(reg_id);
					set_up_tainted_src_bytes(reg_id, reg_size, instr_taint_info);
					break;
//				case RegType::dst_reg:
				//case RegType::dst_max_reg:
				//	instr_taint_info->tainted_dst_reg_before_instr.insert(reg_id);
				//	break;
				//default:
				//	y_assert(false, "reg type wrong.", __FILE__, __LINE__);
				//	break;
				}
			}
		}
		//		return cover;
	}

	bool judge_at_least_one_reg_byte_in_byte_range_is_tainted(MCByteID reg_min_inclusive, MCByteID reg_max_exclusive) {
		// if the latest_taint_record contains element in the specified range, we think max_reg is tainted. 
		bool cover = YMapUtil<MCByteID, TraceableByteTaintSetPosition>::specified_range_cover_some_key_in_map(reg_min_inclusive, reg_max_exclusive, latest_taint_record);
		return cover;
	}

	std::string get_instr_info(instr* it, size_t instr_index) {
		std::string info = "";
		info += it->module_name + ",moffset:" + std::to_string(it->offset) + ",instr_index:" + std::to_string(instr_index);
		return info;
	}

	void untaint_according_to_session_taint_info(std::vector<MCByteID>& cared_bts, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record) {
		for (MCByteID cared_bt : cared_bts) {
			if (curr_session_taint_record.find(cared_bt) == curr_session_taint_record.end()) {
				// should untaint, it is not (taint or (keep_same,NoChange))
				untaint_byte(cared_bt);
			}
		}
	}

	//	uint64_t cared_reg_part(expanded_opnd_info* eoi) {
	//		uint64_t f_reg_info = 0;
	//		uint64_t reg_info = (uint64_t)1 << (byte)eoi->reg_inner_rel_addr_or_mem_addr;
	//		for (int ri = 0; ri < eoi->sz; ri++) {
	//			uint64_t temp = reg_info << ri;
	//			f_reg_info |= temp;
	//		}
	//		return f_reg_info;
	//	}

//	void update_dst_srcs_tainted_info(instr* it, int d_idx, opnd* d, std::vector<std::pair<int, DstSrcOpndTaintType>>& tainted_src_idxs, std::vector<opnd*>& srcs, int expand_idx, InstrTaintInfo* instr_taint_info) {
//		bool dst_total_tainted = false;
//		return dst_total_tainted;
//	}

	/*bool handle_src_reg_opnd_taint(opnd* s, int expand_idx) {
		bool src_total_tainted = false;
		if (expand_idx > -1) {
			assert(s->expanded_infos->size() > expand_idx);
			expanded_opnd_info* eoi = s->expanded_infos->at(expand_idx);
			src_total_tainted = is_register_tainted(s->reg_id_mem_addr_pc_addr_imm, eoi->reg_inner_rel_addr_or_mem_addr, eoi->sz);
		}
		else {
			src_total_tainted = is_register_tainted(s->reg_id_mem_addr_pc_addr_imm, 0, s->actual_size);
		}
		return src_total_tainted;
	}*/

	//	void get_reg_opnd_bytes(opnd* s, std::vector<MCByteID>& res) {
	//		get_reg_bytes(s->reg_id_mem_addr_pc_addr, 0, s->actual_size, res);
	//	}

		/*bool handle_src_mem_opnd_taint(opnd* s, int expand_idx) {
			bool src_total_tainted = false;
			if (expand_idx > -1) {
				assert(s->expanded_infos->size() > expand_idx);
				expanded_opnd_info* eoi = s->expanded_infos->at(expand_idx);
				src_total_tainted = is_memory_tainted(reinterpret_cast<byte*>(eoi->reg_inner_rel_addr_or_mem_addr), eoi->sz);
			}
			else {
				src_total_tainted = is_memory_tainted(reinterpret_cast<byte*>(s->reg_id_mem_addr_pc_addr_imm), s->actual_size);
			}
			return src_total_tainted;
		}*/

		//	void get_mem_opnd_bytes(opnd* s, std::vector<MCByteID>& res) {
		//		get_mem_bytes(reinterpret_cast<byte*>(s->reg_id_mem_addr_pc_addr), s->actual_size, res);
		//	}

	//	void get_bytes(opnd* o, std::vector<MCByteID>& res) {
	//		if (o->op == "reg") {
	//			get_reg_opnd_bytes(o, res);
	//		}
	//		else if (o->op == "mem") {
	//			get_mem_opnd_bytes(o, res);
	//		}
	//		else {
				// do nothing. 
	//			assert(false);
	//		}
	//	}

	void update_dst_taint_info_if_src_is_tainted(size_t instr_index, InstrTaintInfo* instr_taint_info, int opnd_d_idx,
		MCByteID d_mbid, MCByteID s_mbid,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record)
	{
		auto sit = latest_taint_record.find(s_mbid);
		if (sit != latest_taint_record.end()) {
			// tainted. 
//			instr_taint_info->tainted_src_bytes.insert(s_mbid);
#if taint_simplified_mode == 1
			instr_taint_info->PutDstByteSrcsBytesTaintSetInfo();
			instr_taint_info->has_tainted_dst_byte_srcs_bytes_taint_set_info = true;
#else
			auto it = instr_taint_info->tainted_dst_byte_srcs_bytes_taint_set_info.find(d_mbid);

			DstByteTaintInfoInInstr* dbt = NULL;

			if (it == instr_taint_info->tainted_dst_byte_srcs_bytes_taint_set_info.end()) {
				dbt = new DstByteTaintInfoInInstr();
				instr_taint_info->PutDstByteSrcsBytesTaintSetInfo(d_mbid, dbt);
			}
			else {
				dbt = it->second;
			}
			y_assert(dbt != NULL, "dbt != NULL.", __FILE__, __LINE__);

			if (dbt != NULL) {
				TraceableByteTaintSetPosition tbtsp = sit->second;
				dbt->all_srcs_taint_set_info_which_taint_this_dst.insert(tbtsp);
				dbt->which_dst_opnd_idx_set_byte_taint.insert(opnd_d_idx);
			}
#endif
			taint_byte_for_curr_session(d_mbid, instr_index, SessionByteTaintType::SetTaint, curr_session_taint_record);
		}
	}

	void update_dst_unchanged(MCByteID d_mbid, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record) {
		auto ires = curr_session_taint_record.insert({ d_mbid, SessionByteTaintSetInfo() });
		if (ires.second == false) {
			y_assert(ires.first->second.sbtt == SessionByteTaintType::UnChanged, "SessionByteTaintType should be UnChanged.", __FILE__, __LINE__);
		}
	}

	void update_dst_from_srcs_tainted(size_t instr_index, std::vector<std::pair<int, DstSrcOpndTaintType>>& tainted_src_idxs,
		int src_start_relative, // for v-prefixed, we must ignore k1 mask. 
		std::vector<opnd*>& srcs, 
		uint16_t opnd_d_idx, opnd* d, InstrTaintInfo* instr_taint_info,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
		HandleRange hr = DefaultHandleRange)
	{
		std::vector<MCByteID> d_mbids;
		get_bytes_no_expand_consider_range(d, hr, d_mbids);
		//int d_sz = -1;
		//if (hr.handle_byte_size > 0) {
		//	d_sz = hr.handle_byte_size;
		//}
		//get_bytes_no_expand(d, hr.handle_byte_start, d_sz, d_mbids);
		
		// handle taint. 
		int d_b_idx = -1;
		for (MCByteID d_mbid : d_mbids) {
			d_b_idx++;
			for (std::pair<int, DstSrcOpndTaintType>& src_idx_it_taint_info : tainted_src_idxs) {
				int src_idx = src_idx_it_taint_info.first + src_start_relative;
				DstSrcOpndTaintType opnd_ttype = src_idx_it_taint_info.second;
				if (src_idx < srcs.size()) {
					//					handled_srcs.insert(src_idx);
					opnd* s = srcs.at(src_idx);
					
					std::vector<MCByteID> s_mbids;
					get_bytes_no_expand_consider_range(s, hr, s_mbids);
					
					//int s_sz = -1;
					//if (hr.handle_byte_size > 0) {
					//	s_sz = hr.handle_byte_size;
					//}
					//get_bytes_no_expand(s, hr.handle_byte_start, s_sz, s_mbids);
					
					//					bool src_tainted = src_is_tainted(s, expand_idx);
					//					src_total_tainted = src_total_tainted || src_tainted;
					//					bool src_idx_is_tainted = update_dst_from_src_tainted(opnd_tinfo, s, expand_idx, d_idx, d, instr_taint_info);// src_tainted, 
					//					dst_total_tainted = dst_total_tainted || src_idx_is_tainted;

					switch (opnd_ttype) {
					case ByteToAllBytes:
					{
						for (MCByteID s_mbid : s_mbids) {
							//							dst_is_tainted = dst_is_tainted || ;
							update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_mbid, curr_session_taint_record);
						}
					}
					break;
					case ByteToByteOthersUntaint:
					case ByteToByteOthersSignExtend:
//					case ByteToByteOthersNotChange:
					{
						if (d_b_idx < s_mbids.size()) {
							MCByteID s_at_didx_bid = s_mbids.at(d_b_idx);
							//							dst_is_tainted = dst_is_tainted || ;
							update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_at_didx_bid, curr_session_taint_record);
						}
						else {
							if (opnd_ttype == ByteToByteOthersUntaint) {
								// do nothing. 
								// in default, we will untaint the is_not_tainted dst byte. 
							}
							else if (opnd_ttype == ByteToByteOthersSignExtend) {
								// dst byte is tainted based on the sign byte. 
								MCByteID bit_sign_byte = s_mbids.back();
								//								dst_is_tainted = dst_is_tainted || ;
								update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, bit_sign_byte, curr_session_taint_record);
							}
//							else if (opnd_ttype == ByteToByteOthersNotChange) {
								// record the not change dst byte. 
//								update_dst_unchanged(d_mbid, curr_session_taint_record);
//							}
							else {
								y_assert(false, "Taint Byte Type Wrong.", __FILE__, __LINE__);
							}
						}
					}
					break;
					//case ByteToEvenHalfIndexByte:
					//{
					//	if (d_b_idx % 2 == 0) {
					//		// must handle. 
					//		int s_cared_idx = d_b_idx / 2;
					//		MCByteID s_idx_mbid = s_mbids.at(s_cared_idx);
					//		//							dst_is_tainted = dst_is_tainted || ;
					//		update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_idx_mbid, curr_session_taint_record);
					//	}
					//}
					//break;
					//case ByteToOddHalfIndexByte:
					//{
					//	if (d_b_idx % 2 == 1) {
					//		// must handle. 
					//		int s_cared_idx = d_b_idx / 2;
					//		MCByteID s_idx_mbid = s_mbids.at(s_cared_idx);
					//		//							dst_is_tainted = dst_is_tainted || ;
					//		update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_idx_mbid, curr_session_taint_record);
					//	}
					//}
					//break;
					//case QWordToEvenHalfIndexQWord:
					//{
					//	int qword_idx = d_b_idx / 4;
					//	if (qword_idx % 2 == 0) {
					//		int s_cared_qword_idx = qword_idx / 2;
					//		int s_cared_idx = s_cared_qword_idx * 4 + d_b_idx % 4;
					//		MCByteID s_idx_mbid = s_mbids.at(s_cared_idx);
					//		//							dst_is_tainted = dst_is_tainted || ;
					//		update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_idx_mbid, curr_session_taint_record);
					//	}
					//}
					//break;
					//case QWordToOddHalfIndexQWord:
					//{
					//	int qword_idx = d_b_idx / 4;
					//	if (qword_idx % 2 == 1) {
					//		int s_cared_qword_idx = qword_idx / 2;
					//		int s_cared_idx = s_cared_qword_idx * 4 + d_b_idx % 4;
					//		MCByteID s_idx_mbid = s_mbids.at(s_cared_idx);
					//		//							dst_is_tainted = dst_is_tainted || ;
					//		update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d_mbid, s_idx_mbid, curr_session_taint_record);
					//	}
					//}
					//break;
					default:
						y_assert(false, "Taint Byte Type Wrong.", __FILE__, __LINE__);
						break;
					}
				}
			}
			//			if (dst_is_tainted) {
			//				tainted_d_mbids.insert(d_mbid);
			//				instr_taint_info->instr_exist_tainted = instr_taint_info->instr_exist_tainted || dst_is_tainted;
			//			}
		}
	}

	void update_dst_bytes_from_src_bytes_tainted_one_by_one(size_t instr_index, uint16_t opnd_d_idx,
		std::vector<MCByteID>& d_mbids, std::vector<MCByteID>& s_mbids, InstrTaintInfo* instr_taint_info,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record)
	{
		//		handled_srcs.insert(opnd_s_idx);

		//		std::set<MCByteID> tainted_d_mbids;
		//		std::set<MCByteID> not_change_d_mbids;

		y_assert(d_mbids.size() == s_mbids.size(), "d_mbids.size() == s_mbids.size(), but wrong.", __FILE__, __LINE__);

		// handle taint. 
		for (int d_b_idx = 0; d_b_idx < d_mbids.size(); d_b_idx++) {
			//			bool dst_is_tainted = false;

			MCByteID d = d_mbids.at(d_b_idx);
			MCByteID s = s_mbids.at(d_b_idx);

			//			dst_is_tainted = dst_is_tainted || ;
			update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, opnd_d_idx, d, s, curr_session_taint_record);

			//			if (dst_is_tainted) {
			//				tainted_d_mbids.insert(d);
			//				instr_taint_info->instr_exist_tainted = instr_taint_info->instr_exist_tainted || dst_is_tainted;
			//			}
		}

		//		for (MCByteID d_mbid : tainted_d_mbids) {
		//			bool is_tainted = tainted_d_mbids.find(d_mbid) != tainted_d_mbids.end();
		//			bool is_not_change = not_change_d_mbids.find(d_mbid) != not_change_d_mbids.end();
		//			if (!(is_tainted || is_not_change)) {
		//				untaint_byte(d_mbid);
		//			}
		//		}
	}

	// note that expand_idx can be -1, means the expanded info must be considered as all. 
	/*bool src_is_tainted(opnd* s, int expand_idx) {
		bool ibt = false;
		std::vector<MCByteID> bts;
		get_bytes(s, bts);

//		for (MCByteID bt : bts) {
//			size_t start = std::stoull("00000240B9DE0F60", nullptr, 16);
//			size_t end = std::stoull("00000240B9DE0F64", nullptr, 16);
//			if (start <= bt.reg_id_or_mem_with_byte_offset and bt.reg_id_or_mem_with_byte_offset <= end) {
//				printf("encounter memref in start:%llu,end:%llu.\n", start, end);
//			}
//		}

		for (MCByteID bt : bts) {
			ibt = ibt || is_byte_tainted(bt);
		}
		return ibt;
	}*/
	/*bool src_is_tainted(opnd* s, int expand_idx) {
		bool src_tainted = false;
		if (s->op == "reg") {
			if (s->expanded_infos->size() > 0) {
				if (expand_idx > -1) {
					src_tainted = handle_src_reg_opnd_taint(s, expand_idx);
				}
				else {
					for (int ei = 0; ei < s->expanded_infos->size(); ei++) {
						src_tainted = handle_src_reg_opnd_taint(s, ei);
					}
				}
			}
			else {
				// assert(s->expanded_infos->size() == 0);
				// src_total_tainted = is_register_tainted(s->reg_id_mem_addr_pc_addr_imm, 0, s->actual_size);
				src_tainted = handle_src_reg_opnd_taint(s, -1);
			}
		}
		else if (s->op == "mem") {
			if (s->expanded_infos->size() > 0) {
				if (expand_idx > -1) {
					src_tainted = handle_src_mem_opnd_taint(s, expand_idx);
				}
				else {
					for (int ei = 0; ei < s->expanded_infos->size(); ei++) {
						src_tainted = handle_src_mem_opnd_taint(s, ei);
					}
				}
			}
			else {
				assert(s->expanded_infos->size() > 0 and s->expanded_infos->size() > expand_idx);
//				src_total_tainted = is_memory_tainted(reinterpret_cast<byte*>(s->reg_id_mem_addr_pc_addr_imm), s->actual_size);
				src_tainted = handle_src_mem_opnd_taint(s, -1);
			}
		}
		else {
			// do nothing.
		}
		return src_tainted;
	}*/

	// update latest_taint_record. 
	/*void update_dst_tainted(opnd* d, int expand_idx, bool src_total_tainted, size_t instr_index) {
		std::vector<MCByteID> bts = get_bytes(d, expand_idx);
		if (src_total_tainted) {
			taint_bytes(bts, instr_index);
		}
		else {
			untaint_bytes(bts);
		}
	}*/
	/*void update_dst_tainted(opnd* d, int expand_idx, bool src_total_tainted, size_t instr_index) {
		if (d->op == "reg") {
			void (Taint:: * reg_taint_func)(int reg, byte start_byte_idx, byte byte_len, size_t instr_index);
			if (src_total_tainted) {
				reg_taint_func = &Taint::taint_register;
			}
			else {
				reg_taint_func = &Taint::untaint_register;
			}

			if (d->expanded_infos->size() > 0 and expand_idx > 0) {
				assert(d->expanded_infos->size() > expand_idx);
				expanded_opnd_info* eoi = d->expanded_infos->at(expand_idx);

				(this->*reg_taint_func)(d->reg_id_mem_addr_pc_addr_imm, eoi->reg_inner_rel_addr_or_mem_addr, eoi->sz, instr_index);
			}
			else {
				(this->*reg_taint_func)(d->reg_id_mem_addr_pc_addr_imm, 0, d->actual_size, instr_index);
			}
		}
		else if (d->op == "mem") {
			void (Taint:: * mem_taint_func)(byte * addr, size_t mlen, size_t instr_index);
			if (src_total_tainted) {
				mem_taint_func = &Taint::taint_memory;
			}
			else {
				mem_taint_func = &Taint::untaint_memory;
			}

			if (d->expanded_infos->size() > 0 and expand_idx > 0) {
				assert(d->expanded_infos->size() > expand_idx);
				expanded_opnd_info* eoi = d->expanded_infos->at(expand_idx);
				(this->*mem_taint_func)(reinterpret_cast<byte*>(eoi->reg_inner_rel_addr_or_mem_addr), eoi->sz, instr_index);
			}
			else {
				(this->*mem_taint_func)(reinterpret_cast<byte*>(d->reg_id_mem_addr_pc_addr_imm), d->actual_size, instr_index);
			}
		}
	}*/

	bool is_byte_tainted(MCByteID mbid) {
		bool res = false;
		auto it = latest_taint_record.find(mbid);
		if (it != latest_taint_record.end()) {
			res = true;
		}
		return res;
	}

	void update_total_taint_with_taint_session(std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
		std::string& instr_info, InstrTaintInfo* instr_taint_info) {
		for (auto it = curr_session_taint_record.begin(); it != curr_session_taint_record.end(); it++) {
			MCByteID mbid = it->first;
			SessionByteTaintSetInfo sbtsi = it->second;
			if (sbtsi.sbtt == SessionByteTaintType::SetTaint) {
				// debug code.
				//if (sbtsi.tbtsp.instr_index_which_set_dst_byte >= each_instr_taint_info.size()) {
				//	printf("sbtsi.tbtsp.instr_index_which_set_dst_byte:%lld has no entry, total entry size:%lld.\n", sbtsi.tbtsp.instr_index_which_set_dst_byte, each_instr_taint_info.size());
				//}
				//InstrTaintInfo* eiti_iti = each_instr_taint_info.at(sbtsi.tbtsp.instr_index_which_set_dst_byte);
				//if (eiti_iti == NULL) {
				//	printf("sbtsi.tbtsp.instr_index_which_set_dst_byte:%lld is InstrTaintInfo null, wrong.\n", sbtsi.tbtsp.instr_index_which_set_dst_byte);
				//}
				// force update. 
				latest_taint_record.insert_or_assign(mbid, sbtsi.tbtsp);
				//				printf("taint byte mbid:%s,byte_taint_set_instr_info:%s.\n", mbid.to_string().c_str(), instr_info.c_str());
				//				instr_taint_info->instr_exist_tainted = instr_taint_info->instr_exist_tainted || true;
			}
		}
	}

	//void taint_bytes(std::vector<MCByteID>& mbids, size_t instr_index, SessionByteTaintType sbtt,
	//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record) {
	//	for (MCByteID mbid : mbids) {
	//		taint_byte(mbid, instr_index, sbtt, curr_session_taint_record);
	//	}
	//}
	// 
	void taint_memory_for_final(byte* addr, size_t mlen, size_t instr_index, InstrTaintInfo* instr_taint_info)
	{
		std::vector<MCByteID> b_vect;
		for (int i = 0; i < mlen; i++) {
			byte* tam = addr + i;
			MCByteID mbid((uint64_t)tam);
			b_vect.push_back(mbid);
		}
		taint_bytes_for_final(b_vect, instr_index, instr_taint_info);
	}

	void taint_bytes_for_final(std::vector<MCByteID>& b_vect, size_t instr_index, InstrTaintInfo* instr_taint_info)
	{
		for (MCByteID& mbid : b_vect) {
			latest_taint_record.insert_or_assign(mbid, TraceableByteTaintSetPosition(instr_index, mbid));
			// here, may be retainted for multiple read_file. 
#if taint_simplified_mode == 1
			instr_taint_info->PutDstByteSrcsBytesTaintSetInfo();
			instr_taint_info->has_tainted_src_mem_bytes = true;
#else
			(instr_taint_info)->PutDstByteSrcsBytesTaintSetInfo(mbid, NULL);
			(instr_taint_info)->tainted_src_mem_bytes.insert(mbid);
#endif
//			(instr_taint_info)->tainted_src_bytes.insert(mbid);
			//		assert(ires.second == true);
			//		printf("%s byte tainted!\n", mbid.to_string().c_str());
			//		instr_taint_info->instr_exist_tainted = true;
		}
	}

	void taint_byte_for_curr_session(MCByteID mbid, size_t instr_index, SessionByteTaintType sbtt, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record) {
		SessionByteTaintSetInfo sbtsi;
		if (sbtt == SessionByteTaintType::UnChanged) {
			// do nothing. 
			y_assert(sbtsi.sbtt == SessionByteTaintType::UnChanged, "sbtsi.sbtt == SessionByteTaintType::UnChanged, but wrong.", __FILE__, __LINE__);
		}
		else {
			sbtsi.sbtt = SessionByteTaintType::SetTaint;
			sbtsi.tbtsp = TraceableByteTaintSetPosition(instr_index, mbid);
		}
		auto exist = curr_session_taint_record.insert_or_assign(mbid, sbtsi);
		if (not exist.second) {
			// the insertion does not take place, assignment will take place.
			y_assert(sbtsi.sbtt == (*exist.first).second.sbtt, "sbtsi.sbtt == (*exist.first).second.sbtt, but wrong.", __FILE__, __LINE__);// and sbtsi.tbtsp == (*exist.first).second.tbtsp
		}
	}

	void untaint_bytes(std::vector<MCByteID>& mbids) {
		for (MCByteID mbid : mbids) {
			untaint_byte(mbid);
		}
	}

	void untaint_byte(MCByteID mbid) {
		int exist = latest_taint_record.erase(mbid);
		// debug code. 
		if (exist) {
			//			printf("untaint already tainted byte %s.\n", mbid.to_string().c_str());
		}
	}

	/*bool is_memory_tainted(byte* addr, size_t mlen)
	{
		bool res = false;
		for (int i = 0; i < mlen; i++) {
			byte* mem = addr + i;
			auto it = latest_taint_record.find(MCByteID(ByteType::mem, (uint64_t)mem));
			if (it != latest_taint_record.end()) {
				res = true;
				break;
			}
		}
		return res;
	}*/

	/*bool is_register_tainted(int reg, byte start_byte_idx, byte byte_len)
	{
		bool res = false;
		for (int i = 0; i < byte_len; i++) {
			int byte_idx = start_byte_idx + i;
			int reg_byte_id = (reg << 8) + byte_idx;
			auto it = latest_taint_record.find(MCByteID(ByteType::reg, (uint64_t)reg_byte_id));
			if (it != latest_taint_record.end()) {
				res = true;
				break;
			}
		}
		return res;
//		auto it = tainted_regs.find(reg);
//		if (it != tainted_regs.end()) {
//			uint64_t bt = it->second;
//			uint64_t join = bt & tainted_byte_idxes_in_reg;
//			res = join > 0;
//		}
//		return res;
	}*/

	// each bit corresponds to the index of byte in register. 
	/*void taint_register(int reg, byte start_byte_idx, byte byte_len, size_t instr_index)
	{
		for (int i = 0; i < byte_len; i++) {
			int byte_idx = start_byte_idx + i;
			int reg_byte_id = (reg << 8) + byte_idx;
			MCByteID mbid(reg, (uint64_t)reg_byte_id);
			latest_taint_record.insert({ mbid, TraceableByteTaintSetPosition(instr_index, mbid) });
		}

//		uint64_t reg_taint_info = 0;
//		auto it = tainted_regs.find(reg);
//		if (it != tainted_regs.end()) {
			// found
//			reg_taint_info = it->second;
//		}
//		reg_taint_info |= tainted_byte_idxes_in_reg;
//		tainted_regs.insert({ reg, reg_taint_info });
	}*/

	/*void untaint_register(int reg, byte start_byte_idx, byte byte_len, size_t instr_index)
	{
		for (int i = 0; i < byte_len; i++) {
			int byte_idx = start_byte_idx + i;
			int reg_byte_id = (reg << 8) + byte_idx;
			MCByteID mbid(reg, (uint64_t)reg_byte_id);
			latest_taint_record.erase(mbid);
		}

//		uint64_t reg_taint_info = 0;
//		auto it = tainted_regs.find(reg);
//		if (it != tainted_regs.end()) {
			// found
//			reg_taint_info = it->second;
//		}
//		uint64_t bt = reg_taint_info & tainted_byte_idxes_in_reg;
//		uint64_t remain_left = ~bt;
//		uint64_t res = reg_taint_info & remain_left;
//		if (res == 0) {
//			tainted_regs.erase(reg);
//		} else{
//			tainted_regs[reg] = res;
//		}
	}*/

};

