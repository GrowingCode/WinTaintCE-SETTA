#include "yyx_taint_detail.h"
#include <cmath>


static int get_bits_as_int(byte* val, int bit_start, int bit_length) {
	int res = 0;
	for (int i = bit_start; i < bit_start + bit_length; i++) {
		int base_pow = std::pow(2, i - bit_start);
		int val_idx = i / 8;
		byte v = val[val_idx];
		int v_i_idx = i % 8;
		res += ((v & (1 << v_i_idx)) > 0 ? 1 : 0) * base_pow;
	}
	return res;
}

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
		HandleRange hr)>& ss)
{
	int mask_src_opnd_num = std::get<1>(ss);
	int mask_atom_byte_size = std::get<2>(ss);
	auto fp = std::get<4>(ss);

	bool has_mask = false;
	if (it->srcs.size() == mask_src_opnd_num and mask_atom_byte_size > 0) {
		has_mask = true;
	}
	if (fp != NULL) {
		fp(yt, it, instr_index, instr_taint_info, curr_session_taint_record, has_mask, hr);
	}
	else {
		// invoke non-v-pfx function, just must normal_handle_op.
		int src_start_rel = 0;
		if (has_mask) {
			src_start_rel = 1;
		}
		normal_handle_op(yt, it, instr_index, src_start_rel, instr_taint_info, curr_session_taint_record, hr);
	}
	return has_mask;
}

void get_bytes_no_expand_consider_range(opnd* d, HandleRange hr, std::vector<MCByteID>& d_mbids)
{
	int d_sz = -1;
	if (hr.handle_byte_size > 0) {
		d_sz = hr.handle_byte_size;
	}
	
	get_bytes_no_expand(d, hr.handle_byte_start, d_sz, d_mbids);
}

const HandleRange DefaultHandleRange = {0, -1};

void normal_handle_op(YTaint* yt, instr* it, size_t instr_index, int src_start_relative, 
	InstrTaintInfo* instr_taint_info, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	HandleRange hr)
{
	bool find_meta = false;
	auto hc_it = taint_meta.find(it->opname);
	if (hc_it == taint_meta.end()) {
		bool v_start = YStringUtil::startsWith(it->opname, "v");
		if (v_start) {
			std::string non_v_name = it->opname.substr(1);
			hc_it = taint_meta.find(non_v_name);
			if (hc_it != taint_meta.end()) {
				find_meta = true;
			}
		}
	}
	else {
		find_meta = true;
	}

	if (find_meta) {
		std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>& dst_to_its_srcs = hc_it->second;
		for (auto dit = dst_to_its_srcs.begin(); dit != dst_to_its_srcs.end(); dit++) {
			yt->handle_one_dst_taint_info(it, instr_index, dit->first, dst_to_its_srcs, src_start_relative,
				instr_taint_info, curr_session_taint_record, hr);
		}
	}
	else {
		y_assert(false, "find_meta must find.", __FILE__, __LINE__);
	}
}

void handle_lea(YTaint* yt, instr* it, size_t instr_index, 
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record, 
	bool has_mask,
	HandleRange hr=DefaultHandleRange)
{
	opnd* dest = it->dsts.at(0);
	std::vector<MCByteID> d_mbids;
	get_bytes_no_expand(dest, -1, -1, d_mbids);
	for (MCByteID d_mbid : d_mbids) {
		for (auto ruimdmr : it->reg_use_in_mem_ref_or_dst_reg_max_reg_vect) {
			if (ruimdmr->type == RegUseInMemOrDstMaxRegType::reg_used_in_mem_ref) {
				std::vector<MCByteID> s_mbids;
				get_reg_bytes(ruimdmr->reg_id, 0, ruimdmr->reg_val_size, s_mbids);
				for (MCByteID s_mbid : s_mbids) {
					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info,
						0, d_mbid, s_mbid, curr_session_taint_record);
				}
			}
		}
	}
}

static std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>> cmpxchg_taint_meta = {{ 0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}} }, { 1,{{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}} }};

void handle_cmpxchg(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* dest = it->srcs.at(1);
	opnd* xax = it->srcs.at(2);
	bool ov_same = opnd_value_same(dest, xax);
	if (ov_same) {
		//auto dst_cared_srcs_meta = dst_to_its_srcs.find(0);
		//assert(dst_cared_srcs_meta != dst_to_its_srcs.end());
		//int dst_idx = dst_cared_srcs_meta->first;
		//opnd* d = it->dsts.at(dst_idx);
		//update_dst_from_src_tainted(dst_cared_srcs_meta->second, it->srcs, -1, dst_idx, d, instr_taint_info);
		yt->handle_one_dst_taint_info(it, instr_index, 0, cmpxchg_taint_meta, 0, instr_taint_info, curr_session_taint_record);// handled_srcs, 
	}
	else {
		yt->handle_one_dst_taint_info(it, instr_index, 1, cmpxchg_taint_meta, 0, instr_taint_info, curr_session_taint_record);// handled_srcs, 
	}
}

// std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>> cmpxchg8b_taint_meta = {{ 0, {{3,DstSrcOpndTaintType::ByteToByteOthersNotChange},{4,DstSrcOpndTaintType::ByteToByteOthersNotChange}} }, { 1, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}} }, { 2, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}} }};

void handle_cmpxchg8b(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* src_d = it->srcs.at(0);
	opnd* src_xax = it->srcs.at(1);
	opnd* src_xdx = it->srcs.at(2);
	opnd* opd_arr[2] = { src_xax, src_xdx };
	bool ov_same = opnd_value_same(opd_arr, 2, src_d);
	if (ov_same) {
		opnd* dst_d = it->dsts.at(0);
		opnd* xcx = it->srcs.at(3);
		opnd* xbx = it->srcs.at(4);
		std::vector<MCByteID> lower_part_dst_d;
		get_bytes_no_expand(dst_d, 0, dst_d->actual_size / 2, lower_part_dst_d);
		std::vector<MCByteID> higher_part_dst_d;
		get_bytes_no_expand(dst_d, dst_d->actual_size / 2, dst_d->actual_size / 2, higher_part_dst_d);

		std::vector<MCByteID> xcx_bts;
		get_bytes_no_expand(xcx, 0, xcx->actual_size, xcx_bts);

		std::vector<MCByteID> xbx_bts;
		get_bytes_no_expand(xbx, 0, xbx->actual_size, xbx_bts);

		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, lower_part_dst_d, xbx_bts, instr_taint_info, curr_session_taint_record);// handled_srcs, 
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, higher_part_dst_d, xcx_bts, instr_taint_info, curr_session_taint_record);// handled_srcs, 
	}
	else {
		opnd* xax = it->dsts.at(1);
		opnd* xdx = it->dsts.at(2);

		std::vector<MCByteID> lower_part_src_d;
		get_bytes_no_expand(src_d, 0, src_d->actual_size / 2, lower_part_src_d);
		std::vector<MCByteID> higher_part_src_d;
		get_bytes_no_expand(src_d, src_d->actual_size / 2, src_d->actual_size / 2, higher_part_src_d);

		std::vector<MCByteID> xax_bts;
		get_bytes_no_expand(xax, 0, xax->actual_size, xax_bts);

		std::vector<MCByteID> xdx_bts;
		get_bytes_no_expand(xdx, 0, xdx->actual_size, xdx_bts);

		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 1, xax_bts, lower_part_src_d, instr_taint_info, curr_session_taint_record);// handled_srcs, 
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 2, xdx_bts, higher_part_src_d, instr_taint_info, curr_session_taint_record);// handled_srcs, 
	}
}

void handle_bswap(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* dst = it->dsts.at(0);
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(dst, -1, -1, dst_bytes);
	opnd* src = it->srcs.at(0);
	std::vector<MCByteID> src_bytes;
	get_bytes_no_expand(src, -1, -1, src_bytes);
	for (int i = 0; i < dst->actual_size; i++) {
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src_bytes.at(dst->actual_size - i - 1), curr_session_taint_record);
	}
}

void common_handle_vextract128(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	opnd* d = it->dsts.at(0);
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(d, 0, 128 / 8, dst_bytes);

	opnd* s0 = it->srcs.at(0);
	std::vector<MCByteID> s0_lower_part_d;
	get_bytes_no_expand(s0, 0, s0->actual_size / 2, s0_lower_part_d);
	std::vector<MCByteID> s0_higher_part_d;
	get_bytes_no_expand(s0, s0->actual_size / 2, s0->actual_size / 2, s0_higher_part_d);

	opnd* i8 = it->srcs.at(1);
	byte i8_bit0 = (*i8->value) & (int64_t)1;
	y_assert((*i8->value) == i8->int_imm, "(*i8->value) == i8->int_imm", __FILE__, __LINE__);
	if (i8_bit0 == 0) {
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, dst_bytes, s0_lower_part_d, instr_taint_info, curr_session_taint_record);
	}
	else if (i8_bit0 == 1) {
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, dst_bytes, s0_higher_part_d, instr_taint_info, curr_session_taint_record);
	}
	else {
		y_assert(false, "i8_bit0 wrong", __FILE__, __LINE__);
	}
}

void common_handle_vinsert128(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* d = it->dsts.at(0);
	y_assert(d->actual_size == 256 / 8, "d->actual_size == 256 / 8", __FILE__, __LINE__);
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(d, -1, -1, dst_bytes);

	opnd* src0 = it->srcs.at(0);
	y_assert(src0->actual_size == 256 / 8, "d->actual_size == 256 / 8", __FILE__, __LINE__);
	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand(src0, -1, -1, src0_bytes);

	yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, dst_bytes, src0_bytes, instr_taint_info, curr_session_taint_record);

	std::vector<MCByteID> lower_part_d;
	get_bytes_no_expand(d, 0, d->actual_size / 2, lower_part_d);
	std::vector<MCByteID> higher_part_d;
	get_bytes_no_expand(d, d->actual_size / 2, d->actual_size / 2, higher_part_d);

	//opnd* s1 = it->srcs.at(0);
	//y_assert(d->actual_size == s1->actual_size);
	//std::vector<MCByteID> lower_part_s1;
	//get_bytes_no_expand(s1, 0, s1->actual_size / 2, lower_part_s1);
	//std::vector<MCByteID> higher_part_s1;
	//get_bytes_no_expand(s1, s1->actual_size / 2, d->actual_size / 2, higher_part_s1);

	opnd* s1 = it->srcs.at(1);
	y_assert(s1->actual_size == 128 / 8, "s1->actual_size == 128 / 8", __FILE__, __LINE__);
	std::vector<MCByteID> s1_bts;
	get_bytes_no_expand(s1, 0, s1->actual_size, s1_bts);

	opnd* i8 = it->srcs.at(2);
	byte i8_bit0 = (*i8->value) & (int64_t)1;
	y_assert((*i8->value) == i8->int_imm, "(*i8->value) == i8->int_imm", __FILE__, __LINE__);
	if (i8_bit0 == 0) {
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, lower_part_d, s1_bts, instr_taint_info, curr_session_taint_record);
	}
	else if (i8_bit0 == 1) {
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, higher_part_d, s1_bts, instr_taint_info, curr_session_taint_record);
	}
	else {
		y_assert(false, "i8_bit0 wrong.", __FILE__, __LINE__);
	}
}

void handle_rep_stos(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	// loop for d_sz times and use expanded_info. 
	opnd* d0 = it->dsts.at(0);
	opnd* s0 = it->srcs.at(0);
	std::vector<MCByteID> s0_bts;
	get_bytes_no_expand(s0, -1, -1, s0_bts);
	size_t eisize = d0->expanded_infos.size();
	for (int i = 0; i < eisize; i++) {
		std::vector<MCByteID> d0_ei_bts;
		get_bytes_in_expanded(d0, i, d0_ei_bts);
		yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, d0_ei_bts, s0_bts, instr_taint_info, curr_session_taint_record);// handled_srcs, 
	}
}

void handle_interleave(YTaint* yt, size_t instr_index, 
	std::vector<MCByteID>& dst_bytes,
	std::vector<MCByteID>& src1_bytes,
	std::vector<MCByteID>& src2_bytes,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	int atom_byte_size,
	bool is_low)
{
	y_assert(dst_bytes.size() <= 128 / 8 and src1_bytes.size() <= 128 / 8 and src2_bytes.size() <= 128 / 8, "interleave detail src byte num wrong.", __FILE__, __LINE__);
	int byte_base = 0;
	if (is_low) {
		byte_base = 0;
	}
	else {
		byte_base = src1_bytes.size() / 2;
	}
	int k = dst_bytes.size() / atom_byte_size;
	for (int i = 0; i < k; i++) {
		int src_i = i / 2;
		if (i % 2 == 0) {
			// use src1
			for (int j = 0; j < atom_byte_size; j++) {
				yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i * atom_byte_size + j), src1_bytes.at(byte_base + src_i * atom_byte_size + j), curr_session_taint_record);
			}
		}
		else {
			// use src2
			for (int j = 0; j < atom_byte_size; j++) {
				yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i * atom_byte_size + j), src2_bytes.at(byte_base + src_i * atom_byte_size + j), curr_session_taint_record);
			}
		}
	}
}

void handle_interleave_256b(YTaint* yt, size_t instr_index, 
	std::vector<MCByteID>& dst_bytes,
	std::vector<MCByteID>& src1_bytes,
	std::vector<MCByteID>& src2_bytes, 
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	int atom_byte_size,
	bool is_low)
{
	y_assert(dst_bytes.size() == 256 / 8, "dst_bytes.size() == 256 / 8", __FILE__, __LINE__);
	{
		std::vector<MCByteID> dst_first_half = vector_slicing<MCByteID>(dst_bytes, 0, 16);
		std::vector<MCByteID> src1_first_half = vector_slicing<MCByteID>(src1_bytes, 0, 16);
		std::vector<MCByteID> src2_first_half = vector_slicing<MCByteID>(src2_bytes, 0, 16);
		handle_interleave(yt, instr_index, dst_first_half, src1_first_half, src2_first_half,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
	{
		std::vector<MCByteID> dst_second_half = vector_slicing<MCByteID>(dst_bytes, 16, 16);
		std::vector<MCByteID> src1_second_half = vector_slicing<MCByteID>(src1_bytes, 16, 16);
		std::vector<MCByteID> src2_second_half = vector_slicing<MCByteID>(src2_bytes, 16, 16);
		handle_interleave(yt, instr_index, dst_second_half, src1_second_half, src2_second_half,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
}

void handle_interleave_512b(YTaint* yt, size_t instr_index, 
	std::vector<MCByteID>& dst_bytes,
	std::vector<MCByteID>& src1_bytes, 
	std::vector<MCByteID>& src2_bytes, 
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	int atom_byte_size,
	bool is_low)
{
	y_assert(dst_bytes.size() == 512 / 8, "dst_bytes.size() == 512 / 8", __FILE__, __LINE__);
	{
		std::vector<MCByteID> dst_first_half = vector_slicing<MCByteID>(dst_bytes, 0, 32);
		std::vector<MCByteID> src1_first_half = vector_slicing<MCByteID>(src1_bytes, 0, 32);
		std::vector<MCByteID> src2_first_half = vector_slicing<MCByteID>(src2_bytes, 0, 32);
		handle_interleave_256b(yt, instr_index, dst_first_half, src1_first_half, src2_first_half,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
	{
		std::vector<MCByteID> dst_second_half = vector_slicing<MCByteID>(dst_bytes, 32, 32);
		std::vector<MCByteID> src1_second_half = vector_slicing<MCByteID>(src1_bytes, 32, 32);
		std::vector<MCByteID> src2_second_half = vector_slicing<MCByteID>(src2_bytes, 32, 32);
		handle_interleave_256b(yt, instr_index, dst_second_half, src1_second_half, src2_second_half,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
}

void common_handle_v_or_punpck(YTaint* yt, instr* it, size_t instr_index,
	int dst_idx, int src1_idx, int src2_idx, 
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	int atom_byte_size, 
	bool is_low)// else is_high
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(it->dsts.at(dst_idx), -1, -1, dst_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand(it->srcs.at(src1_idx), -1, -1, src1_bytes);

	std::vector<MCByteID> src2_bytes;
	get_bytes_no_expand(it->srcs.at(src2_idx), -1, -1, src2_bytes);

	int db_sz = dst_bytes.size();
	if (db_sz == 512 / 8) {
		handle_interleave_512b(yt, instr_index, dst_bytes, src1_bytes, src2_bytes,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
	else if (db_sz == 256 / 8) {
		handle_interleave_256b(yt, instr_index, dst_bytes, src1_bytes, src2_bytes,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
	else {
		handle_interleave(yt, instr_index, dst_bytes, src1_bytes, src2_bytes,
			instr_taint_info, curr_session_taint_record, atom_byte_size, is_low);
	}
}

void handle_v(instr* it, int one_rep_byte_sz, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record)
{
	opnd* k1 = it->srcs.at(1);
	opnd* d = it->dsts.at(0);
	int rep_times = d->actual_size / one_rep_byte_sz;
	for (int i = 0; i < rep_times; i++) {
		bool update = (k1->value[i / 8] & (1 << (i % 8))) > 0;
		if (update) {
			// do nothing. 
		}
		else {
			// todo, may untaint for z mask. 
			std::vector<MCByteID> bts;
			get_bytes_no_expand(d, i * one_rep_byte_sz, one_rep_byte_sz, bts);
			for (MCByteID bt : bts) {
				curr_session_taint_record.erase(bt);
			}
		}
	}
}

void handle_punpcklbw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 8 / 8, true);
}

void handle_vpunpcklbw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 8 / 8, true);
}

void handle_punpcklwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 16 / 8, true);
}

void handle_vpunpcklwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 16 / 8, true);
}

void handle_punpckldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	// first src must use index 1, index 1 is dest but for punpckldq, dest is the 0th parameter. 
	// second src must use index 0, index 0 is source but for punpckldq, source is the 1th parameter. 
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0, 
		instr_taint_info, curr_session_taint_record, 32 / 8, true);
}

void handle_vpunpckldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;

	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 32 / 8, true);
}

void handle_punpcklqdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0, 
		instr_taint_info, curr_session_taint_record, 64 / 8, true);
}

void handle_vpunpcklqdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 64 / 8, true);
}


void handle_punpckhbw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 8 / 8, false);
}

void handle_vpunpckhbw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 8 / 8, false);
}

void handle_punpckhwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 16 / 8, false);
}

void handle_vpunpckhwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 16 / 8, false);
}

void handle_punpckhdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	// first src must use index 1, index 1 is dest but for punpckldq, dest is the 0th parameter. 
	// second src must use index 0, index 0 is source but for punpckldq, source is the 1th parameter. 
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 32 / 8, false);
}

void handle_vpunpckhdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;

	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 32 / 8, false);
}

void handle_punpckhqdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	common_handle_v_or_punpck(yt, it, instr_index, 0, 1, 0,
		instr_taint_info, curr_session_taint_record, 64 / 8, false);
}

void handle_vpunpckhqdq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange) {
	int dst_idx = 0;
	int src1_idx = it->srcs.size() - 1 - 1;
	int src2_idx = it->srcs.size() - 1;
	common_handle_v_or_punpck(yt, it, instr_index, dst_idx, src1_idx, src2_idx,
		instr_taint_info, curr_session_taint_record, 64 / 8, false);
}

void handle_common_v_or_pmovmskb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(it->dsts.at(0), -1, -1, dst_bytes);

	std::vector<MCByteID> src_bytes;
	get_bytes_no_expand(it->srcs.at(0), -1, -1, src_bytes);

	int i_len = src_bytes.size();
	for (int i = 0; i < i_len; i++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i / 8), src_bytes.at(i), curr_session_taint_record);
	}
}

void handle_common_palignr(YTaint* yt, opnd* dst, opnd* src0, opnd* src1, opnd* imm, size_t instr_index,
	InstrTaintInfo* instr_taint_info, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	HandleRange hr = DefaultHandleRange)
{
	y_assert(imm->detail_ot == opnd_type::is_immed_int, "imm->detail_ot == opnd_type::is_immed_int", __FILE__, __LINE__);

	std::vector<MCByteID> src_d_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src_d_bytes);
	
	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> total;
	total.insert(total.end(), src_d_bytes.begin(), src_d_bytes.end());
	total.insert(total.end(), src1_bytes.begin(), src1_bytes.end());
	
	int start = (*imm->value);
	int length = dst_bytes.size();
	std::vector<MCByteID> src_in_total = vector_slicing<MCByteID>(total, start, length);

	y_assert(src_in_total.size() == dst_bytes.size(), "src_in_total.size() == dst_bytes.size()", __FILE__, __LINE__);
	yt->update_dst_bytes_from_src_bytes_tainted_one_by_one(instr_index, 0, dst_bytes, src_in_total, instr_taint_info, curr_session_taint_record);
}

void handle_palignr(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	int src_sz = it->srcs.size();
	opnd* src0 = it->srcs.at(0);
	opnd* s_imm = it->srcs.at(1);
	opnd* src_d = it->srcs.at(2);
	y_assert(s_imm->detail_ot == opnd_type::is_immed_int, "s_imm->detail_ot == opnd_type::is_immed_int", __FILE__, __LINE__);

	opnd* dst = it->dsts.at(0);

	handle_common_palignr(yt, dst, src_d, src0, s_imm, instr_index, 
		instr_taint_info, curr_session_taint_record, hr);
}

void handle_vpalignr(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* src1 = NULL;
	opnd* src2 = NULL;
	opnd* s_imm = NULL;
	if (has_mask) {
		s_imm = it->srcs.at(1);
		src1 = it->srcs.at(2);
		src2 = it->srcs.at(3);
	}
	else {
		src1 = it->srcs.at(0);
		src2 = it->srcs.at(1);
		s_imm = it->srcs.at(2);
	}

	y_assert(s_imm->detail_ot == opnd_type::is_immed_int, "s_imm->detail_ot == opnd_type::is_immed_int", __FILE__, __LINE__);
	opnd* dst = it->dsts.at(0);

	handle_common_palignr(yt, dst, src1, src2, s_imm, instr_index,
		instr_taint_info, curr_session_taint_record, hr);
}

enum pshuf_mode {
	all_handle,
	low_half_direct_mov,
	high_half_direct_mov,
};

void handle_common_pshuf(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size,
	pshuf_mode pm)
{
	opnd* src1 = NULL;
	opnd* s_imm = NULL;
	if (has_mask) {
		src1 = it->srcs.at(2);
		s_imm = it->srcs.at(1);
	}
	else {
		src1 = it->srcs.at(0);
		s_imm = it->srcs.at(1);
	}

	int orders[4]{0};
	orders[0] = get_bits_as_int(s_imm->value, 0, 2);
	orders[1] = get_bits_as_int(s_imm->value, 2, 2);
	orders[2] = get_bits_as_int(s_imm->value, 4, 2);
	orders[3] = get_bits_as_int(s_imm->value, 6, 2);
	
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(it->dsts.at(0), hr, dst_bytes);
	
	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);
	
	int db_size = dst_bytes.size();
	y_assert(db_size == 128 / 8 || db_size == 64 / 8, "db_size == 128 / 8 || db_size == 64 / 8", __FILE__, __LINE__);
	int atom_rep_times = db_size / atom_byte_size;
	
	int direct_mov_start = 0;
	int direct_mov_len = atom_rep_times / 2;
	int normal_handle_start = 0;
	int normal_handle_len = atom_rep_times / 2;

	if (pm == pshuf_mode::all_handle) {
		direct_mov_len = 0;
		normal_handle_len = atom_rep_times;
	}
	else if (pm == pshuf_mode::low_half_direct_mov) {
		normal_handle_start = atom_rep_times / 2;
	}
	else if (pm == pshuf_mode::high_half_direct_mov) {
		direct_mov_start = atom_rep_times / 2;
	}
	else {
		y_assert(false, "pshuf_mode outof range.", __FILE__, __LINE__);
	}
	
	for (int i = direct_mov_start; i < direct_mov_start + direct_mov_len; i++) {
//		int src1_start = i;
//		int src1_end = (std::min)((size_t)(src1_start + atom_byte_size), src1_bytes.size());
		for (int j = i * atom_byte_size; j < i * atom_byte_size + atom_byte_size; j++) {
//			for (int k = 0; k < atom_byte_size; k++) {
//				int byte_idx = j * atom_byte_size + k;
				yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
					dst_bytes.at(j), src1_bytes.at(j), curr_session_taint_record);
//			}
		}
	}
	
	y_assert(4 == normal_handle_len, "4 must == normal_handle_len, but not.", __FILE__, __LINE__);
	for (int i = 0; i < 4; i++) {
		int src1_start = orders[i] * atom_byte_size;
		int src1_end = (std::min)((size_t)(src1_start + atom_byte_size), src1_bytes.size());
		for (int j = src1_start; j < src1_end; j++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
				dst_bytes.at((normal_handle_start + i) * atom_byte_size + j - src1_start), src1_bytes.at(j), curr_session_taint_record);
		}
	}
}

void handle_pshufb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* dst = it->dsts.at(0);

	opnd* src0 = it->srcs.at(0);
	opnd* src1 = it->srcs.at(1);

	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int index = 0;
	int pos = 0;
	while (index < src0->actual_size) {
		if (src0->actual_size == 16) {
			pos = get_bits_as_int(src0->value, index * 8, 4);
		}
		else if (src0->actual_size == 8) {
			pos = get_bits_as_int(src0->value, index * 8, 3);
		}
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(pos), src1_bytes.at(index), curr_session_taint_record);
		index++;
	}
}

void handle_vpshufb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	// TODO, if has_mask, its logic cannot simply reuse pshufb. 
	// TODO, stop origin mask handling in framework for this. 
}

void handle_pshufd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pshuf(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, has_mask, hr, 4, pshuf_mode::all_handle);
}

void handle_pshufw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pshuf(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, has_mask, hr, 2, pshuf_mode::all_handle);
}

//void handle_common_packss(YTaint* yt, size_t instr_index,
//	opnd* dst,
//	opnd* src0,
//	opnd* src1,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	bool has_mask,
//	HandleRange hr,
//	int atom_byte_size)
//{
//	std::vector<MCByteID> dst_bytes;
//	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);
//
//	std::vector<MCByteID> src0_bytes;
//	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);
//
//	std::vector<MCByteID> src1_bytes;
//	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);
//
//	y_assert(dst_bytes.size() == 128 / 8 and src0_bytes.size() == 128 / 8 and src1_bytes.size() == 128 / 8);
//
//	std::vector<MCByteID>& curr_src = src0_bytes;
//	int dst_byte_base_index = 0;
//	for (int t = 0; t < 2; t++) {
//		int rep_times = curr_src.size() / atom_byte_size;
//		for (int i = 0; i < rep_times; i++) {
//			for (int j = 0; j < atom_byte_size; j++) {
//				int dst_idx = dst_byte_base_index + j / 2 + i * (atom_byte_size / 2);
//				yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(dst_idx), curr_src.at(i * atom_byte_size + j), curr_session_taint_record);
//			}
//		}
//		dst_byte_base_index += 64 / 8;
//		curr_src = src1_bytes;
//	}
//}

//void handle_packsswb(YTaint* yt, instr* it, size_t instr_index,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	bool has_mask,
//	HandleRange hr = DefaultHandleRange)
//{
//	opnd* dst = it->dsts.at(0);
//
//	opnd* src0 = it->srcs.at(1);
//	opnd* src1 = it->srcs.at(0);
//
//	handle_common_packss(yt, instr_index, dst, src0, src1, instr_taint_info, curr_session_taint_record, has_mask, hr, 16 / 8);
//}
//
//void handle_vpacksswb(YTaint* yt, instr* it, size_t instr_index,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	bool has_mask,
//	HandleRange hr = DefaultHandleRange)
//{
//	opnd* dst = it->dsts.at(0);
//
//	opnd* src0 = it->srcs.at(it->srcs.size() - 2);
//	opnd* src1 = it->srcs.at(it->srcs.size() - 1);
//
//	handle_common_packss(yt, instr_index, dst, src0, src1, instr_taint_info, curr_session_taint_record, has_mask, hr, 16 / 8);
//}
//
//void handle_packssdw(YTaint* yt, instr* it, size_t instr_index,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	bool has_mask,
//	HandleRange hr = DefaultHandleRange)
//{
//	opnd* dst = it->dsts.at(0);
//
//	opnd* src0 = it->srcs.at(1);
//	opnd* src1 = it->srcs.at(0);
//
//	handle_common_packss(yt, instr_index, dst, src0, src1, instr_taint_info, curr_session_taint_record, has_mask, hr, 32 / 8);
//}
//
//void handle_vpackssdw(YTaint* yt, instr* it, size_t instr_index,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	bool has_mask,
//	HandleRange hr = DefaultHandleRange)
//{
//	opnd* dst = it->dsts.at(0);
//
//	opnd* src0 = it->srcs.at(it->srcs.size() - 2);
//	opnd* src1 = it->srcs.at(it->srcs.size()-1);
//	
//	handle_common_packss(yt, instr_index, dst, src0, src1, instr_taint_info, curr_session_taint_record, has_mask, hr, 32 / 8);
//}

void handle_pshufhw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pshuf(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, has_mask, hr, 2, pshuf_mode::low_half_direct_mov);
}

void handle_pshuflw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pshuf(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, has_mask, hr, 2, pshuf_mode::high_half_direct_mov);
}

void handle_vperm2i128(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info, 
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand(it->dsts.at(0), -1, -1, dst_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand(it->srcs.at(0), -1, -1, src1_bytes);

	std::vector<MCByteID> src2_bytes;
	get_bytes_no_expand(it->srcs.at(1), -1, -1, src2_bytes);

	auto imm_v = it->srcs.at(2)->value;
	int imm801 = get_bits_as_int(imm_v, 0, 2);
	int imm845 = get_bits_as_int(imm_v, 4, 2);
	int imm83 = get_bits_as_int(imm_v, 3, 1);
	int imm87 = get_bits_as_int(imm_v, 7, 1);

	if (imm801 == 0 && !imm83)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src1_bytes.at(i), curr_session_taint_record);
		}
	}
	else if (imm801 == 1 && !imm83)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src1_bytes.at(i + 16), curr_session_taint_record);
		}
	}
	else if (imm801 == 2 && !imm83)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src2_bytes.at(i), curr_session_taint_record);
		}
	}
	else if (imm801 == 3 && !imm83)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src2_bytes.at(i + 16), curr_session_taint_record);
		}
	}

	if (imm845 == 0 && !imm87)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i + 16), src1_bytes.at(i), curr_session_taint_record);
		}
	}
	else if (imm845 == 1 && !imm87)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i + 16), src1_bytes.at(i + 16), curr_session_taint_record);
		}
	}
	else if (imm845 == 2 && !imm87)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i + 16), src2_bytes.at(i), curr_session_taint_record);
		}
	}
	else if (imm845 == 3 && !imm87)
	{
		for (int i = 0; i < 128 / 8; i++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i + 16), src2_bytes.at(i + 16), curr_session_taint_record);
		}
	}
}

void handle_common_pmadd(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	bool has_mask,
	HandleRange hr)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int db_sz = dst_bytes.size();
	y_assert(db_sz == 32 / 8, "db_sz == 32 / 8", __FILE__, __LINE__);
	for (int j = 0; j < 4; j++)
	{
		for (int k = 0; k < 4; k++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src0_bytes.at(k), curr_session_taint_record);
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src1_bytes.at(k), curr_session_taint_record);
		}
	}
}

void handle_pmaddwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmadd(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr);
}

void handle_vpmaddwd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmadd(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr);
}

void handle_sign_extension_right_shift(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr,
	bool overshift_set_sign_bit,
	int shift_atom_byte_size,
	opnd* dst,
	opnd* src,
	opnd* shift_count)
{
	int64_t shift_num = 0;
	int sc_sz = (std::min)((uint64_t)8, shift_count->actual_size);
	memcpy_s(&shift_num, sc_sz, shift_count->value, sc_sz);

	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src_bytes;
	get_bytes_no_expand_consider_range(src, hr, src_bytes);

	bool handle_shift = true;
	if (shift_num > shift_atom_byte_size * 8) {
		if (overshift_set_sign_bit) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(0), src_bytes.at(src_bytes.size() - 1), curr_session_taint_record);
			handle_shift = false;
		}
		else {
			shift_num = shift_atom_byte_size * 8;
		}
	}
	if (handle_shift) {
		// handle sign extension
		int influenced_byte_end_index_from_high_to_low = shift_num / 8;
		for (int j = 0; j <= influenced_byte_end_index_from_high_to_low; j++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(dst_bytes.size() - 1 - j), src_bytes.at(src_bytes.size() - 1), curr_session_taint_record);
		}
		// handle normal right shift. 
		int shift_low_rounds = shift_num / 8;
		int shift_remain = shift_num % 8;
		for (int j = src_bytes.size() - 1; j >= shift_low_rounds; j--) {
			int must_influence_dst_byte_idx = j - shift_low_rounds;
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(must_influence_dst_byte_idx), src_bytes.at(j), curr_session_taint_record);
			if (shift_remain != 0) {
				int may_influence_dst_byte_idx = must_influence_dst_byte_idx - 1;
				if (may_influence_dst_byte_idx >= 0) {
					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(may_influence_dst_byte_idx), src_bytes.at(j), curr_session_taint_record);
				}
			}
		}
	}
}

void handle_psraw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_sign_extension_right_shift(yt, instr_index,
		instr_taint_info,
		curr_session_taint_record,
		has_mask, hr, false, 16 / 8,
		it->dsts.at(0), it->srcs.at(1),
		it->srcs.at(0));
}

void handle_vpsraw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_sign_extension_right_shift(yt, instr_index,
		instr_taint_info,
		curr_session_taint_record,
		has_mask, hr, false, 16 / 8,
		it->dsts.at(0), it->srcs.at(it->srcs.size() - 2),
		it->srcs.at(it->srcs.size() - 1));
}

void handle_psrad(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_sign_extension_right_shift(yt, instr_index,
		instr_taint_info,
		curr_session_taint_record,
		has_mask, hr, false, 32 / 8,
		it->dsts.at(0), it->srcs.at(1),
		it->srcs.at(0));
}

void handle_vpsrad(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* shift_count = it->srcs.at(it->srcs.size() - 1);
	int shift_atom_byte_size = false;
	if (shift_count->detail_ot == opnd_type::is_immed_int) {
		shift_atom_byte_size = true;
	}
	handle_sign_extension_right_shift(yt, instr_index,
		instr_taint_info,
		curr_session_taint_record,
		has_mask, hr, shift_atom_byte_size, 32 / 8,
		it->dsts.at(0), it->srcs.at(it->srcs.size() - 2),
		shift_count);
}

void handle_vpsraq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* shift_count = it->srcs.at(it->srcs.size() - 1);
	int shift_atom_byte_size = false;
	if (shift_count->detail_ot == opnd_type::is_immed_int) {
		shift_atom_byte_size = true;
	}
	handle_sign_extension_right_shift(yt, instr_index,
		instr_taint_info,
		curr_session_taint_record,
		has_mask, hr, shift_atom_byte_size, 64 / 8,
		it->dsts.at(0), it->srcs.at(it->srcs.size() - 2),
		shift_count);
}

void handle_common_pinsr(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	opnd* imm,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size)
{
	y_assert(imm->detail_ot == opnd_type::is_immed_int, "imm->detail_ot == opnd_type::is_immed_int", __FILE__, __LINE__);

	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int shift_count = 0;
	int db_sz = dst_bytes.size();
	if (atom_byte_size == 8 / 8) {
		shift_count = get_bits_as_int(imm->value, 0, 4);
	}
	else if (atom_byte_size == 32 / 8) {
		shift_count = get_bits_as_int(imm->value, 0, 2);
	}
	else if (atom_byte_size == 64 / 8) {
		shift_count = get_bits_as_int(imm->value, 0, 1);
	}
	else {
		y_assert(false, "atom_byte_size wrong.", __FILE__, __LINE__);
	}

	int shift_byte_num = shift_count * atom_byte_size;

	for (int j = 0; j < db_sz; j++) {
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src0_bytes.at(j), curr_session_taint_record);
	}

	for (int j = 0; j < db_sz - shift_byte_num; j++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j + shift_byte_num), src1_bytes.at(j), curr_session_taint_record);
	}
}

void handle_pinsrb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 8 / 8);
}

void handle_vpinsrb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 3), 
		it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 8 / 8);
}

void handle_pinsrd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 32 / 8);
}

void handle_vpinsrd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 3),
		it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 32 / 8);
}

void handle_pinsrq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 64 / 8);
}

void handle_vpinsrq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsr(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 3),
		it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 64 / 8);
}

void handle_common_pinsrw(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	opnd* imm,
	bool has_mask,
	HandleRange hr,
	int atom_byte_sz)
{
	y_assert(imm->detail_ot == opnd_type::is_immed_int, "imm->detail_ot == opnd_type::is_immed_int", __FILE__, __LINE__);

	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int db_sz = dst_bytes.size();

	int sel = 0;
	if (db_sz == 64 / 8) {
		sel = get_bits_as_int(imm->value, 0, 2);
	}
	else {
		sel = get_bits_as_int(imm->value, 0, 3);
	}
	
	for (int j = 0; j < db_sz; j++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src0_bytes.at(j), curr_session_taint_record);
	}

	for (int j = 0; j < atom_byte_sz; j++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(sel * atom_byte_sz + j), src1_bytes.at(j), curr_session_taint_record);
	}
}

void handle_pinsrw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsrw(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->dsts.at(0), 
		it->srcs.at(0), it->srcs.at(1), has_mask, hr, 16 / 8);
}

void handle_vpinsrw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pinsrw(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 3), 
		it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 16 / 8);
}

void handle_common_psll(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	//src0 is order
	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	uint64_t v;
	int v_len = (std::min)((uint64_t)64 / 8, src0->actual_size);
	memcpy_s(&v, v_len, src0->value, v_len);

	int vb_shift = v / 8;
	if (vb_shift <= atom_byte_size) {
		int v_remain = v % 8;
		int v_remain_shift = v_remain > 0 ? 1 : 0;
		for (int i = 0; i < atom_byte_size - vb_shift; i++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at((uint64_t)i + vb_shift), src1_bytes.at(i), curr_session_taint_record);
			if (v_remain > 0) {
				if (i + vb_shift + v_remain_shift < atom_byte_size) {
					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at((uint64_t)i + vb_shift + v_remain_shift), src1_bytes.at(i), curr_session_taint_record);
				}
			}
		}
	}
	else {
		// do nothing. 
	}
}

void handle_psllw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 16 / 8);
}

void handle_vpsllw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 16 / 8);
}

void handle_pslld(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 32 / 8);
}

void handle_vpslld(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 32 / 8);
}

void handle_psllq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 64 / 8);
}

void handle_vpsllq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psll(yt, it, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 64 / 8);
}

void handle_common_pmulhalf(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int db_sz = dst_bytes.size();

	for (int j = 0; j < 16 / 8; j++)
	{
		for (int k = 0; k < 16 / 8; k++)
		{
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src0_bytes.at(k), curr_session_taint_record);
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src1_bytes.at(k), curr_session_taint_record);
		}
	}
}

void handle_pmullw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmulhalf(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 16 / 8);
}

void handle_vpmullw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmulhalf(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 16 / 8);
}

void handle_pmulhw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmulhalf(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 16 / 8);
}

void handle_shift_for_perm_qwords(YTaint* yt, size_t instr_index,
	opnd* indices, int shift_extract_bit_num, int shift_step, 
	std::vector<MCByteID>& dst_bytes,
	std::vector<MCByteID>& to_permutate_bytes,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record)
{
	y_assert(to_permutate_bytes.size() == dst_bytes.size(), "to_permutate_bytes.size() == dst_bytes.size()", __FILE__, __LINE__);
	int i_steps = dst_bytes.size() / (64 / 8);
	for (int i = 0; i < i_steps; i++) {
		int shift_num = get_bits_as_int(indices->value, i * shift_step, shift_extract_bit_num) * (64 / 8);
		int max_j = (std::min)((uint64_t)shift_num + 64 / 8, to_permutate_bytes.size() / 8);
		int dst_base = i * 64 / 8;
		for (int j = shift_num; j < max_j; j++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
				dst_bytes.at(dst_base + j - shift_num), to_permutate_bytes.at(j), curr_session_taint_record);
		}
	}
}

void handle_vpermq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* dst = it->dsts.at(0);
	
	opnd* to_permutate = it->srcs.at(it->srcs.size() - 2);
	opnd* possible_imm8 = it->srcs.at(it->srcs.size() - 1);
	opnd* indices = possible_imm8;
	bool last_is_imm8 = false;
	if (possible_imm8->detail_ot == opnd_type::is_immed_int) {
		last_is_imm8 = true;
	}
	else {
		to_permutate = it->srcs.at(it->srcs.size() - 1);
		indices = it->srcs.at(it->srcs.size() - 2);
	}
	
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> to_permutate_bytes;
	get_bytes_no_expand_consider_range(to_permutate, hr, to_permutate_bytes);

	std::vector<MCByteID> indices_bytes;
	get_bytes_no_expand_consider_range(indices, hr, indices_bytes);

	if (last_is_imm8) {
		{
			std::vector<MCByteID> dst_0_256 = vector_slicing(dst_bytes, 0, 256 / 8);
			std::vector<MCByteID> to_permutate_0_256 = vector_slicing(to_permutate_bytes, 0, 256 / 8);
			handle_shift_for_perm_qwords(yt, instr_index, indices, 2, 2, dst_0_256, to_permutate_0_256,
				instr_taint_info, curr_session_taint_record);
		}
		if (dst_bytes.size() >= 512 / 8) {
			std::vector<MCByteID> dst_256_512 = vector_slicing(dst_bytes, 256 / 8, 256 / 8);
			std::vector<MCByteID> to_permutate_256_512 = vector_slicing(to_permutate_bytes, 256 / 8, 256 / 8);
			handle_shift_for_perm_qwords(yt, instr_index, indices, 2, 2, dst_256_512, to_permutate_256_512,
				instr_taint_info, curr_session_taint_record);
		}
	}
	else
	{
		if (dst_bytes.size() == 256 / 8) {
			std::vector<MCByteID> dst_0_256 = vector_slicing(dst_bytes, 0, 256);
			std::vector<MCByteID> to_permutate_0_256 = vector_slicing(to_permutate_bytes, 0, 256);
			handle_shift_for_perm_qwords(yt, instr_index, indices, 2, 64, dst_0_256, to_permutate_0_256,
				instr_taint_info, curr_session_taint_record);
		}
		else if (dst_bytes.size() == 512 / 8) {
			std::vector<MCByteID> dst_0_512 = vector_slicing(dst_bytes, 0, 512 / 8);
			std::vector<MCByteID> to_permutate_0_512 = vector_slicing(to_permutate_bytes, 0, 512 / 8);
			handle_shift_for_perm_qwords(yt, instr_index, indices, 3, 64, dst_0_512, to_permutate_0_512,
				instr_taint_info, curr_session_taint_record);
		}
		else {
			y_assert(false, "dst_bytes.size() wrong.", __FILE__, __LINE__);
		}
	}
}

void handle_vpmulhw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pmulhalf(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 16 / 8);
}

void handle_common_psign(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* sign_opnd,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

//	std::vector<MCByteID> sign_opnd_bytes;
//	get_bytes_no_expand_consider_range(sign_opnd, hr, sign_opnd_bytes);

	int64_t sign_val = 0;
	memcpy_s(&sign_val, atom_byte_size, sign_opnd->value + hr.handle_byte_start, atom_byte_size);

//	for (int i = 0; i < db_sz; i++) {
//		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), sign_opnd_bytes.at(i//2*2+1), curr_session_taint_record);
//	}

	if (sign_val != 0) {
		for (int i = 0; i < dst_bytes.size(); i++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src0_bytes.at(i), curr_session_taint_record);
		}
	}
}

void handle_psignb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr, 8 / 8);
}

void handle_vpsignb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2),
		it->srcs.at(it->srcs.size() - 1), has_mask, hr, 8 / 8);
}

void handle_psignw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr, 16 / 8);
}

void handle_vpsignw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), 
		it->srcs.at(it->srcs.size() - 1), has_mask, hr, 16 / 8);
}

void handle_psignd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr, 32 / 8);
}

void handle_vpsignd(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psign(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2),
		it->srcs.at(it->srcs.size() - 1), has_mask, hr, 32 / 8);
}

void handle_common_pslldq(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	bool has_mask,
	HandleRange hr)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	y_assert(dst_bytes.size() == src0_bytes.size(), "dst_bytes.size() == src0_bytes.size()", __FILE__, __LINE__);
//	std::vector<MCByteID> src1_bytes;
//	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int64_t shift_num = src1->int_imm;

	if (shift_num > 15) {
		shift_num = 16;
	}
	for (int j = 0; j < 128 / 8 - shift_num; j++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j + shift_num), src0_bytes.at(j), curr_session_taint_record);
	}
//	for (int j = 0; j < 128 / 8; j++)
//	{
//		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(j), src1_bytes.at(0), curr_session_taint_record);
//	}
}

void handle_pslldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pslldq(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr);
}

void handle_vpslldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pslldq(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), 
		it->srcs.at(it->srcs.size() - 1), has_mask, hr);
}

void handle_common_psrldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src,
	opnd* src_imm,
	bool has_mask,
	HandleRange hr)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src_bytes;
	get_bytes_no_expand_consider_range(src, hr, src_bytes);

//	std::vector<MCByteID> src_imm_bytes;
//	get_bytes_no_expand_consider_range(src_imm, hr, src_imm_bytes);

//	int i;
	int v = src_imm->int_imm;
//	memcpy_s(&v, 1, it->srcs.at(1)->value, 1);
	v = (v > 15) ? 16 : v;

	for (int i = 0; (i + v) < 128 / 8; i++)
	{
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src_bytes.at(i + v), curr_session_taint_record);
	}
//	yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src_imm_bytes.at(0), curr_session_taint_record);
}

void handle_psrldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psrldq(yt, it, instr_index, instr_taint_info, curr_session_taint_record,
		it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), has_mask, hr);
}

void handle_vpsrldq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_psrldq(yt, it, instr_index, instr_taint_info, curr_session_taint_record,
		it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr);
}

void psrl(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src,
	opnd* src_imm,
	HandleRange hr,
	int by)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src_bytes;
	get_bytes_no_expand_consider_range(src, hr, src_bytes);

//	std::vector<MCByteID> src_count_bytes;
//	get_bytes_no_expand_consider_range(src_imm, hr, src_count_bytes);

	int64_t shift_num;
	int c_size = (std::min)((uint64_t)64 / 8, src_imm->actual_size);
	memcpy_s(&shift_num, c_size, src_imm->value, c_size);
	
	if (shift_num < by * 8) {
		int shift_byte_num = shift_num / 8;
		for (int i = 0; (i + shift_byte_num) < by; i++) {
			yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src_bytes.at(i + shift_byte_num), curr_session_taint_record);
			int possible_byte_idx = i + shift_byte_num + 1;
			if ((shift_num % 8 != 0) and (possible_byte_idx < src_bytes.size())) {
				yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0, dst_bytes.at(i), src_bytes.at(possible_byte_idx), curr_session_taint_record);
			}
		}
	}
}

void handle_psrlw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), hr, 16 / 8);
}

void handle_vpsrlw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), hr, 16 / 8);
}

void handle_psrld(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), hr, 32 / 8);
}

void handle_vpsrld(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), hr, 32 / 8);
}

void handle_psrlq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(1), it->srcs.at(0), hr, 64 / 8);
}

void handle_vpsrlq(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	HandleRange hr = DefaultHandleRange)
{
	psrl(yt, instr_index, instr_taint_info, curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), hr, 64 / 8);
}

//void handle_common_pack(YTaint* yt, size_t instr_index,
//	InstrTaintInfo* instr_taint_info,
//	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
//	opnd* dst,
//	opnd* src0,
//	opnd* src1,
//	bool has_mask,
//	HandleRange hr,
//	int atom_byte_size,
//	int determine_size, // 2 or 4
//	int min_val,
//	int max_val)
//{
//	std::vector<MCByteID> dst_bytes;
//	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);
//
//	std::vector<MCByteID> src0_bytes;
//	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);
//
//	std::vector<MCByteID> src1_bytes;
//	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);
//
//	int64_t src_val = 0;
//	if (determine_size == 2) {
//		for (int i = 0; i < atom_byte_size; i++) {
//			if (i < atom_byte_size / 2) {
//				memcpy_s(&src_val, determine_size, src0->value + i * determine_size, determine_size);
//				if (min_val < src_val < max_val) {
//					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
//						dst_bytes.at(i), src0_bytes.at(i * 2), curr_session_taint_record);
//				}
//			}
//			else {
//				memcpy_s(&src_val, determine_size, src1->value + (i - 8) * determine_size, determine_size);
//				if (min_val < src_val < max_val) {
//					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
//						dst_bytes.at(i), src1_bytes.at((i - 8) * 2), curr_session_taint_record);
//				}
//			}
//		}
//	}
//	else if (determine_size == 4) {
//		for (int i = 0; i < atom_byte_size / 2; i++) {
//			if (i < atom_byte_size / 4) {
//				memcpy_s(&src_val, 4, src0->value + i * 4, 4);
//				if (src_val >= 0) {
//					for (int k = 0; k < 2; k++) {
//						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
//							dst_bytes.at(i * 2 + k), src0_bytes.at(i * 4 + k), curr_session_taint_record);
//					}
//				}
//			}
//			else {
//				memcpy_s(&src_val, 4, src1->value + (i - 4) * 4, 4);
//				if (src_val >= 0) {
//					for (int k = 0; k < 2; k++) {
//						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
//							dst_bytes.at(i * 2 + k), src1_bytes.at((i - 4) * 4 + k), curr_session_taint_record);
//					}
//				}
//			}
//		}
//	}
//}

void handle_common_pack(YTaint* yt, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	opnd* dst,
	opnd* src0,
	opnd* src1,
	bool has_mask,
	HandleRange hr,
	int atom_byte_size,
	int determine_size, // 2 or 4
	int min_val,
	int max_val)
{
	std::vector<MCByteID> dst_bytes;
	get_bytes_no_expand_consider_range(dst, hr, dst_bytes);

	std::vector<MCByteID> src0_bytes;
	get_bytes_no_expand_consider_range(src0, hr, src0_bytes);

	std::vector<MCByteID> src1_bytes;
	get_bytes_no_expand_consider_range(src1, hr, src1_bytes);

	int64_t src0_val, src1_val;
	int i, j;
	int start = hr.handle_byte_start;
	if (start == -1)
	{
		start = 0;
	}
	if (determine_size == 2) {
		for (i = 0; i < atom_byte_size; i++) {
			if (i < atom_byte_size / 2) {
				memcpy_s(&src0_val, determine_size, src0->value + i * 2 + start, determine_size);
				if (min_val <= src0_val && src0_val <= max_val) {
					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
						dst_bytes.at(i), src0_bytes.at(i * 2), curr_session_taint_record);
				}
			}
			else {
				memcpy_s(&src1_val, determine_size, src1->value + (i - atom_byte_size / 2) * 2 + start, determine_size);
				if (min_val <= src1_val && src1_val <= max_val) {
					yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
						dst_bytes.at(i), src1_bytes.at((i - atom_byte_size / 2) * 2), curr_session_taint_record);
				}
			}
		}
	}
	else if (determine_size == 4) {
		/*for (int i = 0; i < atom_byte_size / 2; i++) {
			if (i < atom_byte_size / 4) {
				memcpy_s(&src0_val, 4, src0->value + i * 4 + start, 4);
				if (src0_val >= 0) {
					for (int k = 0; k < 2; k++) {
						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
							dst_bytes.at(i * 2 + k), src0_bytes.at(i * 4 + k), curr_session_taint_record);
					}
				}
			}
			else {
				memcpy_s(&src1_val, 4, src1->value + (i - 4) * 4 + start, 4);
				if (src1_val >= 0) {
					for (int k = 0; k < 2; k++) {
						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
							dst_bytes.at(i * 2 + k), src1_bytes.at((i - 4) * 4 + k), curr_session_taint_record);
					}
				}
			}
		}*/
		for (i = 0; i < atom_byte_size; i += 2) {
			if (i < atom_byte_size / 2) {
				memcpy_s(&src0_val, determine_size, src0->value + i * 2 + start, determine_size);
				if (min_val <= src0_val && src0_val <= max_val) {
					for (int j = 0; j < 2; j++)
					{
						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
							dst_bytes.at(i + j), src0_bytes.at(i * 2 + j), curr_session_taint_record);
					}
				}
			}
			else {
				memcpy_s(&src1_val, determine_size, src1->value + (i - atom_byte_size / 2) * 2 + start, determine_size);
				if (min_val <= src1_val && src1_val <= max_val) {
					for (j = 0; j < 2; j++)
					{
						yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
							dst_bytes.at(i + j), src1_bytes.at((i - atom_byte_size / 2) * 2 + j), curr_session_taint_record);
					}
				}
			}
		}
	}
}

void handle_packuswb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 128 / 8, 2, 0x0, 0xff);
}

void handle_vpackuswb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 128 / 8, 2, 0x0, 0xff);
}

void handle_packusdw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 128 / 8, 2, 0x0, 0xffff);
}

void handle_vpackusdw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 128 / 8, 2, 0x0, 0xffff);
}

void handle_packsswb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 128 / 8, 2, 0x80, 0x7f);
}

void handle_vpacksswb(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 128 / 8, 2, 0x80, 0x7f);
}

void handle_packssdw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(0), it->srcs.at(1), has_mask, hr, 128 / 8, 2, 0x8000, 0x7fff);
}

void handle_vpackssdw(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	handle_common_pack(yt, instr_index, instr_taint_info,
		curr_session_taint_record, it->dsts.at(0), it->srcs.at(it->srcs.size() - 2), it->srcs.at(it->srcs.size() - 1), has_mask, hr, 128 / 8, 2, 0x8000, 0x7ffff);
}

void handle_rep_movs(YTaint* yt, instr* it, size_t instr_index,
	InstrTaintInfo* instr_taint_info,
	std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
	bool has_mask,
	HandleRange hr = DefaultHandleRange)
{
	opnd* src0 = it->srcs.at(0);
	std::vector<MCByteID> src0_real_bytes;
	get_bytes_in_expanded(src0, -1, src0_real_bytes);

	opnd* dst0 = it->dsts.at(0);
	std::vector<MCByteID> dst0_real_bytes;
	get_bytes_in_expanded(dst0, -1, dst0_real_bytes);

	int s_sz = src0_real_bytes.size();
	int d_sz = dst0_real_bytes.size();
	y_assert(s_sz == d_sz, "s_sz == d_sz", __FILE__, __LINE__);
	for (int i = 0; i < d_sz; i++) {
		MCByteID s0_i = src0_real_bytes.at(i);
		MCByteID d0_i = dst0_real_bytes.at(i);
		yt->update_dst_taint_info_if_src_is_tainted(instr_index, instr_taint_info, 0,
			d0_i, s0_i, curr_session_taint_record);
	}
}

// void (*handle_fp)(YTaint* yt, instr* it, size_t instr_index, InstrTaintInfo* instr_taint_info, std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record)
// the first two int for each op are only for v-prefixed instruction to show the mask opnd and mask atom byte size. 
std::map<std::string, std::tuple<SpecialHandleMode,
	MaskSrcOpndNum, MaskAtomByteSize, SplittedPartByteSize,
	void (*)(YTaint* yt, instr* it, size_t instr_index,
		InstrTaintInfo* instr_taint_info,
		std::map<MCByteID, SessionByteTaintSetInfo>& curr_session_taint_record,
		bool has_mask,
		HandleRange hr)>> special_handling_taint_meta = {
			// mostly for position taint but can be taken as normal taint, should judge reg_use_in_mem not src mem itself. 
			// {0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}
			{"bswap", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_bswap}},
			{"lea", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_lea}},
			{"vextractf128", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, common_handle_vextract128}},
			{"vextracti128", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, common_handle_vextract128}},
			{"vinsertf128", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, common_handle_vinsert128}},
			{"vinserti128", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, common_handle_vinsert128}},
			{"rep stos", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_rep_stos}},
			{"cmpxchg8b", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_cmpxchg8b}},
			{"cmpxchg", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_cmpxchg}},
			{"punpcklbw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpcklbw}},
			{"vpunpcklbw", {SpecialHandleMode::InvokeDirectOrNonV, 3, 8 / 8, -1, handle_vpunpcklbw}},
			{"punpcklwd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpcklwd}},
			{"vpunpcklwd", {SpecialHandleMode::InvokeDirectOrNonV, 3, 16 / 8, -1, handle_vpunpcklwd}},
			{"punpckldq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpckldq}},
			{"vpunpckldq", {SpecialHandleMode::InvokeDirectOrNonV, 3, 32 / 8, -1, handle_vpunpckldq}},
			{"punpcklqdq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpcklqdq}},
			{"vpunpcklqdq", {SpecialHandleMode::InvokeDirectOrNonV, 3, 64 / 8, -1, handle_vpunpcklqdq}},
			{"punpckhbw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpckhbw}},
			{"vpunpckhbw", {SpecialHandleMode::InvokeDirectOrNonV, 3, 8 / 8, -1, handle_vpunpckhbw}},
			{"punpckhwd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpckhwd}},
			{"vpunpckhwd", {SpecialHandleMode::InvokeDirectOrNonV, 3, 16 / 8, -1, handle_vpunpckhwd}},
			{"punpckhdq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpckhdq}},
			{"vpunpckhdq", {SpecialHandleMode::InvokeDirectOrNonV, 3, 32 / 8, -1, handle_vpunpckhdq}},
			{"punpckhqdq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_punpckhqdq}},
			{"vpunpckhqdq", {SpecialHandleMode::InvokeDirectOrNonV, 3, 64 / 8, -1, handle_vpunpckhqdq}},
			{"vmovd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, NULL}},
			{"vmovq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, NULL}},
			{"vmovntdq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, NULL}},
			{"vmovaps", {SpecialHandleMode::InvokeDirectOrNonV, 2, 32 / 8, -1, NULL}},
			{"vmovups", {SpecialHandleMode::InvokeDirectOrNonV, 2, 32 / 8, -1, NULL}},
			{"vaesenc", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, NULL}},
			{"vaesenclast", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, NULL}},
			{"paddb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 8 / 8, NULL}},
			{"vpaddb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 8 / 8, 8 / 8, NULL}},
			{"paddw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, NULL}},
			{"vpaddw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, NULL}},
			{"paddd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, NULL}},
			{"vpaddd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, NULL}},
			{"paddq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 64 / 8, NULL}},
			{"vpaddq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 64 / 8, 64 / 8, NULL}},
			//{"pcmpeqb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 8 / 8, NULL}},
			//{"vpcmpeqb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 8 / 8, 8 / 8, NULL}},
			//{"pcmpeqw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, NULL}},
			//{"vpcmpeqw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, NULL}},
			//{"pcmpeqd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, NULL}},
			//{"vpcmpeqd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, NULL}},
			{"pmovmskb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_common_v_or_pmovmskb}},
			{"vpmovmskb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_common_v_or_pmovmskb}},
			// VPORD may be different from normal situation if (EVEX.b = 1) AND (SRC2 *is memory*), handle this specifically. 
			// todo, to solve this, add loop in normal handle if some opnd byte size is not enough. 
			{"vpord", {SpecialHandleMode::InvokeDirectOrNonV, 3, 32 / 8, -1, NULL}},
			// same problem as vport. 
			{"vpandd", {SpecialHandleMode::InvokeDirectOrNonV, 3, 32 / 8, -1, NULL}},
			{"palignr", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_palignr}},
			{"vpalignr", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 4, 8 / 8, 128 / 8, handle_vpalignr}},
			{"pshufb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pshufb} },
			{"vpshufb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_vpshufb} },
			{"pshufd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pshufd}},
			{"vpshufd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 8 / 8, 128 / 8, handle_pshufd}},
			{"pshufw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pshufw}},
			{"pshufhw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_pshufhw}},
			{"vpshufhw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_pshufhw}},
			{"pshuflw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_pshuflw}},
			{"vpshuflw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_pshuflw}},
//			{"packsswb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_packsswb}},
//			{"vpacksswb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, 8 / 8, 128 / 8, handle_vpacksswb}},
//			{"packssdw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_packssdw}},
//			{"vpackssdw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_vpackssdw}},
//			{"packuswb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_packsswb}},
//			{"vpackuswb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, 8 / 8, 128 / 8, handle_vpacksswb}},
//			{"packusdw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_packssdw}},
//			{"vpackusdw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_vpackssdw}},
			{"vperm2i128", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_vperm2i128}},
			{"pmulhuw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, NULL}},
			{"vpmulhuw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, NULL}},
			{"pmaddwd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_pmaddwd}},
			{"vpmaddwd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, handle_vpmaddwd}},
			{"psraw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_psraw}},
			{"vpsraw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, handle_vpsraw}},
			{"psrad", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_psrad}},
			{"vpsrad", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, handle_vpsrad}},
			{"vpsraq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 64 / 8, 64 / 8, handle_vpsraq}},
			{"pinsrd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pinsrd}},
			{"vpinsrd", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_vpinsrd}},
			{"pinsrb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pinsrb}},
			{"vpinsrb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_vpinsrb}},
			{"pinsrq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pinsrq}},
			{"vpinsrq", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_vpinsrq}},
			{"pinsrw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_pinsrw}},
			{"vpinsrw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_vpinsrw}},
			{"vpsubb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 8 / 8, 8 / 8, NULL}},
			{"vpsubw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, NULL}},
			{"vpsubd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, NULL}},
			{"vpsubq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 64 / 8, 64 / 8, NULL}},
			{"pslld", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_pslld }},
			{"vpslld", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, handle_vpslld }},
			{"psllw", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_psllw }},
			{"vpsllw", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, handle_vpsllw }},
			{"psllq", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 64 / 8, handle_pslldq }},
			{"vpsllq", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, 64 / 8, 64 / 8, handle_vpslldq }},
			{"pslldq", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_pslldq }},
			{"vpslldq", { SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_vpslldq }},
			{"pmullw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_pmullw}},
			{"vpmullw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, handle_vpmullw}},
			{"pmulhw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_pmulhw}},
			{"vpmulhw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, handle_vpmulhw}},
			{"pmulld", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, NULL} },
			{"vpmulld", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, NULL} },
			{"pabsb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 8 / 8, NULL} },
			{"vpabsb", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 2, 8 / 8, 8 / 8, NULL} },
			{"pabsw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, NULL} },
			{"vpabsw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 2, 16 / 8, 16 / 8, NULL} },
			{"pabsd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, NULL} },
			{"vpabsd", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 2, 32 / 8, 32 / 8, NULL} },
			{"pabsq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 64 / 8, NULL} },
			{"vpabsq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 2, 64 / 8, 64 / 8, NULL} },
			{"vpermq", { SpecialHandleMode::InvokeDirectOrNonV, 3, 64 / 8, -1, handle_vpermq } },
			{"psignb",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 8 / 8, handle_psignb} },
			{"vpsignb",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 8 / 8, handle_vpsignb} },
			{"psignw",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_psignw} },
			{"vpsignw",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_vpsignw} },
			{"psignd",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_psignd} },
			{"vpsignd",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_vpsignd} },
			{"pslldq",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_pslldq} },
			{"vpslldq",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_vpslldq} },
			{"psrldq",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_psrldq} },
			{"vpsrldq",{SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 128 / 8, handle_vpsrldq} },
			{"psrlw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 16 / 8, handle_psrld} },
			{"vpsrlw", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 16 / 8, 16 / 8, handle_vpsrld} },
			{"psrld", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 32 / 8, handle_psrld} },
			{"vpsrld", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 32 / 8, 32 / 8, handle_vpsrld} },
			{"psrlq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, -1, -1, 64 / 8, handle_psrld} },
			{"vpsrlq", {SpecialHandleMode::SplitPartsAndEachPartInvokeDirectOrNonV, 3, 64 / 8, 64 / 8, handle_vpsrld} },
			{"packuswb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, 128 / 8, handle_packuswb} },
			{"vpackuswb", {SpecialHandleMode::InvokeDirectOrNonV, 3, 8 / 8, 128 / 8, handle_vpackuswb} },
			{"packusdw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, 128 / 8, handle_packusdw} },
			{"vpackusdw", {SpecialHandleMode::InvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_vpackusdw} },
			{"packsswb", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, 128 / 8, handle_packsswb} },
			{"vpacksswb", {SpecialHandleMode::InvokeDirectOrNonV, 3, 8 / 8, 128 / 8, handle_vpacksswb} },
			{"packssdw", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, 128 / 8, handle_packssdw} },
			{"vpackssdw", {SpecialHandleMode::InvokeDirectOrNonV, 3, 16 / 8, 128 / 8, handle_vpackssdw} },
			{"rep movs", {SpecialHandleMode::InvokeDirectOrNonV, -1, -1, -1, handle_rep_movs} },
};








