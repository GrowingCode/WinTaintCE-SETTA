#pragma once

#include <stdint.h>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <sstream>

#include "yyx_global_info.h"
#include "yyx_trace.h"


enum e_flags {
	CF,
	PF,
	AF,
	ZF,
	SF,
	TF,
	IF,
	DF,
	OF,
	NT,
	RF,
	NULLEF,
};

#define 	EFLAGS_READ_CF   0x00000001
#define 	EFLAGS_READ_PF   0x00000002
#define 	EFLAGS_READ_AF   0x00000004
#define 	EFLAGS_READ_ZF   0x00000008
#define 	EFLAGS_READ_SF   0x00000010
#define 	EFLAGS_READ_TF   0x00000020
#define 	EFLAGS_READ_IF   0x00000040
#define 	EFLAGS_READ_DF   0x00000080
#define 	EFLAGS_READ_OF   0x00000100
#define 	EFLAGS_READ_NT   0x00000200
#define 	EFLAGS_READ_RF   0x00000400
#define 	EFLAGS_WRITE_CF   0x00000800
#define 	EFLAGS_WRITE_PF   0x00001000
#define 	EFLAGS_WRITE_AF   0x00002000
#define 	EFLAGS_WRITE_ZF   0x00004000
#define 	EFLAGS_WRITE_SF   0x00008000
#define 	EFLAGS_WRITE_TF   0x00010000
#define 	EFLAGS_WRITE_IF   0x00020000
#define 	EFLAGS_WRITE_DF   0x00040000
#define 	EFLAGS_WRITE_OF   0x00080000
#define 	EFLAGS_WRITE_NT   0x00100000
#define 	EFLAGS_WRITE_RF   0x00200000
#define 	EFLAGS_READ_ALL   0x000007ff
#define 	EFLAGS_READ_NON_PRED   EFLAGS_READ_ALL
#define 	EFLAGS_WRITE_ALL   0x003ff800
#define 	EFLAGS_READ_6   0x0000011f
#define 	EFLAGS_WRITE_6   0x0008f800
#define 	EFLAGS_READ_ARITH   EFLAGS_READ_6
#define 	EFLAGS_WRITE_ARITH   EFLAGS_WRITE_6
#define 	EFLAGS_WRITE_TO_READ(x)   ((x) >> 11)
#define 	EFLAGS_READ_TO_WRITE(x)   ((x) << 11)

enum DstSrcOpndTaintType {
	ByteToAllBytes, // most arith instructions use this type. 
	//	ByteToAtOrPrevBytes, 
//	ByteToByteOthersNotChange, // mostly for mov series. 
	ByteToByteOthersUntaint, // mostly for mov/movzx series. 
	ByteToByteOthersSignExtend, // mostly for movsx series. 
//	ByteToEvenHalfIndexByte,
//	ByteToOddHalfIndexByte,
//	QWordToEvenHalfIndexQWord,
//	QWordToOddHalfIndexQWord,

	InstructionExecutedConditional,// for movd, movq, cmpxchg, others should be untainted or ignored should be condtioned on opnd type. 
};

extern std::map<std::string, std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>> taint_meta;

/*typedef enum taint_res
{
	TAINT_NONE = 0,
	TAINT_SPREAD = 1,
	TAINT_SHRINK = 2
} taint_res_t;*/

enum ByteType {
	reg,
	mem,
	immed,
};

enum ByteImmType {
	not_sure,// if we only want byte offset, just use this is ok.
	is_int,
	is_float,
};

class MCByteID {

public:

	static const int reg_lf_bit_num = 20;
	static const int reg_byte_offset_max_bit_num = 18;

	byte byte_type = ByteType::reg;// 0 is reg, 1 is mem. 
	uint64_t reg_id_or_mem_or_imm_with_byte_offset = 0;

	MCByteID() {
	}

	MCByteID(const MCByteID& mbid) {
		this->byte_type = mbid.byte_type;
		this->reg_id_or_mem_or_imm_with_byte_offset = mbid.reg_id_or_mem_or_imm_with_byte_offset;
	}
//	MCByteID(byte byte_type, uint64_t reg_id_or_mem_with_byte_offset) : byte_type(byte_type), reg_id_or_mem_with_byte_offset(reg_id_or_mem_with_byte_offset) {}
	MCByteID(uint16_t reg_id, uint16_t byte_offset, bool offset_to_max) {
		this->byte_type = ByteType::reg;
		y_assert(byte_offset < (1 << reg_byte_offset_max_bit_num), "byte_offset < (1 << reg_byte_offset_max_bit_num)", __FILE__, __LINE__);
		this->reg_id_or_mem_or_imm_with_byte_offset = ((uint64_t)reg_id << reg_lf_bit_num) + (offset_to_max ? ((uint64_t)1 << reg_byte_offset_max_bit_num) : byte_offset);
	}
	MCByteID(uint64_t mem_offset) {
		this->byte_type = ByteType::mem;
		this->reg_id_or_mem_or_imm_with_byte_offset = mem_offset;
	}
	MCByteID(ByteImmType bit, uint64_t imm_val) {
		this->byte_type = ByteType::immed;
		this->reg_id_or_mem_or_imm_with_byte_offset = imm_val;
	}

	~MCByteID() {}

	bool operator <(const MCByteID& order) const {
		if ((byte_type < order.byte_type)
			|| (byte_type == order.byte_type) && (reg_id_or_mem_or_imm_with_byte_offset < order.reg_id_or_mem_or_imm_with_byte_offset)) {
			return true;
		}
		return false;
	}

	bool operator ==(const MCByteID& order) const {
		return byte_type == order.byte_type and reg_id_or_mem_or_imm_with_byte_offset == order.reg_id_or_mem_or_imm_with_byte_offset;
	}

	friend std::ostream& operator <<(std::ostream& out, const MCByteID& mbid)
	{
		out << mbid.to_string();
		return out;
	}

	std::string to_string() const {
		std::ostringstream oss;
		if (this->byte_type == ByteType::reg) {
			uint16_t reg_id = this->reg_id_or_mem_or_imm_with_byte_offset >> reg_lf_bit_num;
			uint64_t temp_mask = ((uint64_t)1 << reg_byte_offset_max_bit_num) - 1;
			uint32_t byte_offset = this->reg_id_or_mem_or_imm_with_byte_offset & temp_mask;
			oss << "reg_id:" << reg_id << ",byte_offset:" << byte_offset;//  << ";"
		}
		else if (this->byte_type == ByteType::mem) {
			uint64_t mem_offset = this->reg_id_or_mem_or_imm_with_byte_offset;
			oss << "mem_addr:" << reinterpret_cast<void*>(mem_offset);//  << ";"
		}
		else if (this->byte_type == ByteType::immed) {
			uint64_t imm_offset = this->reg_id_or_mem_or_imm_with_byte_offset;
			oss << "imm_byte_index:" << imm_offset;//  << ";"
		}
		else {
			y_assert(false, "byte_type wrong.", __FILE__, __LINE__);
		}
		return oss.str();
	}

};

/*
class MCRegOrMem {
	
public:

	byte rm_type = 0;// 0 is reg, 1 is memory. 
	uint64_t reg_id_or_mem_addr = 0;

	MCRegOrMem() {

	}

	MCRegOrMem(byte rm_type, uint64_t reg_id_or_mem_addr) {
		this->rm_type = rm_type;
		this->reg_id_or_mem_addr = reg_id_or_mem_addr;
	}

	~MCRegOrMem() {

	}

	bool operator <(const MCRegOrMem& order) const {
		if ((rm_type < order.rm_type)
			|| (rm_type == order.rm_type) && (reg_id_or_mem_addr < order.reg_id_or_mem_addr)) {
			return true;
		}
		return false;
	}

};
*/

enum SessionByteTaintType {
	UnChanged,
	SetTaint,
};

// must be dst opnd. 
class TraceableByteTaintSetPosition {

public:

	size_t instr_index_which_set_dst_byte = 0;
	MCByteID bid;

	bool operator <(const TraceableByteTaintSetPosition& order) const {
		if ((instr_index_which_set_dst_byte < order.instr_index_which_set_dst_byte)
			|| (instr_index_which_set_dst_byte == order.instr_index_which_set_dst_byte) && (bid < order.bid)) {
			return true;
		}
		return false;
	}

	TraceableByteTaintSetPosition() {
	}

	TraceableByteTaintSetPosition(size_t instr_index_which_set_dst_byte, MCByteID bid) {
		this->instr_index_which_set_dst_byte = instr_index_which_set_dst_byte;
		this->bid = bid;
	}

	~TraceableByteTaintSetPosition() {
	}

	friend std::ostream& operator << (std::ostream& out, const TraceableByteTaintSetPosition& a) {
		out << a.to_string();
		return out;
	}

	std::string to_string() const {
		std::ostringstream oss;
		
		oss << "bid:" << bid.to_string() << ";set_instr_index:" << instr_index_which_set_dst_byte << ";";
		
		return oss.str();
	}

};

class SessionByteTaintSetInfo {

public:
	SessionByteTaintType sbtt = SessionByteTaintType::UnChanged;
	// if sbtt is SessionByteTaintType::SetTaint, tbtsp must be with valid value, otherwise, tbtsp can be 0 default values. 
	TraceableByteTaintSetPosition tbtsp;

	SessionByteTaintSetInfo() {
	}

	SessionByteTaintSetInfo(TraceableByteTaintSetPosition tbtsp) {
		this->sbtt = SessionByteTaintType::SetTaint;
		this->tbtsp = tbtsp;
	}

	~SessionByteTaintSetInfo() {
	}
};

class DstByteTaintInfoInInstr {

public:
	std::set<uint16_t> which_dst_opnd_idx_set_byte_taint;
	// the taint set info of a src is the dst byte in which the src byte is latestly tainted. 
	std::set<TraceableByteTaintSetPosition> all_srcs_taint_set_info_which_taint_this_dst;

	DstByteTaintInfoInInstr() {

	}

	DstByteTaintInfoInInstr(const DstByteTaintInfoInInstr& dbt) {
		this->which_dst_opnd_idx_set_byte_taint = dbt.which_dst_opnd_idx_set_byte_taint;
		this->all_srcs_taint_set_info_which_taint_this_dst = dbt.all_srcs_taint_set_info_which_taint_this_dst;
	}

	~DstByteTaintInfoInInstr() {

	}

};

enum RegType {
	src_reg,
//	dst_reg,
	src_use_in_mem_reg,
	dst_max_reg,
};

class InstrTaintInfo {

public:

//	bool instr_srcs_exist_tainted = false;
//	bool instr_dsts_exist_tainted = false;
//	bool instr_exist_tainted = false;
	
	// the following only affects the dst taint handle logic. 
	// here is the which memory or reg byte are set up dst tainted in this instr. 
	// each byte has an id. 
	// summarize dst byte's reg or mem, if is reg and not tainted before instr, must set the dst reg's max reg's value (value is before this instr), otherwise, this triton max_reg value must equal the trace value (before instr). 
	// record whether dst reg is tainted before executing an instr, because the latest_taint_record is only available in the procedure of taint analysis and this data is used after the analysis. 
	// the dst_byte_srcs_bytes_taint_set_info only stores whether dst reg is tainted after executing an instr. 
	// this should be just a copy of latest_taint_record. 
	// directly copy latest_taint_record is to complex, just record tainted max reg in use. 
	// the following three structures are filled before main taint execution. 
//	std::set<uint16_t> tainted_dst_reg_before_instr;
//	std::set<uint16_t> tainted_src_and_use_in_mem_reg_before_instr;
//	std::set<uint16_t> tainted_src_and_use_in_mem_max_reg_before_instr;
	// this data is necessary, as this should only store the tainted memory byte, but for simplicity, we also store tainted reg byte. 
#if taint_simplified_mode == 1
	bool has_tainted_dst_byte_srcs_bytes_taint_set_info = false;
	bool has_tainted_dst_max_reg_before_instr = false;
	bool has_tainted_src_reg_before_instr = false;
	bool has_tainted_src_mem_bytes = false;
	bool has_tainted_src_reg_bytes = false;
#else
	std::map<MCByteID, DstByteTaintInfoInInstr*> tainted_dst_byte_srcs_bytes_taint_set_info;
	std::set<uint16_t> tainted_dst_max_reg_before_instr;
	std::set<uint16_t> tainted_src_reg_before_instr;
	std::set<MCByteID> tainted_src_mem_bytes;
	std::set<MCByteID> tainted_src_reg_bytes;
#endif

	// include reg and mem but exclude reg_use_in_mem. 
//	std::set<MCByteID> tainted_src_bytes;
	// summarize src byte's reg or mem, if is tainted, the triton value must be equal with the trace value, otherwise, force set the value to trace value. 
	// reg_in_mem_ref is also included. 

	InstrTaintInfo() {

	}

	InstrTaintInfo(InstrTaintInfo* iti) {
#if taint_simplified_mode == 1
		this->has_tainted_dst_byte_srcs_bytes_taint_set_info = iti->has_tainted_dst_byte_srcs_bytes_taint_set_info;
		this->has_tainted_dst_max_reg_before_instr = iti->has_tainted_dst_max_reg_before_instr;
		this->has_tainted_src_reg_before_instr = iti->has_tainted_src_reg_before_instr;
		this->has_tainted_src_mem_bytes = iti->has_tainted_src_mem_bytes;
		this->has_tainted_src_reg_bytes = iti->has_tainted_src_reg_bytes;
#else

		for (const auto& kvp : iti->tainted_dst_byte_srcs_bytes_taint_set_info) {
			MCByteID key = kvp.first;
			DstByteTaintInfoInInstr* value = kvp.second;
			DstByteTaintInfoInInstr* copiedValue = NULL;
			if (value != NULL) {
				copiedValue = new DstByteTaintInfoInInstr(*value);
			}
			this->tainted_dst_byte_srcs_bytes_taint_set_info[key] = copiedValue;
		}
//		this->tainted_dst_reg_before_instr = iti->tainted_dst_reg_before_instr;
		this->tainted_dst_max_reg_before_instr = iti->tainted_dst_max_reg_before_instr;
//		this->tainted_src_and_use_in_mem_reg_before_instr = iti->tainted_src_and_use_in_mem_reg_before_instr;
//		this->tainted_src_and_use_in_mem_max_reg_before_instr = iti->tainted_src_and_use_in_mem_max_reg_before_instr;
		this->tainted_src_reg_bytes = iti->tainted_src_reg_bytes;
		this->tainted_src_mem_bytes = iti->tainted_src_mem_bytes;
//		this->tainted_src_bytes = iti->tainted_src_bytes;
#endif
	}

#if taint_simplified_mode == 1
	void PutDstByteSrcsBytesTaintSetInfo() {
		has_tainted_dst_byte_srcs_bytes_taint_set_info = true;
	}
#else
	void PutDstByteSrcsBytesTaintSetInfo(MCByteID mbid, DstByteTaintInfoInInstr* dbtiii) {
		tainted_dst_byte_srcs_bytes_taint_set_info.insert_or_assign(mbid, dbtiii);
	}
#endif

	// only lea needs to consider strict dst as it uses reg_in_mem to compute dst. 
	bool SrcRegOrMemOrStrictDstHaveTaintBeforeInstr() {
//		return tainted_src_and_use_in_mem_reg_before_instr.size() > 0 || tainted_src_mem_bytes.size() > 0;
#if taint_simplified_mode == 1
		return has_tainted_src_reg_bytes || has_tainted_src_mem_bytes 
			|| has_tainted_dst_byte_srcs_bytes_taint_set_info;
#else
		return tainted_src_reg_bytes.size() > 0 || tainted_src_mem_bytes.size() > 0 
			|| tainted_dst_byte_srcs_bytes_taint_set_info.size() > 0;
#endif
	}

	//bool SrcRegOrMemHaveTaintBeforeInstr() {
	//	return SrcRegOrMemHaveTaintBeforeInstr() || tainted_src_and_use_in_mem_max_reg_before_instr.size() > 0;
	//}

	// must consider here and judge whether triton value is same as trace value even the dst is to be untainted. 
	bool DstMaxRegHasTaintBeforeInstr() {
#if taint_simplified_mode == 1
		return has_tainted_dst_max_reg_before_instr;
#else
		return tainted_dst_max_reg_before_instr.size() > 0;
#endif
	}

//	InstrTaintInfo(bool instr_srcs_exist_tainted, bool instr_dsts_exist_tainted) {
//		this->instr_srcs_exist_tainted = instr_srcs_exist_tainted;
//		this->instr_dsts_exist_tainted = instr_dsts_exist_tainted;
//	}

	~InstrTaintInfo() {
#if taint_simplified_mode == 1
#else
		for (auto it = tainted_dst_byte_srcs_bytes_taint_set_info.begin(); it != tainted_dst_byte_srcs_bytes_taint_set_info.end(); it++) {
			DstByteTaintInfoInInstr* dbt = it->second;
			if (dbt != NULL) {
				dbt->which_dst_opnd_idx_set_byte_taint.clear();
				dbt->all_srcs_taint_set_info_which_taint_this_dst.clear();
				delete dbt;
			}
		}
#endif
	}

};

class InstrTaintRootInfo {

public:

	// origin_taint's key is the byte that has been tainted since the end of the current instruction execution. 
	// origin_taint's value is all possible bytes in the source operand that caused the key to be tainted before all instructions were executed. 
	std::map<MCByteID, std::set<TraceableByteTaintSetPosition>> origin_taint;

	InstrTaintRootInfo() {

	}

	InstrTaintRootInfo(InstrTaintRootInfo* itri) {
		origin_taint = itri->origin_taint;
//		dst_byte_origin_taint = itri->dst_byte_origin_taint;
//		src_byte_origin_taint = itri->src_byte_origin_taint;
	}

	~InstrTaintRootInfo() {

	}

};

class BranchDependInfo {

public:

	bool depends_exist_tainted = false;
	std::set<uint64_t> depend_idxes;

	BranchDependInfo() {

	}

	BranchDependInfo(BranchDependInfo* bdi) {
		this->depends_exist_tainted = bdi->depends_exist_tainted;
		this->depend_idxes = bdi->depend_idxes;
	}

	~BranchDependInfo() {

	}

};

void get_mem_bytes(byte* addr, size_t mlen, std::vector<MCByteID>& res);

void get_mem_opnd_bytes_in_expanded(opnd* s, int expand_idx, std::vector<MCByteID>& res);

void get_mem_opnd_bytes_no_expand(opnd* s, int start, int len, std::vector<MCByteID>& res);

void get_immed_bytes(size_t immlen, std::vector<MCByteID>& res);

void get_reg_bytes(int reg_id, byte start_byte_idx, byte byte_len, std::vector<MCByteID>& res);

void get_reg_opnd_bytes_in_expanded(opnd* s, int expand_idx, std::vector<MCByteID>& res);

void get_reg_opnd_bytes_no_expand(opnd* s, int start, int len, std::vector<MCByteID>& res);

std::pair<int, int> get_belonged_max_size_reg_id_and_offset(int reg_id);

// if start is -1, means use opnd's actual size. 
void get_bytes_no_expand(opnd* o, int start, int len, std::vector<MCByteID>& res);

void get_bytes_in_expanded(opnd* o, int expand_idx, std::vector<MCByteID>& res);



