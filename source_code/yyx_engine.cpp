#include <stdint.h>

#include "yyx_global_info.h"
#include "yyx_engine.h"


/*
* first level string key is op name. 
* second level vector pair int key is dest index in all dest opnds. 
* second level vector pair int value is all source indexs (each in source opnds). 
* if pair key is -1, pair value must be null, it means the instruction is executed but has conditions or rep expanded info. 
*/
std::map<std::string, std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>> taint_meta = {
	{"add",{ {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"or", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}} } },
	{"sbb", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"and", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}} } },
	{"sub", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"xor", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}} } },
	{"cmp", {} },//0dst 2src
	{"pcmpeqb", {} },
	{"pcmpeqd", {} },
	{"pcmpeqw", {} },
	{"pcmpeqq", {} },
	{"pcmpgtb", {} },
	{"pcmpgtd", {} },
	{"pcmpgtw", {} },
	{"pcmpgtq", {} },
	{"vpcmpeqb", {} },
	{"vpcmpeqw", {} },
	{"vpcmpeqd", {} },
	{"inc", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"dec", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"push", { {1,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}} } },// {0,{{1,InstructionTaintType::ByteToAtOrPrevBytes}}} xsp must not be tainted. 
	{"pop", { {0,{{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },// ,{1,{0}} actually, xsp must not be tainted. 
	{"imul", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"jb", {} },
	{"jnb", {} },
	{"jz", {} },
	{"jnz", {} },
	{"jbe",{} },
	{"jnbe", {} },
	{"js", {} },
	{"jns", {} },
	{"jl", {} },
	{"jnl", {} },
	{"jle", {} },
	{"jnle", {} },
	{"call", {} },
	{"jmp", {} },
	{"mov", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"test", {} },//0dst 2src
	{"xchg", {{0,{{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}},{1,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cwde", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"cdq", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"ret", {} },
	{"syscall", {} },//2dst 0src
	{"cmovb", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnb", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovz", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnz", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovbe", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnbe", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovs", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovns", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovl", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnl", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovle", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnle", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cld", {}},
	{"movd", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movq", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movdqu", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vmovdqu", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movdqa", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vmovdqa", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"jb", {}},
	{"jnb",{}},
	{"jz",{}},
	{"jnz",{}},
	{"jbe",{}},
	{"jnbe",{}},
	{"js",{}},
	{"jns",{}},
	{"jl",{}},
	{"jnl",{}},
	{"jle",{}},
	{"jnle",{}},
	{"rdseed",{}},
	{"rdtscp",{}},
	{"setl",{}},
	{"setb",{}},
	{"setbe",{}},
	{"setnb",{}},
	{"setz",{}},
	{"setnz",{}},
	{"setnbe",{}},
	{"setns",{}},
	{"setnle",{}},
	{"sfence",{}},
	{"cpuid",{}},
	{"bt",{}},
	{"bts",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},// bit position taint, but can be considered as value tainted. 
	{"btr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},// bit position taint, but can be considered as value tainted. 
	{"movzx",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"bsf",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"bsr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"movsx",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}}},
	{"xadd",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}, {1,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"psrldq",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"rol",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"ror",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"shl",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"shr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"sar",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"not",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"neg",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"mul",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"pmulld",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"vpmulld",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"div",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"idiv",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"lfence",{}},
	{"prefetchw",{}},
	{"movups",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"movss",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"movsd",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"movhps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"movaps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"comiss",{}},
	{"xorps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"movsxd",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"xgetbv",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"movdqu",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movntdq",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vzeroupper",{}},
	{"rdrand",{}},
	{"pand",{{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpand",{{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"aesenc",{{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vaesenc",{{0,{{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"aesenclast",{{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vaesenclast",{{0,{{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"paddb",{{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"paddw",{{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"paddd",{{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"paddq",{{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"por", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpor", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpord", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"pxor", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpxor", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"pand", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpand", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"vpandd", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint},{1,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"aeskeygenassist", {{0, {{1, DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"psubb", {{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"psubw", {{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"psubd", {{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"psubq", {{0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"pabsb", {{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"pabsw", {{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"pabsd", {{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"pabsq", {{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
};

std::map<int, std::pair<int, int>> initialize_reg_to_belonged_max_size_reg_and_offset() {
	std::map<int, std::pair<int, int>> res = {
		{DR_REG_AL,{DR_REG_RAX,0}},
		{DR_REG_CL,{DR_REG_RCX,0}},
		{DR_REG_DL,{DR_REG_RDX,0}},
		{DR_REG_BL,{DR_REG_RBX,0}},
		{DR_REG_AH,{DR_REG_RAX,1}},
		{DR_REG_CH,{DR_REG_RCX,1}},
		{DR_REG_DH,{DR_REG_RDX,1}},
		{DR_REG_BH,{DR_REG_RBX,1}},
		{DR_REG_SPL,{DR_REG_RSP,0}},
		{DR_REG_BPL,{DR_REG_RBP,0}},
		{DR_REG_SIL,{DR_REG_RSI,0}},
		{DR_REG_DIL,{DR_REG_RDI,0}},
	};
	// the above only shows an example code, then, we initialize based on iteration code. 
	for (int i = DR_REG_R8L; i <= DR_REG_R15L; i++) {
		res.insert({ i, {DR_REG_R8 + (i - DR_REG_R8L), 0} });
	}
	for (int i = DR_REG_AX; i <= DR_REG_R15W; i++) {
		res.insert({ i, {DR_REG_RAX + (i - DR_REG_AX), 0} });
	}
	for (int i = DR_REG_EAX; i <= DR_REG_R15D; i++) {
		res.insert({ i, {DR_REG_RAX + (i - DR_REG_EAX), 0} });
	}
	for (int i = DR_REG_MM0; i <= DR_REG_MM7; i++) {
		res.insert({ i, {DR_REG_ZMM0 + (i - DR_REG_MM0), 0} });
	}
	for (int i = DR_REG_XMM0; i <= DR_REG_XMM31; i++) {
		res.insert({ i, {DR_REG_ZMM0 + (i - DR_REG_XMM0), 0} });
	}
	for (int i = DR_REG_YMM0; i <= DR_REG_YMM31; i++) {
		res.insert({ i, {DR_REG_ZMM0 + (i - DR_REG_YMM0), 0} });
	}
	return res;
}

std::map<int, std::pair<int, int>> reg_to_belonged_max_size_reg_and_offset = initialize_reg_to_belonged_max_size_reg_and_offset();

void get_reg_bytes(int reg_id, byte start_byte_idx, byte byte_len, std::vector<MCByteID>& res) {
	y_assert(start_byte_idx >= 0 and byte_len > 0, "start_byte_idx >= 0 and byte_len > 0", __FILE__, __LINE__);
	std::pair<int, int> belonged_reg_id_and_offset = get_belonged_max_size_reg_id_and_offset(reg_id);
	for (int i = 0; i < byte_len; i++) {
		int byte_idx = start_byte_idx + i;
	//	int reg_byte_id = (belonged_reg_id_and_offset.first << 8) + byte_idx + belonged_reg_id_and_offset.second;
		MCByteID mbid(belonged_reg_id_and_offset.first, byte_idx + belonged_reg_id_and_offset.second, false);
		res.insert(res.end(), mbid);
	}
}

void get_mem_bytes(byte* addr, size_t mlen, std::vector<MCByteID>& res) {
	for (int i = 0; i < mlen; i++) {
		MCByteID mbid((uint64_t)(addr + i));
		res.insert(res.end(), mbid);
	}
}

void get_mem_opnd_bytes_in_expanded(opnd* s, int expand_idx, std::vector<MCByteID>& res) {
	y_assert(expand_idx > -1, "expand_idx > -1", __FILE__, __LINE__);
	y_assert(s->expanded_infos.size() > expand_idx, "s->expanded_infos.size() > expand_idx", __FILE__, __LINE__);
	expanded_opnd_info* eoi = s->expanded_infos.at(expand_idx);
	get_mem_bytes(reinterpret_cast<byte*>(eoi->reg_inner_rel_addr_or_mem_addr), eoi->sz, res);
}

void get_mem_opnd_bytes_no_expand(opnd* s, int start, int len, std::vector<MCByteID>& res) {
	y_assert(len >= 0, "len >= 0", __FILE__, __LINE__);
	if (len > 0) {
		y_assert(start >= 0 and len > 0 and start + len <= s->actual_size, "start >= 0 and len > 0 and start + len <= s->actual_size", __FILE__, __LINE__);
	}
	get_mem_bytes(reinterpret_cast<byte*>(s->reg_id_mem_addr) + start, len, res);
}

void get_immed_bytes(size_t immlen, std::vector<MCByteID>& res) {
	for (int i = 0; i < immlen; i++) {
		// we only want byte offset, so not_sure enum value is enough. 
		MCByteID mbid(ByteImmType::not_sure, i);
		res.insert(res.end(), mbid);
	}
}

void get_reg_opnd_bytes_in_expanded(opnd* s, int expand_idx, std::vector<MCByteID>& res) {
	y_assert(expand_idx > -1, "expand_idx > -1", __FILE__, __LINE__);
	y_assert(s->expanded_infos.size() > expand_idx, "s->expanded_infos.size() > expand_idx", __FILE__, __LINE__);
	expanded_opnd_info* eoi = s->expanded_infos.at(expand_idx);
	get_reg_bytes(s->reg_id_mem_addr, eoi->reg_inner_rel_addr_or_mem_addr, eoi->sz, res);
}

void get_reg_opnd_bytes_no_expand(opnd* s, int start, int len, std::vector<MCByteID>& res) {
	y_assert(start >= 0 and len > 0 and start + len <= s->actual_size, "start >= 0 and len > 0 and start + len <= s->actual_size", __FILE__, __LINE__);
	get_reg_bytes(s->reg_id_mem_addr, start, len, res);
}

std::pair<int, int> get_belonged_max_size_reg_id_and_offset(int reg_id) {
	std::pair<int, int> res = { reg_id, 0 };
	auto it = reg_to_belonged_max_size_reg_and_offset.find(reg_id);
	if (it != reg_to_belonged_max_size_reg_and_offset.end()) {
		res = it->second;
	}
	return res;
}

// if start is -1, means use opnd's actual size. 
void get_bytes_no_expand(opnd* o, int start, int len, std::vector<MCByteID>& res) {
	int r_start = start;
	int r_len = len;
	if (start == -1 || len == -1) {
		y_assert(start == -1 || start == 0, "start == -1 || start == 0", __FILE__, __LINE__);
		r_start = 0;
		r_len = o->actual_size;
	}
	if (o->detail_ot == opnd_type::is_reg) {
		get_reg_opnd_bytes_no_expand(o, r_start, r_len, res);
	}
	else if (o->detail_ot == opnd_type::is_mem) {
		get_mem_opnd_bytes_no_expand(o, r_start, r_len, res);
	}
	else if (o->detail_ot == opnd_type::is_immed_int || o->detail_ot == opnd_type::is_immed_float) {
//	else if (o->op.rfind("immed_", 0) == 0) {
		// the immed must return bytes, as ByteToByteNotChange depends on numner of bytes to set up untaint or taint information. 
		get_immed_bytes(r_len, res);
	}
	else {
		y_assert(false, "detail_ot wrong.", __FILE__, __LINE__);
	}
}

void get_bytes_in_expanded(opnd* o, int expand_idx, std::vector<MCByteID>& res) {
	if (o->expanded_infos.size() > 0) {
		if (expand_idx > -1) {
			if (o->detail_ot == opnd_type::is_reg) {
				get_reg_opnd_bytes_in_expanded(o, expand_idx, res);
			}
			else if (o->detail_ot == opnd_type::is_mem) {
				get_mem_opnd_bytes_in_expanded(o, expand_idx, res);
			}
			else {
				y_assert(false, "detail_ot wrong.", __FILE__, __LINE__);
			}
		}
		else {
			for (int ei = 0; ei < o->expanded_infos.size(); ei++) {
				if (o->detail_ot == opnd_type::is_reg) {
					get_reg_opnd_bytes_in_expanded(o, ei, res);
				}
				else if (o->detail_ot == opnd_type::is_mem) {
					get_mem_opnd_bytes_in_expanded(o, ei, res);
				}
				else {
					y_assert(false, "detail_ot wrong.", __FILE__, __LINE__);
				}
			}
		}
	}
}




