#pragma once

#include <set>
#include <map>
#include <vector>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <iostream>
#include <windows.h>

#include "yyx_global_info.h"

// extern bool check_op;

constexpr uint64_t is_cbr_in_type_position_and_info = 0x1;

enum trace_unit_type {
	is_in_partial_use,/*actually nothing is meaningless, but insert here to be consistent with unit_type*/
	is_op_meta,
	is_src,
	is_dst,
	is_high_level_op_type,
	is_expanded_rep_str,
};

enum opnd_type {
	is_no_type,/*actually nothing is meaningless, but insert here to be consistent with unit_detail_type*/
	is_reg,
	is_mem,
	is_immed_int,
	is_immed_float,
	is_pc
};

enum high_level_op_type {
	main_entry,
	heap_free,
	heap_alloc,
	read_file,
};

enum RegUseInMemOrDstMaxRegType {
	not_in_mem,
	reg_used_in_mem_ref,
	max_reg_of_dst_reg,
};

enum ExecuteState {
	InstrExecuteResultBase = 0,
	BufferModifyStateBase = 3,
};

class trace_read_util {

public:

	static void hex_string_to_byte_array(std::string& s, byte* arr, size_t alen) {
		size_t slength = s.size();
		y_assert(slength / 2 == alen and slength % 2 == 0, "byte array length error, yyx_trace.h, line 61.", __FILE__, __LINE__);
		for (size_t i = 0, j = 0; i < alen; i++, j += 2) {
			arr[i] = (s[j] % 32 + 9) % 25 * 16 + (s[j + 1] % 32 + 9) % 25;
		}
	}

	static void convert_to_hex(std::string& str, byte* opcode, size_t size)
	{
		for (size_t i = 0; i < size; i++)
		{
			std::string sub = str.substr(i * 2, 2);
			unsigned long mid = stoul(sub, nullptr, 16);
			opcode[i] = mid;
		}
	}

	static std::string get_substr(std::string curline, std::string target, int& spos)
	{
		std::string cursub("");

		int epos = curline.find(target, (uint64_t)spos + 1);
		if (epos > -1) {
			cursub = curline.substr((uint64_t)spos + 1, (uint64_t)epos - spos - 1);
			spos = epos;
		}

		return cursub;
	}

};

class expanded_opnd_info {

public:
	uint64_t reg_inner_rel_addr_or_mem_addr;
	uint64_t sz;
	byte* value;

	expanded_opnd_info(expanded_opnd_info* eoi)
	{
		this->reg_inner_rel_addr_or_mem_addr = eoi->reg_inner_rel_addr_or_mem_addr;
		this->sz = eoi->sz;

		byte* cur_value = new byte[sz];
		memcpy_s(cur_value, sz, eoi->value, sz);
		this->value = cur_value;
	}

	expanded_opnd_info(uint64_t mem_addr, uint64_t sz, byte* value) {
		this->reg_inner_rel_addr_or_mem_addr = mem_addr;
		this->sz = sz;
		this->value = value;
	}

	~expanded_opnd_info() {
		delete[] value;
	}

};

class opnd { //record instruction src opnd and dst opnd

public:

	int optype = 0;//1,src opnd;2,dst opnd
	opnd_type detail_ot = is_no_type;
	int64_t opnd_rep_time_direction = 0;
	uint64_t reg_id_mem_addr = 0;//reg id, mem_addr, pc_addr, imm
	std::string pc_module_name = "";
	uint64_t pc_offset = 0;
	int64_t int_imm = 0;
	float float_imm = 0;
	std::string op = "";// detail type, reg, mem, pc, imm. 
	uint64_t actual_size = 0; // occupy bytes not consider rep times (original default value size). 
	//    std::string pre_rec4;//4£¬values in reg or mem, for pc or imm, this should be empty. 
	std::string hexdata = "";
	byte* value = NULL;// length should be same as actual_size. 

	std::vector<expanded_opnd_info*> expanded_infos;

	opnd() {

	}

	opnd(opnd* opd)
	{
		this->optype = opd->optype;
		this->detail_ot = opd->detail_ot;
		this->opnd_rep_time_direction = opd->opnd_rep_time_direction;
		this->reg_id_mem_addr = opd->reg_id_mem_addr;
		this->pc_module_name = opd->pc_module_name;
		this->pc_offset = opd->pc_offset;
		this->int_imm = opd->int_imm;
		this->float_imm = opd->float_imm;
		this->op = opd->op;
		this->actual_size = opd->actual_size;
		this->hexdata = opd->hexdata;

		if (actual_size > 0 and opd->value != NULL) {
			byte* cur_value = new byte[actual_size];
			memcpy_s(cur_value, actual_size, opd->value, actual_size);
			this->value = cur_value;
		}

		for (int i = 0; i < opd->expanded_infos.size(); i++)
		{
			expanded_opnd_info* cur_expanded_info = new expanded_opnd_info(opd->expanded_infos.at(i));
			this->expanded_infos.push_back(cur_expanded_info);
		}
	}

	opnd(std::string curline)
	{
		optype = curline[0] - '0';
		int spos = 1;// in all following execution, it must be index of ',' or ':' or ';' or '\n'
		int unit_type = std::stol(trace_read_util::get_substr(curline, ",", spos));
		detail_ot = (opnd_type)unit_type;
		opnd_rep_time_direction = std::stoll(trace_read_util::get_substr(curline, ",", spos));
		std::string reg_id_mem_addr_imm_pc_offset_val_str = trace_read_util::get_substr(curline, ",", spos);
		op = trace_read_util::get_substr(curline, ",", spos);
		switch (detail_ot) {
		case is_no_type:
			// do nothing. 
			y_assert(false, "is_no_type wrong.", __FILE__, __LINE__);
			break;
		case is_reg:
			y_assert(op == "reg", "is_reg wrong.", __FILE__, __LINE__);
			reg_id_mem_addr = std::stoull(reg_id_mem_addr_imm_pc_offset_val_str);
			break;
		case is_mem:
			y_assert(op == "mem", "is_mem wrong.", __FILE__, __LINE__);
			reg_id_mem_addr = std::stoull(reg_id_mem_addr_imm_pc_offset_val_str);
			break;
		case is_pc:
			pc_offset = std::stoull(reg_id_mem_addr_imm_pc_offset_val_str);
			break;
		case is_immed_int:
			y_assert(op == "immed_int", "is_immed_int wrong.", __FILE__, __LINE__);
			int_imm = std::stoll(reg_id_mem_addr_imm_pc_offset_val_str);
			break;
		case is_immed_float:
			y_assert(op == "immed_float", "is_immed_float wrong.", __FILE__, __LINE__);
			float_imm = std::stof(reg_id_mem_addr_imm_pc_offset_val_str);
			break;
		}

		if (detail_ot == is_pc) {
			pc_module_name = trace_read_util::get_substr(curline, ",", spos);
		}

		if (detail_ot == is_reg || detail_ot == is_mem) {
			//            size = stoi(trace_read_util::get_substr(curline, ",", spos));
			actual_size = std::stoll(trace_read_util::get_substr(curline, ",", spos));
			hexdata = trace_read_util::get_substr(curline, ";", spos);
			value = new byte[actual_size];
			trace_read_util::hex_string_to_byte_array(hexdata, value, actual_size);
		}
		else {
			actual_size = stoi(trace_read_util::get_substr(curline, ";", spos));
		}
		if (detail_ot == is_immed_int || detail_ot == is_immed_float) {
			// set up value. 
			value = new byte[actual_size];
			if (unit_type == is_immed_int) {
				memcpy_s(value, actual_size, &int_imm, actual_size);
			}
			else if (unit_type == is_immed_float) {
				memcpy_s(value, actual_size, &float_imm, actual_size);
			}
		}
	}

	~opnd()
	{
		delete[] value;
		for (auto it = expanded_infos.begin(); it != expanded_infos.end(); it++) {
			delete* it;
		}
	}
};

class reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr {

public:

	RegUseInMemOrDstMaxRegType type = RegUseInMemOrDstMaxRegType::reg_used_in_mem_ref;
	uint16_t reg_id = 0;
	byte reg_val_size = 0;
	byte* store_reg_val_addr = NULL;

	reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr() {

	}

	reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr(reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* ruim) {
		this->type = ruim->type;
		this->reg_id = ruim->reg_id;
		this->reg_val_size = ruim->reg_val_size;

		byte* cur_srva = new byte[reg_val_size];
		memcpy_s(cur_srva, reg_val_size, ruim->store_reg_val_addr, reg_val_size);
		this->store_reg_val_addr = cur_srva;
	}

	reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr(RegUseInMemOrDstMaxRegType type, uint16_t reg_id, byte reg_val_size, byte* store_reg_val_addr) {
		this->type = type;
		this->reg_id = reg_id;
		this->reg_val_size = reg_val_size;
		this->store_reg_val_addr = store_reg_val_addr;
	}

	~reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr() {

	}

};

class rep_opnd_expanded {

public:
	int trace_type = 0;
	int direction = 0;//1:src,2:dst;
	int belonged_opnd_idx = 0;
	uint64_t expand_mem_addr = 0;
	int size = 0;
	std::string hex_data = "";
	byte* data_addr = NULL;

	rep_opnd_expanded() {

	}

	rep_opnd_expanded(std::string curline) {
		int spos = 1;
		trace_type = curline[0] - '0';
		direction = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		belonged_opnd_idx = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		expand_mem_addr = std::stoull(trace_read_util::get_substr(curline, ",", spos));
		size = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		hex_data = trace_read_util::get_substr(curline, ";", spos);
		data_addr = new byte[size];
		trace_read_util::hex_string_to_byte_array(hex_data, data_addr, size);
	}

	~rep_opnd_expanded() {

	}

};

class slot
{
public:
	trace_unit_type kind = trace_unit_type::is_op_meta;// first type is trace_unit_type::is_op_meta or trace_unit_type::is_high_level_op_type. 
	void* object = NULL;
	size_t index = -1;
	size_t line_idx = -1;

	slot() {}

	slot(slot* s_cpy);

	slot(trace_unit_type kind, void* object, size_t index, size_t line_idx) {
		this->kind = kind;
		this->object = object;
		this->index = index;
		this->line_idx = line_idx;
	}

	~slot() {
	}

};

class instr//record meta info of instruction.
{
public:

	slot* container = NULL;

	std::string module_name = "";// module
	uint64_t offset = 0;// offset to module start
	uint64_t addr = 0;// instr app_pc (maybe different for different runs)
	std::string opname = "";// op
	byte executed = 0;// whether the instr is executed. 
	long long time = 0;// instr run time, begin from 1979
	uint64_t xsp = 0;
	uint64_t instr_type = 0;
	// int eflag;// eflags before run this instr
	// int pred;// predicate of instr
	uint32_t eflags_usage_consider_all = 0;// eflags usage of instr, consider all. 
	int inst_predicate = 0;// eflags usage of instr, consider default (may include conditional execution? not sure.)

	byte* inst_bytes = NULL;// raw byte hex representation, can be directly used in triton. for example, "\x02\x03\x04\x05". 
	int inst_bytes_size = 0;

	std::vector<opnd*> srcs;
	std::vector<opnd*> dsts;

	std::vector<reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr*> reg_use_in_mem_ref_or_dst_reg_max_reg_vect;

	instr() {

	}

	instr(slot* s_ctnr, instr* itr)
	{
		this->container = s_ctnr;

		this->module_name = itr->module_name;
		this->offset = itr->offset;
		this->addr = itr->addr;
		this->opname = itr->opname;
		this->executed = itr->executed;
		this->time = itr->time;
		this->xsp = itr->xsp;
		this->instr_type = itr->instr_type;
		this->eflags_usage_consider_all = itr->eflags_usage_consider_all;
		this->inst_predicate = itr->inst_predicate;
		this->inst_bytes_size = itr->inst_bytes_size;

		byte* cur_inst_bytes = new byte[inst_bytes_size];
		memcpy_s(cur_inst_bytes, inst_bytes_size, itr->inst_bytes, inst_bytes_size);
		this->inst_bytes = cur_inst_bytes;

		for (int i = 0; i < itr->srcs.size(); i++)
		{
			opnd* cur_src = new opnd(itr->srcs.at(i));
			this->srcs.push_back(cur_src);
		}
		for (int j = 0; j < itr->dsts.size(); j++)
		{
			opnd* cur_dst = new opnd(itr->dsts.at(j));
			this->dsts.push_back(cur_dst);
		}
		for (int k = 0; k < itr->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.size(); k++)
		{
			reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* cur_ruim = new reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr(itr->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.at(k));
			this->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.push_back(cur_ruim);
		}
	}

	instr(std::string& curline)
	{
		int spos = 1;// in all following execution, it must be index of ',' or ':' or '\n'
		module_name = trace_read_util::get_substr(curline, ",", spos);
		offset = std::stoull(trace_read_util::get_substr(curline, ",", spos));
		addr = std::stoull(trace_read_util::get_substr(curline, ":", spos));// , nullptr, 16
		opname = trace_read_util::get_substr(curline, ",", spos);
		executed = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		time = std::stoll(trace_read_util::get_substr(curline, ",", spos));
		xsp = std::stoull(trace_read_util::get_substr(curline, ",", spos));
		instr_type = std::stoull(trace_read_util::get_substr(curline, ",", spos));
		y_assert(instr_type < 2, "instr_type wrong.", __FILE__, __LINE__);
		//       eflag = stoi(trace_read_util::get_substr(curline, ",", spos));
		//       pred = stoi(trace_read_util::get_substr(curline, ",", spos));
		eflags_usage_consider_all = std::stoul(trace_read_util::get_substr(curline, ",", spos));
		inst_predicate = std::stoi(trace_read_util::get_substr(curline, ",", spos));

		std::string raw_bytes_str = trace_read_util::get_substr(curline, ";", spos);
		inst_bytes_size = raw_bytes_str.size() / 2;
		inst_bytes = new byte[inst_bytes_size];
		trace_read_util::hex_string_to_byte_array(raw_bytes_str, inst_bytes, inst_bytes_size);

		// debug code
//		if (module_name == "Resolved_ucrtbase.dll_1048577" and offset == 99987) {
//			printf("at debug point!");
//		}

		while (spos > -1 and spos < curline.size() - 2) {
			std::string rtype_str = trace_read_util::get_substr(curline, ",", spos);
			RegUseInMemOrDstMaxRegType rtype = (RegUseInMemOrDstMaxRegType)std::stoul(rtype_str);
			std::string reg_id_str = trace_read_util::get_substr(curline, ",", spos);
			uint16_t reg_id = std::stoul(reg_id_str);
			std::string reg_val_sz_str = trace_read_util::get_substr(curline, ",", spos);
			byte reg_val_sz = std::stoul(reg_val_sz_str);
			std::string reg_val_hex_data_str = trace_read_util::get_substr(curline, ";", spos);
			byte* reg_val_hex_data = new byte[reg_val_sz];
			trace_read_util::hex_string_to_byte_array(reg_val_hex_data_str, reg_val_hex_data, reg_val_sz);

			reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* ruim = new reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr(rtype, reg_id, reg_val_sz, reg_val_hex_data);
			reg_use_in_mem_ref_or_dst_reg_max_reg_vect.push_back(ruim);
		}
	}

	~instr()
	{
		for (opnd* src : srcs) {
			delete src;
		}
		for (opnd* dst : dsts) {
			delete dst;
		}
		for (reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* ruimr : reg_use_in_mem_ref_or_dst_reg_max_reg_vect) {
			delete ruimr;
		}
		//        for (rep_opnd_expanded* roe : vect_rep_expanded) {
		//           delete roe;
		//        }
	}
};

class high_level_op
{
public:

	slot* container = NULL;

	int in_trace_type = 0;// type must be trace_unit_type::is_high_level_op_type.
	int high_op_type = 0;
	byte pre_or_post = 0;// 0 is pre nothing follows; 1 is post follows ':' and 3 elements. 
	uint16_t return_reg_id = 0;// return reg id, should be DR_REG_AL, DR_REG_EAX or DR_REG_RAX.
	std::string hop_name = "";//name of the op. can be read_file, heap_free. 
	byte executed_successful = 0;//whether executed, 1 successful, 0, not
	std::string file_name = "";
	size_t file_position = 0;
	uint64_t addr = 0;
	int num = 0;

	high_level_op() {

	}

	high_level_op(slot* s, high_level_op* hop) {
		this->container = s;

		this->in_trace_type = hop->in_trace_type;
		this->high_op_type = hop->high_op_type;
		this->pre_or_post = hop->pre_or_post;
		this->return_reg_id = hop->return_reg_id;
		this->hop_name = hop->hop_name;
		this->executed_successful = hop->executed_successful;
		this->file_name = hop->file_name;
		this->file_position = hop->file_position;
		this->addr = hop->addr;
		this->num = hop->num;
	}

	high_level_op(std::string curline)
	{
		int spos = 1;// in all following execution, it must be index of ',' or ':' or '\n'
		in_trace_type = curline[0] - '0';
		high_op_type = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		pre_or_post = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		return_reg_id = std::stoi(trace_read_util::get_substr(curline, ",", spos));
		if (pre_or_post == 1)
		{
			hop_name = trace_read_util::get_substr(curline, ":", spos);
			executed_successful = std::stoi(trace_read_util::get_substr(curline, ",", spos));
			if (high_op_type == high_level_op_type::read_file) {
				y_assert(hop_name == "read_file", "high_op name wrong.", __FILE__, __LINE__);
				std::string raw_file_name = trace_read_util::get_substr(curline, ",", spos);
				y_assert(YStringUtil::startsWith(raw_file_name, "\\\\?\\"), "raw_file_name start wrong.", __FILE__, __LINE__);
				file_name = raw_file_name.substr(4);
				YStringUtil::replace_all(file_name, "\\", "/");
//				printf("processed file_name:%s\n", file_name.c_str());
				file_position = std::stoull(trace_read_util::get_substr(curline, ",", spos));
			}
			addr = std::stoull(trace_read_util::get_substr(curline, ",", spos));
			num = std::stoi(trace_read_util::get_substr(curline, ";", spos));
		}
		else {
			hop_name = trace_read_util::get_substr(curline, ";", spos);
		}
	}

	~high_level_op()
	{
	}
};

class trace_print_util {

public:

	static void print_last_instr(std::vector<instr*> vect_instr) {
		instr* it = vect_instr.back();
		std::cout << it->module_name << std::endl;
		std::cout << it->offset << std::endl;
		std::cout << it->addr << std::endl;
		std::cout << it->opname << std::endl;
		std::cout << it->executed << std::endl;
		std::cout << it->time << std::endl;
		std::cout << it->xsp << std::endl;
		std::cout << it->instr_type << std::endl;
		std::cout << it->eflags_usage_consider_all << std::endl;
		std::cout << it->inst_predicate << std::endl;
		//std::cout << "size:" << vect.size() << std::endl;
		//std::cout << "instrv_num:" << instrv_num << std::endl;
		std::cout << std::endl;
	}

	static void print_last_dst_opnd(std::vector<instr*> vect_instr) {
		opnd* od = vect_instr.back()->dsts.back();
		print_opnd(od);
	}

	static void print_last_src_opnd(std::vector<instr*> vect_instr) {
		opnd* od = vect_instr.back()->srcs.back();
		print_opnd(od);
	}

	static void print_opnd(opnd* od) {
		std::cout << "reg_or_mem_or_pc:" << od->reg_id_mem_addr << ";int_imm:" << od->int_imm << ";float_imm:" << od->float_imm << std::endl;
		std::cout << od->op << std::endl;
		std::cout << od->actual_size << std::endl;
		std::cout << od->hexdata << std::endl;
		//std::cout << vect1[instrv_num - 1].srcs[srcv_num - 1]->rec4[15] << std::endl;
		//std::cout << "size:" << vect[instrv_num - 1].srcs.size() << std::endl;
		//std::cout << "srcv_num:" << srcv_num << std::endl;
		std::cout << std::endl;
	}

	static void print_last_hop(std::vector<high_level_op*> vector_high_level_op) {
		high_level_op* hop = vector_high_level_op.back();
		std::cout << hop->in_trace_type << std::endl;
		std::cout << hop->hop_name << std::endl;
		std::cout << hop->pre_or_post << std::endl;

		if (hop->pre_or_post == 1)
		{
			std::cout << hop->executed_successful << std::endl;
			std::cout << hop->addr << std::endl;
			std::cout << hop->num << std::endl;
		}
		std::cout << std::endl;
	}

};

class YTrace {

public:
	std::vector<instr*> vect_instr;
	std::vector<high_level_op*> vect_hop;
	std::vector<slot*> vect;

	YTrace() {
	}

	YTrace(bool use_content, std::string content) {
		if (use_content) {
			char* ptr = (char*)content.c_str();
			initial_from_string(ptr);
		}
		else {
			FileReadContent fri;
			YFileUtil::read_whole_file(content, &fri);
			char* ptr = (char*)fri.addr;
			initial_from_string(ptr);
			// must not delete, because this fri will be de-constructed and the addr and the data will be deleted. 
//			delete[] fri.addr;
		}
	}

	void initial_from_string(char* ptr) {
		char* next_ptr = NULL;

		std::map<instr*, std::vector<rep_opnd_expanded*>*> instr_to_roes;
		std::vector<std::vector<rep_opnd_expanded*>*> roes;

		int line_idx = 0;
		while ((next_ptr = strchr(ptr, '\n')) != NULL)
		{
			line_idx++;
			//printf("line_idx:%d\n", line_idx);
			//if (line_idx == 3991) {
			//	printf("OK\n");
			//}

			//tf >> curline;
			*next_ptr = '\0';
			std::string currline(ptr);

			//			if (line_idx == 1) {
			//				printf("line1:%s\n", currline.c_str());
			//			}

			size_t num = next_ptr - ptr;
			// next round ptr should be next_ptr + 1.
			ptr = next_ptr + 1;
			if (num == 0) {
				continue;
			}
			else {
				y_assert(num > 5, "num should > 5, but wrong.", __FILE__, __LINE__);
			}

			byte raw_tt = currline[0] - '0';
			trace_unit_type tt = (trace_unit_type)raw_tt;
			switch (tt) {
			case trace_unit_type::is_op_meta:
			{
				instr* cur1 = new instr(currline);
				slot* cur1_slot = new slot(trace_unit_type::is_op_meta, cur1, vect.size(), line_idx);
				cur1->container = cur1_slot;

				if (cur1->opname.rfind("rep ", 0) == 0) {
					// found rep. 
					y_assert(roes.size() == 1, "rep start wrong.", __FILE__, __LINE__);
					std::vector<rep_opnd_expanded*>* roe = roes.at(0);
					roes.pop_back();
					instr_to_roes.insert({ cur1, roe });
				}
				else {
					y_assert(roes.size() == 0, "roes.size() must == 0, but wrong.", __FILE__, __LINE__);
				}
				//				if (vect.size() > 0) {
				//					slot* back_s = vect.back();
				//					if (back_s->kind == trace_unit_type::is_expanded_rep_str) {
				//						vect.pop_back();
				//						std::vector<rep_opnd_expanded*>* vect_roe = (std::vector<rep_opnd_expanded*>*)back_s->object;
				//						instr_to_roes.insert({ cur1, vect_roe });
				//					}
				//				}
				vect_instr.push_back(cur1);
				vect.push_back(cur1_slot);
			}
			break;
			case trace_unit_type::is_src:
			{
				opnd* cur2 = new opnd(currline);
				vect_instr.back()->srcs.push_back(cur2);
			}
			break;
			case trace_unit_type::is_dst:
			{
				opnd* cur3 = new opnd(currline);
				vect_instr.back()->dsts.push_back(cur3);
			}
			break;
			case trace_unit_type::is_high_level_op_type:
			{
				high_level_op* cur4 = new high_level_op(currline);
				vect_hop.push_back(cur4);
				slot* cur4_slot = new slot(tt, cur4, vect.size(), line_idx);
				cur4->container = cur4_slot;
				vect.push_back(cur4_slot);
			}
			break;
			case trace_unit_type::is_expanded_rep_str:
			{
				bool insert_ele = false;
				//				if (vect.size() == 0) {
				//					insert_ele = true;
				//				}
				//				else {
				//					slot* s = vect.back();
				//					if (s->kind != trace_unit_type::is_expanded_rep_str) {
				//						insert_ele = true;
				//					}
				//				}
				if (roes.size() == 0) {
					insert_ele = true;
				}
				else {
					y_assert(roes.size() == 1, "roes.size() must == 1, but wrong.", __FILE__, __LINE__);
				}
				if (insert_ele) {
					std::vector<rep_opnd_expanded*>* vect_roe = new std::vector<rep_opnd_expanded*>();
					roes.push_back(vect_roe);
					//					slot* cur5_slot = new slot(tt, vect_roe, vect.size(), line_idx);
					//					vect.push_back(cur5_slot);
				}
				//				slot* s = vect.back();
				//				assert(s->kind == trace_unit_type::is_expanded_rep_str);
				//				std::vector<rep_opnd_expanded*>* vect_roe = (std::vector<rep_opnd_expanded*>*)s->object;
				std::vector<rep_opnd_expanded*>* vect_roe = roes.back();
				rep_opnd_expanded* roe = new rep_opnd_expanded(currline);
				vect_roe->push_back(roe);
			}
			break;
			default:
				y_assert(false, "unseen trace_unit_type.", __FILE__, __LINE__);
				break;
			}
		}

		// handle instr_to_aoes to put expanded rep data into opnd. 
		for (auto it = instr_to_roes.begin(); it != instr_to_roes.end(); it++) {
			instr* inst = it->first;
			std::vector<rep_opnd_expanded*>* vect_roes = it->second;
			for (auto vect_roe = vect_roes->begin(); vect_roe != vect_roes->end(); vect_roe++) {
				rep_opnd_expanded* roe = *vect_roe;
				//                roe->belonged_opnd_idx;
				//                roe->direction;
				//                roe->expand_mem_addr;
				//                roe->data_addr;
				//                roe->size;
				//                roe->hex_data;
				opnd* opd = NULL;
				if (roe->direction == trace_unit_type::is_src) {
					opd = inst->srcs.at(roe->belonged_opnd_idx);
				}
				else if (roe->direction == trace_unit_type::is_dst) {
					opd = inst->dsts.at(roe->belonged_opnd_idx);
				}
				else {
					// do nothing. 
				}
				if (opd != NULL) {
					expanded_opnd_info* eoi = new expanded_opnd_info(roe->expand_mem_addr, roe->size, roe->data_addr);
					opd->expanded_infos.push_back(eoi);
				}
				else {
					y_assert(false, "unseen roe->direction.", __FILE__, __LINE__);
				}
			}
			for (opnd* src : inst->srcs) {
				check_expanded_info_size(src);
			}
			for (opnd* dst : inst->dsts) {
				check_expanded_info_size(dst);
			}
			delete vect_roes;
		}
		instr_to_roes.clear();
	}

	std::string get_instr_info(int i) {
		std::string res;
		if (this->vect.at(i)->kind == trace_unit_type::is_op_meta) {
			instr* inst = (instr*)this->vect.at(i)->object;
			res = inst->opname + "," + std::to_string(inst->executed);
		}
		else if (this->vect.at(i)->kind == trace_unit_type::is_high_level_op_type) {
			high_level_op* hop = (high_level_op*)this->vect.at(i)->object;
			if (hop->pre_or_post == 1) {
				res = hop->hop_name + "," + std::to_string(hop->executed_successful);
			}
		}
		else {
			y_assert(false, "unseen slot kind.", __FILE__, __LINE__);
		}
		return res;
	}
	
	void check_expanded_info_size(opnd* opd) {
		size_t eisize = opd->expanded_infos.size();
		if (eisize > 0) {
			y_assert(eisize == abs(opd->opnd_rep_time_direction), "opd->expanded_infos.size() wrong.", __FILE__, __LINE__);
		}
	}

	~YTrace() {
		// clear all data. 
		for (auto it = vect_instr.begin(); it != vect_instr.end(); it++) {
			delete* it;
		}
		vect_instr.clear();
		//        delete vect_instr;
		for (auto it = vect_hop.begin(); it != vect_hop.end(); it++) {
			delete* it;
		}
		vect_hop.clear();
		//        delete vect_hop;
		vect.clear();
		//        delete vect;
	}

};


bool module_name_should_be_ignored_when_computing_branch(std::string module_name);

bool opnd_value_same(opnd* opd1, opnd* opd2);

bool opnd_value_same(opnd** opd1, int opd1_size, opnd* opd2);



