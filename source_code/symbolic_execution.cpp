#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
// #include <random>
#include <Windows.h>

#include "test_analysis.h"
#include "yyx_common_run.h"
#include "yyx_trace.h"
#include "yyx_trace_taint.h"
#include "symbolic_execution.h"

triton::arch::register_e convert_reg_id_in_trace_to_triton_id(uint16_t reg_id_in_trace);

// std::string folder_put_generated_symbolic_execution_seeds = "C:/HomeSpace/BinarySymbolicOutput";
bool symbolic_execution_write_file = true;

struct read_file_info
{
	uint64_t initaddr;
	int addrnum;

	std::string file_name;
	size_t file_pos_when_read;
};

// using namespace triton;
// using namespace triton::arch;
// using namespace triton::arch::x86;
// using namespace triton::engines::symbolic;

void TaintSymbolicMain(const std::string& drrun_path, const std::string& yyx_taint_dll_path,
	const std::string& exe_path, const std::string& folder_put_instr_val_trace,
	const std::string& folder_put_generated_seeds,
	const std::string& folder_put_temp_generated_seeds)
{
	std::set<std::string> interesting_seed_sigs;
	std::map<std::string, int> mutated_seed_count;

	for (const auto& entry : std::filesystem::directory_iterator(folder_put_generated_seeds)) {
		std::string path_ss = entry.path().string();
		YStringUtil::replace_all(path_ss, "\\", "/");
		mutated_seed_count.insert({ path_ss, 0 });
	}

	int min_num = 0, max_num = 1000;

	//std::random_device seed;
	//std::ranlux48 engine(seed());
	//std::uniform_int_distribution<> distrib(min_num, max_num);

	int iturn = 0;
	int max_turn = 1000;
	while (iturn < max_turn) {
		std::pair<std::string, int> min = *std::min_element(mutated_seed_count.begin(),
			mutated_seed_count.end(), compare_value_in_map<std::string, int>());
		mutated_seed_count.insert_or_assign(min.first, min.second + 1);
		if (min.second == 0) {
			FileReadContent* ori_seed = new FileReadContent();
			YFileUtil::read_whole_file(min.first, ori_seed);

			YEssenTaintedTrace* one_yett = RunSeedAndHandleInteresting(drrun_path, yyx_taint_dll_path, min.first,
				exe_path, folder_put_instr_val_trace, folder_put_generated_seeds,
				"existing seed prepare-run to begin mutation.", interesting_seed_sigs, mutated_seed_count);

			OneTraceSymbolicExecution(one_yett, folder_put_temp_generated_seeds);

			RunEachFileCollectUniqueBitmap(drrun_path, 
				yyx_taint_dll_path, exe_path,
				folder_put_instr_val_trace, 
				folder_put_generated_seeds, 
				folder_put_temp_generated_seeds,
				"run generated seed.",
				interesting_seed_sigs, mutated_seed_count);
		}
		iturn++;
	}
}

// the data is not huge, so a stack allocated data is enough. 
static void generate_test_data(std::vector<slot*>& vect) {

	high_level_op* hop = new high_level_op();
	hop->hop_name = "read_file";
	hop->addr = 20068;
	hop->num = 2;
	slot* slot_hop = new slot;
	slot_hop->kind = trace_unit_type::is_high_level_op_type;
	slot_hop->object = hop;
	vect.push_back(slot_hop);

	/* mov ecx, [eax] */
	instr* cur1 = new instr();
	cur1->module_name = "Resolved_TestReadFile.exe_45057";
	cur1->offset = 337616;
	cur1->addr = 0x00007FFD349E26D0;
	cur1->opname = "mov";
	cur1->executed = 0;
	cur1->time = 1930026520891;
	cur1->xsp = 518;
	cur1->instr_type = 0;
	cur1->eflags_usage_consider_all = 0;
	cur1->inst_predicate = 0;
	byte ib0[3];
	ib0[0] = '\x67';
	ib0[1] = '\x8B';
	ib0[2] = '\x08';
	cur1->inst_bytes = ib0;
	cur1->inst_bytes_size = 3;

	opnd* cur2 = new opnd();
	cur2->optype = 1;
	cur2->reg_id_mem_addr = 20068;
	cur2->op = "mem";
	cur2->actual_size = 1;
	cur2->hexdata = "06";
	cur2->value = new byte[cur2->actual_size];
	trace_read_util::hex_string_to_byte_array(cur2->hexdata, cur2->value, cur2->actual_size);

	reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr* ruim = new reg_use_in_mem_ref_or_dst_reg_max_reg_for_an_instr();
	ruim->reg_id = 17;
	ruim->reg_val_size = 2;
	byte* reg_val_hex_data = new byte[ruim->reg_val_size];
	std::string hexstr = "644e";
	trace_read_util::hex_string_to_byte_array(hexstr, reg_val_hex_data, ruim->reg_val_size);
	ruim->store_reg_val_addr = reg_val_hex_data;
	cur1->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.push_back(ruim);

	opnd* cur3 = new opnd();
	cur3->optype = 2;
	cur3->reg_id_mem_addr = 18;
	cur3->op = "reg";
	//cur3->actual_size = 2;
	//cur3->hexdata = "07D0";
	//cur3->value = new byte[cur3->actual_size];
	//trace_read_util::hex_string_to_byte_array(cur3->hexdata, cur3->value, cur3->actual_size);

	slot* cur1_slot = new slot();
	cur1_slot->kind = trace_unit_type::is_op_meta;
	cur1_slot->object = cur1;
	//cur1_slot->index = vect->size();
	vect.push_back(cur1_slot);
//	vect_instr.push_back(cur1);
	cur1->srcs.push_back(cur2);
	cur1->dsts.push_back(cur3);

	/* cmp ecx, 6 */
	opnd* cur5 = new opnd();
	cur5->optype = 1;
	cur5->detail_ot = is_immed_int;
	cur5->int_imm = 6;
	cur5->op = "immed_int";
	//cur5->actual_size = 4;
	//cur5->hexdata = "11061d10";
	//cur5->value = new byte[cur3->actual_size];
	//trace_read_util::hex_string_to_byte_array(cur5->hexdata, cur5->value, cur5->actual_size);

	opnd* cur6 = new opnd();
	cur6->optype = 2;
	//cur6->reg_id_mem_addr_pc_addr_imm = 18;
	cur6->op = "reg";
	//cur6->actual_size = 2;
	//cur6->hexdata = "05DC";
	//cur6->value = new byte[cur3->actual_size];
	//trace_read_util::hex_string_to_byte_array(cur6->hexdata, cur6->value, cur6->actual_size);

	instr* cur4 = new instr();
	cur4->module_name = "Resolved_TestReadFile.exe_45057";
	cur4->offset = 13250;
	cur4->addr = 0x00007FF6D8A933C2;
	cur4->opname = "cmp";
	cur4->executed = 0;
	cur4->time = 1930026522174;
	cur4->xsp = 514;
	cur4->instr_type = 0;
	cur4->eflags_usage_consider_all = 587776;
	cur4->inst_predicate = 587776;
	byte ib1[3];
	ib1[0] = '\x83';
	ib1[1] = '\xF9';
	ib1[2] = '\x06';
	cur4->inst_bytes = ib1;
	cur4->inst_bytes_size = 3;

	slot* cur4_slot = new slot();
	cur4_slot->kind = trace_unit_type::is_op_meta;
	cur4_slot->object = cur4;
	//cur4_slot->index = vect->size();
	vect.push_back(cur4_slot);
//	vect_instr.push_back(cur4);
	cur4->srcs.push_back(cur5);
	cur4->dsts.push_back(cur6);
	
	/* jne 0x57 */
	opnd* cur8 = new opnd();
	cur8->optype = 1;
	cur8->reg_id_mem_addr = 0x00007FF6D8A92DFC;
	cur8->op = "pc";
	cur8->actual_size = 4;
	cur8->hexdata = "573e1120";
	cur8->value = new byte[cur3->actual_size];
	trace_read_util::hex_string_to_byte_array(cur8->hexdata, cur8->value, cur8->actual_size);

	instr* cur7 = new instr();
	cur7->module_name = "Resolved_TestReadFile.exe_45057";
	cur7->offset = 658368;
	cur7->addr = 0x00007FFD34A30BC0;
	cur7->opname = "jne";
	cur7->executed = 0;
	cur7->time = 1930026521144;
	cur7->xsp = 582;
	cur7->instr_type = 0;
	cur7->eflags_usage_consider_all = 0;
	cur7->inst_predicate = 0;
	byte ib2[6]{0};
	ib2[0] = '\x0F';
	ib2[1] = '\x85';
	ib2[2] = '\x51';
	ib2[3] = '\x00';
	ib2[4] = '\x00';
	ib2[5] = '\x00';
	cur7->inst_bytes = ib2;
	cur7->inst_bytes_size = 6;

	slot* cur7_slot = new slot();
	cur7_slot->kind = trace_unit_type::is_op_meta;
	cur7_slot->object = cur7;
	//cur7_slot->index = vect->size();
	vect.push_back(cur7_slot);
//	vect_instr.push_back(cur7);
	cur7->srcs.push_back(cur8);

//	std::cout << "it's running..." << std::endl;
}

// this function also considers dst max reg, because dst max regs are stored in reg_use_in_mem_ref_or_dst_reg_max_reg_vect, we also set the dst max reg if the triton dst max reg value is not equal to trace dst max reg value. 
// std::map<triton::uint16, int>* regset, 
static void set_and_confirm_dr_reg_value(instr* instrp, InstrTaintInfo* instr_taint_info, triton::Context* ctx, triton::uint16 sj_dr_reg_id, size_t actual_size, byte* value) {
	triton::arch::register_e triton_reg_id = convert_reg_id_in_trace_to_triton_id(sj_dr_reg_id);
	const triton::arch::Register& reg = ctx->getRegister(triton_reg_id);
	
//	auto it = regset->find(triton_reg_id);
//	bool already_set_to_1 = false;
//	if (it != regset->end()) {
		// found
//		if (it->second == 1) {
			// has been set. 
//			already_set_to_1 = true;
//		}
//	}
	
	triton::uint512 setvalue{ 0 };
	memcpy_s(&setvalue, actual_size, value, actual_size);

//	printf("sj_reg_id:%lld, triton_reg_id:%lld,setvalue:%llu.\n", sj_reg_id, triton_reg_id, (uint64_t)setvalue);
//	auto val = ctx->getConcreteRegisterValue(ctx->getRegister(triton::arch::ID_REG_X86_RDX));
//	printf("in_set_func before inst rdx value:%llu.\n", (uint64_t)val);

	//if (already_set_to_1) {
	//	triton::uint512 exist_value= ctx->getConcreteRegisterValue(reg);
	//	if (exist_value != setvalue) {
	//		ctx->setConcreteRegisterValue(reg, setvalue);
	//		bool src_sj_is_max_reg_and_tainted = instr_taint_info->tainted_src_and_use_in_mem_max_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_src_and_use_in_mem_max_reg_before_instr.end();
	//		bool src_sj_is_not_max_reg_and_tainted = instr_taint_info->tainted_src_and_use_in_mem_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_src_and_use_in_mem_reg_before_instr.end();
	//		bool dst_sj_is_max_reg_and_tainted = instr_taint_info->tainted_dst_max_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_dst_max_reg_before_instr.end();
	//		bool dst_sj_is_not_max_reg_and_tainted = instr_taint_info->tainted_dst_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_dst_reg_before_instr.end();
	//		if (src_sj_is_max_reg_and_tainted || src_sj_is_not_max_reg_and_tainted || dst_sj_is_max_reg_and_tainted || dst_sj_is_not_max_reg_and_tainted) {
	//			// if tainted, must print warning. 
	//			char ebuf[64 * 8];
	//			triton_print_util::print_uint512_to_buffer(exist_value, ebuf, 64 * 8);
	//			char sbuf[64 * 8];
	//			triton_print_util::print_uint512_to_buffer(setvalue, sbuf, 64 * 8);
	//			printf("src_sj_is_max_reg_and_tainted:%d, src_sj_is_not_max_reg_and_tainted:%d, dst_sj_is_max_reg_and_tainted:%d, in trace, dst_sj_is_not_max_reg_and_tainted:%d.\n", src_sj_is_max_reg_and_tainted, src_sj_is_not_max_reg_and_tainted, dst_sj_is_max_reg_and_tainted, dst_sj_is_not_max_reg_and_tainted);
	//			printf("Warning! dr_reg:%d, value:%s in triton, does not equal value:%s in trace, instr_line_idx:%llu.\n", sj_dr_reg_id, ebuf, sbuf, instrp->container->line_idx);
	//		}
	//	}
	//}
	//else {
	//	ctx->setConcreteRegisterValue(reg, setvalue);
	//	regset->insert_or_assign(triton_reg_id, 1);//maybe no need to use the value
	//}

	triton::uint512 exist_value = ctx->getConcreteRegisterValue(reg);
	if (exist_value != setvalue) {
		ctx->setConcreteRegisterValue(reg, setvalue);
		if (ctx->isRegisterSymbolized(reg)) {
			char ebuf[64 * 8];
			TritonPrintUtil::print_uint512_to_buffer(exist_value, ebuf, 64 * 8);
			char sbuf[64 * 8];
			TritonPrintUtil::print_uint512_to_buffer(setvalue, sbuf, 64 * 8);
			printf("Wrong! symbolized dr_reg:%d, value:%s in triton, does not equal value:%s in trace, instr_line_idx:%llu.\n", sj_dr_reg_id, ebuf, sbuf, instrp->container->line_idx);
			std::string temp_info;
			if (instr_taint_info != NULL) {
#if taint_simplified_mode == 1
#else
//				bool src_sj_is_max_reg_and_tainted = instr_taint_info->tainted_src_and_use_in_mem_max_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_src_and_use_in_mem_max_reg_before_instr.end();
//				bool src_sj_is_not_max_reg_and_tainted = instr_taint_info->tainted_src_and_use_in_mem_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_src_and_use_in_mem_reg_before_instr.end();
				bool src_sj_is_not_max_reg_and_tainted = instr_taint_info->tainted_src_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_src_reg_before_instr.end();
				bool dst_sj_is_max_reg_and_tainted = instr_taint_info->tainted_dst_max_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_dst_max_reg_before_instr.end();
//				bool dst_sj_is_not_max_reg_and_tainted = instr_taint_info->tainted_dst_reg_before_instr.find(sj_dr_reg_id) != instr_taint_info->tainted_dst_reg_before_instr.end();
				// "has taint info but src_sj_is_max_reg_and_tainted:" + std::to_string(src_sj_is_max_reg_and_tainted) +  + ",dst_sj_is_not_max_reg_and_tainted:" + std::to_string(dst_sj_is_not_max_reg_and_tainted) 
				temp_info = "has taint info but src_sj_is_not_max_reg_and_tainted:" + std::to_string(src_sj_is_not_max_reg_and_tainted) + ",dst_sj_is_max_reg_and_tainted:" + std::to_string(dst_sj_is_max_reg_and_tainted) + ".\n";
#endif
			}
			else {
				temp_info = "has no taint info";
			}
			if (not temp_info.empty()) {
				printf("Wrong! symbolized dr_reg:%d, instr_line_idx:%llu, %s.\n", sj_dr_reg_id, instrp->container->line_idx, temp_info.c_str());
				y_assert(false, "temp_info must empty", __FILE__, __LINE__);
			}
		}
	}
	else {
		// do nothing. 
	}

//	auto val2 = ctx->getConcreteRegisterValue(ctx->getRegister(triton::arch::ID_REG_X86_RDX));
//	printf("in_set_func after inst rdx value:%llu.\n", (uint64_t)val2);
}

// std::map<triton::uint64, int>* memset, 
static void set_and_confirm_dr_mem_value(instr* instrp, InstrTaintInfo* instr_taint_info, triton::Context* ctx, triton::uint64 mem_addr, size_t actual_size, byte* value) {
	//	triton::arch::MemoryAccess mem(mem_addr, actual_size);
	//	triton::uint512 setvalue{ 0 };
	//	memcpy_s(&setvalue, actual_size, value, actual_size);
	//	ctx->setConcreteMemoryValue(mem, setvalue);
	//	std::cout << "setvalue when set :" << setvalue << std::endl;
	for (int k = 0; k < actual_size; k++)
	{
		uint64_t kbyte_addr = mem_addr + k;
		byte kbyte_val = *(value + k);
		//		auto it = memset->find(kbyte_addr);
		//		bool already_set_to_1 = false;
		//		if (it != memset->end()) {
					// found
		//			if (it->second == 1) {
						// has been set. 
		//				already_set_to_1 = true;
		//			}
		//		}
		//		if (instrp->container->line_idx == 116733) {
		//			printf("line 116733,kbyte_addr:%llu,already_set_to_1:%d\n", kbyte_addr, already_set_to_1);
		//		}
		triton::arch::MemoryAccess mem(kbyte_addr, 1);
		//if (already_set_to_1) {
		//	// already set, judge whether consistent with trace. 
		//	auto raw_exist_byte_v = ctx->getConcreteMemoryValue(mem);
		//	byte exist_byte_v = (byte)raw_exist_byte_v;
		//	if (exist_byte_v != kbyte_val)
		//	{
		//		// we must set the mem triton value to trace value
		//		ctx->setConcreteMemoryValue(mem, kbyte_val);
		//		if (instr_taint_info != NULL) {
		//			// if that mem byte is not tainted, it is no matter, just force to update. 
		//			// but is tainted, should print warning. 
		//			MCByteID kmbid(ByteType::mem, kbyte_addr);
		//			if (instr_taint_info->tainted_src_mem_bytes.find(kmbid) != instr_taint_info->tainted_src_mem_bytes.end()) {
		//				printf("Warning! mem addr:%p, value:%d in triton, does not equal value:%d, in trace, instr_line_idx:%llu.\n", reinterpret_cast<void*>(kbyte_addr), exist_byte_v, kbyte_val, instrp->container->line_idx);
		//			}
		//		}
		//	}
		//}
		//else {
		//	ctx->setConcreteMemoryValue(mem, kbyte_val);
		//	memset->insert_or_assign(kbyte_addr, 1);
		//}
		auto raw_exist_byte_v = ctx->getConcreteMemoryValue(mem);
		byte exist_byte_v = (byte)raw_exist_byte_v;
		if (exist_byte_v != kbyte_val) {
			ctx->setConcreteMemoryValue(mem, kbyte_val);
			if (ctx->isMemorySymbolized(mem)) {
				printf("Wrong! symbolized mem addr:%p, value:%d in triton, does not equal value:%d, in trace, instr_line_idx:%llu.\n", reinterpret_cast<void*>(kbyte_addr), exist_byte_v, kbyte_val, instrp->container->line_idx);
				std::string temp_info;
				if (instr_taint_info != NULL) {
					// if that mem byte is not tainted, it is no matter, just force to update. 
					// but is tainted, should print warning. 
#if taint_simplified_mode == 1
#else
					MCByteID kmbid(kbyte_addr);
					if (instr_taint_info->tainted_src_mem_bytes.find(kmbid) != instr_taint_info->tainted_src_mem_bytes.end()) {
						temp_info = "has taint info but is tainted";
					}
#endif
				}
				else {
					temp_info = "has no taint info";
				}
				if (not temp_info.empty()) {
					printf("Wrong! symbolized mem addr:%p, instr_line_idx:%llu, %s.\n", reinterpret_cast<void*>(kbyte_addr), instrp->container->line_idx, temp_info.c_str());
					y_assert(false, "temp_info must empty", __FILE__, __LINE__);
				}
			}
			else {
				// do nothing
			}
		}
		else {
			// do nothing. 
		}
	}
}

void OneTraceSymbolicExecution(YEssenTaintedTrace* yett, const std::string& folder_put_temp_generated_seeds)
{
	printf("==== begin SymbolicExecution.\n");

	ClearFilesInDir(folder_put_temp_generated_seeds);

	// exec_time is used for put a same file prefix for seeds solved by this execution turn. 
	std::string exec_time = YTimeUtil::getCurrTimeString();
	// iterate the vect, when encountering read_file, mark the read content as symbol. 

	// for each instr, put them into triton processing.
	// before inst processing, for each register or memory, set the value if not previously setted. 
	// for each branch, try to solve the path constraint. 

	// summary all solved results and put them into many files. 

	// second phase, set up reg or mem value, execute selected instr according to the taint information. 

	// once set value in eax, value in al, for example, is set indirectly.
	
//	std::map<triton::uint64, int>* memset = new std::map<triton::uint64, int>();
//	std::map<triton::uint16, int>* regset = new std::map<triton::uint16, int>();
//	std::vector<byte>* prevalue = new std::vector<byte>();
	std::map<triton::uint64, int>* symbo = new std::map<triton::uint64, int>();

	//set rfi at once when read file
	//set rela for new variables at once after symbolize

	std::vector<read_file_info>* rfi = new std::vector<read_file_info>();
	std::map<uint64_t, uint64_t>* rela = new std::map<uint64_t, uint64_t>();//key is new variable id value is current rfi->size()-1 after symbolize memory, rela rela is var and rfi' last index

	//compute var's offset in input file a follows:
	//except last read file, sum all before read_file_info's hop->num = previously accumulated read file offset
	//previously accumulated read file offset + curr_var's origin address - last read file's init_addr = var's final offset in input file. 

	triton::Context* ctx = new triton::Context();
	ctx->setArchitecture(triton::arch::ARCH_X86_64);
	
	//read the bin file
//	std::string input_bin_path = "D:/C++projects/final_trace_taint/YTraceTaint/test_read_and_write_file";
	//std::string result_path = "D:/C++projects/final_trace_taint/YTraceTaint/test_result";
	//CopyFile();
//	std::fstream bin(input_bin_path, std::ios::in | std::ios::binary);
//	byte item;
//	if (!bin)
//	{
//		std::cout << "Oops, I can't open the bin file" << std::endl;
//	}
//	while (!bin.eof())
//	{
//		bin >> item;
//		prevalue->push_back(item);
//	}
//	bin.close();
	int solved_branches = 0;

//	printf("yett->tained_slots.size():%lld.\n", yett->tained_slots.size());
	printf("Tainted for Symbolic Execution instruction num:%llu.\n", yett->tained_slots.size());
	for (int i = 0; i < yett->tained_slots.size(); i++)
	{
//		printf("loop i:%lld.\n", i);

		SlicedSlot& ss = yett->tained_slots.at(i);
		slot* s = ss.s;
		if (s->kind == trace_unit_type::is_high_level_op_type) {
			high_level_op* hop = (high_level_op*)s->object;

			if (hop->hop_name == "read_file")
			{
				read_file_info cur{ hop->addr, hop->num, hop->file_name, hop->file_position };
				rfi->push_back(cur);
				for (int j = 0; j < hop->num; j++)
				{
					uint64_t tainted_addr = hop->addr + j;
					symbo->insert_or_assign(tainted_addr, 0);
					//std::cout << "address that need to be symbolized :" << (uint64)hop->addr + j << std::endl;
				}
			}
		}
		else if (s->kind == trace_unit_type::is_op_meta) {
			instr* instrp = (instr*)s->object;
			
			triton::arch::Instruction inst;
			inst.setOpcode(instrp->inst_bytes, instrp->inst_bytes_size);
			inst.setAddress(instrp->addr);
			
			ctx->disassembly(inst);
			
//			printf("instruction is branch: %d.\n", inst.isBranch());

//			bool ctn = true;
			bool module_should_ignore_for_branch = module_name_should_be_ignored_when_computing_branch(instrp->module_name);
//			if (inst.isBranch()) {
//				if (module_should_ignore_for_branch) {
//					ctn = false;
//				}
//			}
//			ctn = true;

			std::string inst_dis_str = inst.getDisassembly();//bug in Debug mode, well in Release
//			printf("module_name:%s, module_branch_ignore:%d, processed inst:%s, in original file line number:%lld.\n",// ctn:%d, 
//				instrp->module_name.c_str(), module_should_ignore_for_branch, inst_dis_str.c_str(), s->line_idx);// ctn, 

//			if (ctn) {
			size_t sliced_index = yett->get_sliced_index_from_origin_index(s->index);
			InstrTaintInfo* instr_taint_info = yett->yet->each_instr_taint_info.at(sliced_index);

			//reg_use_in_mem_ref_vect,set value in these regs
			//instrp->reg_use_in_mem_ref_vect.at(j)->store_reg_val_addr_in_large_buffer, pointer to address in eax  e.g. [eax+4]
//			if (s->line_idx == 99632) {
//				printf("trace line 99632, reg_use_in_mem number:%lld.\n", instrp->reg_use_in_mem_ref_vect.size());
//			}
			for (int j = 0; j < instrp->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.size(); j++)
			{
				auto rumj = instrp->reg_use_in_mem_ref_or_dst_reg_max_reg_vect.at(j);
				set_and_confirm_dr_reg_value(instrp, instr_taint_info, ctx, // regset, 
					rumj->reg_id, rumj->reg_val_size, rumj->store_reg_val_addr);
			}
			//set mem and reg in srcs before process inst
			for (int j = 0; j < instrp->srcs.size(); j++)
			{
				opnd* sj = instrp->srcs.at(j);
				if (sj->detail_ot == opnd_type::is_reg) {
					set_and_confirm_dr_reg_value(instrp, instr_taint_info, ctx, // regset, 
						sj->reg_id_mem_addr, sj->actual_size, sj->value);
				}
				else if (sj->detail_ot == opnd_type::is_mem)
				{
					set_and_confirm_dr_mem_value(instrp, instr_taint_info, ctx, sj->reg_id_mem_addr, sj->actual_size, sj->value); // memset, 
				}
			}

			const auto& vb = ctx->getSymbolicVariables();
			size_t before_sv_sz = vb.size();
			//symbolize memory
			for (int j = 0; j < instrp->srcs.size(); j++)
			{
				auto isj = instrp->srcs.at(j);
				if (isj->detail_ot == opnd_type::is_mem) {
					//					if (s->line_idx == 100452) {
					//						std::string symbo_str = YPrintUtil::print_to_string<triton::uint64, int>(symbo);
					//						printf("pre_line:%llu,src mem size:%lld,symbo detail:%s.\n", isj->actual_size, s->line_idx, symbo_str.c_str());
					//					}

					for (int k = 0; k < isj->actual_size; k++) {
						//						std::cout << instrp->srcs.at(j)->reg_id_mem_addr_pc_addr + k << std::endl;
						uint64_t mem_addr = isj->reg_id_mem_addr + k;
						auto it = symbo->find(mem_addr);
						if (it != symbo->end()) {
							// found.
							if (it->second == 0) {
								ctx->symbolizeMemory(mem_addr, 1);
								//	printf("symbolized:%p successfully\n", reinterpret_cast<void*>(mem_addr));
								symbo->insert_or_assign(mem_addr, 1);
							}
						}
					}

					// debug code.
//					std::string post_symbo_str = YPrintUtil::print_to_string<triton::uint64, int>(symbo);
//					printf("post_line:%llu,src mem size:%lld,symbo detail:%s.\n", s->line_idx, isj->actual_size, post_symbo_str.c_str());
				}
			}
			const auto& after_sv = ctx->getSymbolicVariables();
			auto bss_it = after_sv.find(before_sv_sz);
			for (auto& it = bss_it; it != after_sv.end(); it++) {
				rela->insert_or_assign(it->first, rfi->size() - 1);
			}
			//			for (auto it = va.begin(); it != va.end(); it++)
			//			{
			//				if (it->first > size1 - 1)
			//				{
			//					rela->insert_or_assign(it->first, rfi->size() - 1);
			//				}
			//			}

			//			auto val = ctx->getConcreteRegisterValue(ctx->getRegister(triton::arch::ID_REG_X86_RDX));
			//			printf("before inst rdx value:%llu.\n", (uint64_t)val);

			auto ctx_prev_pred = ctx->getPathPredicate();

			ctx->buildSemantics(inst);

			//if (s->line_idx == 100455) {
			//	bool mem_symbolized_2318185266384 = ctx->isMemorySymbolized(2318185266384);
			//	bool mem_symbolized_2318185266385 = ctx->isMemorySymbolized(2318185266385);
			//	bool mem_symbolized_2318185266386 = ctx->isMemorySymbolized(2318185266386);
			//	bool mem_symbolized_2318185266387 = ctx->isMemorySymbolized(2318185266387);
			//	std::cout << "after execute line 100455" << std::endl;
			//	std::cout << "mem_symbolized_2318185266384:" << mem_symbolized_2318185266384
			//		<< ",mem_symbolized_2318185266385:" << mem_symbolized_2318185266385
			//		<< ",mem_symbolized_2318185266386:" << mem_symbolized_2318185266386
			//		<< ",mem_symbolized_2318185266387:" << mem_symbolized_2318185266387
			//		<< std::endl;
			//}
			//if (s->line_idx == 116733) {
			//	bool mem_symbolized_2318185266384 = ctx->isMemorySymbolized(2318185266384);
			//	bool mem_symbolized_2318185266385 = ctx->isMemorySymbolized(2318185266385);
			//	bool mem_symbolized_2318185266386 = ctx->isMemorySymbolized(2318185266386);
			//	bool mem_symbolized_2318185266387 = ctx->isMemorySymbolized(2318185266387);
			//	std::cout << "after execute line 116733" << std::endl;
			//	std::cout << "mem_symbolized_2318185266384:" << mem_symbolized_2318185266384
			//		<< ",mem_symbolized_2318185266385:" << mem_symbolized_2318185266385
			//		<< ",mem_symbolized_2318185266386:" << mem_symbolized_2318185266386
			//		<< ",mem_symbolized_2318185266387:" << mem_symbolized_2318185266387
			//		<< std::endl;
			//}
			//if (s->line_idx == 116747) {
			//	bool mem_symbolized_369213504832 = ctx->isMemorySymbolized(369213504832);
			//	bool mem_symbolized_369213504833 = ctx->isMemorySymbolized(369213504833);
			//	bool mem_symbolized_369213504834 = ctx->isMemorySymbolized(369213504834);
			//	bool mem_symbolized_369213504835 = ctx->isMemorySymbolized(369213504835);
			//	std::cout << "after execute line 116747" << std::endl;
			//	std::cout << "mem_symbolized_369213504832:" << mem_symbolized_369213504832
			//		<< ",mem_symbolized_369213504833:" << mem_symbolized_369213504833
			//		<< ",mem_symbolized_369213504834:" << mem_symbolized_369213504834
			//		<< ",mem_symbolized_369213504835:" << mem_symbolized_369213504835
			//		<< std::endl;
			//}
			//if (s->line_idx == 130817) {
			//	triton::uint512 tuv = ctx->getConcreteRegisterValue(ctx->registers.x86_ecx);
			//	char pu_buffer[512]{0};
			//	triton_print_util::print_uint512_to_buffer(tuv, pu_buffer, 512);
			//	bool ecx_sd = ctx->isRegisterSymbolized(ctx->registers.x86_ecx);
			//	auto ecx_expr = ctx->getSymbolicRegister(ctx->registers.x86_ecx);
			//	std::cout << "after execute line 130817, ecx_symbolized:" << ecx_sd << ",ecx_expr:" << ecx_expr 
			//		<< ",ecx_value:" << pu_buffer << std::endl;
			//	bool mem_symbolized_2318185266384 = ctx->isMemorySymbolized(2318185266384L);
			//	bool mem_symbolized_2318185266385 = ctx->isMemorySymbolized(2318185266385L);
			//	bool mem_symbolized_2318185266386 = ctx->isMemorySymbolized(2318185266386L);
			//	bool mem_symbolized_2318185266387 = ctx->isMemorySymbolized(2318185266387L);
			//	std::cout << "mem_symbolized_2318185266384:" << mem_symbolized_2318185266384 
			//		<< ",mem_symbolized_2318185266385:" << mem_symbolized_2318185266385
			//		<< ",mem_symbolized_2318185266386:" << mem_symbolized_2318185266386 
			//		<< ",mem_symbolized_2318185266387:" << mem_symbolized_2318185266387
			//		<< std::endl;
			//}

			if (inst.isBranch()) {
				//				std::string fname = instrp->module_name + std::to_string(instrp->offset) + '_';
				if (ctx->getPathConstraints().size() == 0) {
					printf("inst isBranch but no constraints are here.\n");
					//					std::cout << "nothing's here." << std::endl;
				}
				else {
					auto& branches = ctx->getPathConstraints().back().getBranchConstraints();
					//					for (int j = 0; j < ctx->getPathConstraints().at(0).getBranchConstraints().size(); j++) {
					int b_idx = -1;
					for (auto& branch : branches) {
						b_idx++;
						//						const std::tuple<bool, triton::uint64, triton::uint64, triton::ast::SharedAbstractNode>& constr = ctx->getPathConstraints().at(0).getBranchConstraints().at(j);
						//						std::cout << unroll(std::get<3>(constr)) << std::endl;
						bool istaken = std::get<0>(branch);
//						printf("branch:%d, taken:%d;", b_idx, istaken);
						if (not istaken) {
							//							char cursuffix = j + '1';
							//							fname = fname + cursuffix;
							//							std::fstream outf(fname, std::ios::binary | std::ios::out | std::ios::in);
														// solve constraint. 
							//							auto model = ctx->getModel(unroll(std::get<3>(branch)));
							auto to_solve_constraint = ctx->getAstContext()->land(unroll(ctx_prev_pred), unroll(std::get<3>(branch)));
//							auto to_solve_constraint = unroll(std::get<3>(branch));
							auto model = ctx->getModel(to_solve_constraint);

							// get solved result. 
							std::map<std::string, FileReadContent*> involve_solved_read_content;

							for (auto it = model.begin(); it != model.end(); it++) {
								auto id = it->first;
								auto& sm = it->second;
								auto value = it->second.getValue();
								//								int accumuaddr = 0;
								//								for (int k = 0; k < rfi->size() - 1; k++)
								//								{
								//									accumuaddr += rfi->at(k).addrnum;
								//								}
								auto rela_it = rela->find(id);
								y_assert(rela_it != rela->end(), "rela_it != rela->end()", __FILE__, __LINE__);
								auto rfi_idx = rela_it->second;
								read_file_info& rfi_needed = rfi->at(rfi_idx);
								size_t file_rel_addr = rfi_needed.file_pos_when_read + sm.getVariable()->getOrigin() - rfi_needed.initaddr;

								FileReadContent* needed_frc = NULL;
								auto arc_it = involve_solved_read_content.find(rfi_needed.file_name);
								if (arc_it == involve_solved_read_content.end()) {
									needed_frc = new FileReadContent();
									YFileUtil::read_whole_file(rfi_needed.file_name, needed_frc);
									involve_solved_read_content.insert({ rfi_needed.file_name, needed_frc });
								}
								else {
									needed_frc = arc_it->second;
								}
								*(needed_frc->addr + file_rel_addr) = (triton::uint8)value;
							}

							solved_branches++;

							// write to file. 
							if (symbolic_execution_write_file and involve_solved_read_content.size() > 0) {
								for (auto arc_it = involve_solved_read_content.begin(); arc_it != involve_solved_read_content.end(); arc_it++) {
									const std::string& path = arc_it->first;
									FileReadContent* wfrc = arc_it->second;
									std::string fname = YStringUtil::getContentAfterLastAppearOfSpecified(path, "/");
									std::string new_fname = exec_time + "_" + std::to_string(solved_branches) + "_" + fname;
									std::string new_fname_full_path = folder_put_temp_generated_seeds + "/" + new_fname;
									YFileUtil::write_whole_file(new_fname_full_path, wfrc);
									delete wfrc;
								}
							}

							involve_solved_read_content.clear();

							if (model.size() > 0) {
								printf("solved constraints! solved variable number:%lld.\n", model.size());
							}
							//							for (int k = 0; k < prevalue->size(); k++)
							//							{
							//								outf << (*prevalue)[k];
							//							}
														//outf.seekp(k,std::ios::beg);
														//outf.write((*prevalue)[k],1);
							//							outf.close();
						}
//						printf("\n");
					}
				}
			}
//			}
		}
		else {
			y_assert(false, "slot kind wrong.", __FILE__, __LINE__);
		}
	}
}


triton::arch::register_e convert_reg_id_in_trace_to_triton_id(uint16_t reg_id_in_trace) {
	triton::arch::register_e triton_reg = triton::arch::ID_REG_INVALID;
	switch (reg_id_in_trace) {
	case DR_REG_RAX:
		triton_reg = triton::arch::ID_REG_X86_RAX;
		break;
	case DR_REG_RCX:
		triton_reg = triton::arch::ID_REG_X86_RCX;
		break;
	case DR_REG_RDX:
		triton_reg = triton::arch::ID_REG_X86_RDX;
		break;
	case DR_REG_RBX:
		triton_reg = triton::arch::ID_REG_X86_RBX;
		break;
	case DR_REG_RSP:
		triton_reg = triton::arch::ID_REG_X86_RSP;
		break;
	case DR_REG_RBP:
		triton_reg = triton::arch::ID_REG_X86_RBP;
		break;
	case DR_REG_RSI:
		triton_reg = triton::arch::ID_REG_X86_RSI;
		break;
	case DR_REG_RDI:
		triton_reg = triton::arch::ID_REG_X86_RDI;
		break;
	case DR_REG_R8:
		triton_reg = triton::arch::ID_REG_X86_R8;
		break;
	case DR_REG_R9:
		triton_reg = triton::arch::ID_REG_X86_R9;
		break;
	case DR_REG_R10:
		triton_reg = triton::arch::ID_REG_X86_R10;
		break;
	case DR_REG_R11:
		triton_reg = triton::arch::ID_REG_X86_R11;
		break;
	case DR_REG_R12:
		triton_reg = triton::arch::ID_REG_X86_R12;
		break;
	case DR_REG_R13:
		triton_reg = triton::arch::ID_REG_X86_R13;
		break;
	case DR_REG_R14:
		triton_reg = triton::arch::ID_REG_X86_R14;
		break;
	case DR_REG_R15:
		triton_reg = triton::arch::ID_REG_X86_R15;
		break;
	case DR_REG_EAX:
		triton_reg = triton::arch::ID_REG_X86_EAX;
		break;
	case DR_REG_ECX:
		triton_reg = triton::arch::ID_REG_X86_ECX;
		break;
	case DR_REG_EDX:
		triton_reg = triton::arch::ID_REG_X86_EDX;
		break;
	case DR_REG_EBX:
		triton_reg = triton::arch::ID_REG_X86_EBX;
		break;
	case DR_REG_ESP:
		triton_reg = triton::arch::ID_REG_X86_ESP;
		break;
	case DR_REG_EBP:
		triton_reg = triton::arch::ID_REG_X86_EBP;
		break;
	case DR_REG_ESI:
		triton_reg = triton::arch::ID_REG_X86_ESI;
		break;
	case DR_REG_EDI:
		triton_reg = triton::arch::ID_REG_X86_EDI;
		break;
	case DR_REG_R8D:
		triton_reg = triton::arch::ID_REG_X86_R8D;
		break;
	case DR_REG_R9D:
		triton_reg = triton::arch::ID_REG_X86_R9D;
		break;
	case DR_REG_R10D:
		triton_reg = triton::arch::ID_REG_X86_R10D;
		break;
	case DR_REG_R11D:
		triton_reg = triton::arch::ID_REG_X86_R11D;
		break;
	case DR_REG_R12D:
		triton_reg = triton::arch::ID_REG_X86_R12D;
		break;
	case DR_REG_R13D:
		triton_reg = triton::arch::ID_REG_X86_R13D;
		break;
	case DR_REG_R14D:
		triton_reg = triton::arch::ID_REG_X86_R14D;
		break;
	case DR_REG_R15D:
		triton_reg = triton::arch::ID_REG_X86_R15D;
		break;
	case DR_REG_AX:
		triton_reg = triton::arch::ID_REG_X86_AX;
		break;
	case DR_REG_CX:
		triton_reg = triton::arch::ID_REG_X86_CX;
		break;
	case DR_REG_DX:
		triton_reg = triton::arch::ID_REG_X86_DX;
		break;
	case DR_REG_BX:
		triton_reg = triton::arch::ID_REG_X86_BX;
		break;
	case DR_REG_SP:
		triton_reg = triton::arch::ID_REG_X86_SP;
		break;
	case DR_REG_BP:
		triton_reg = triton::arch::ID_REG_X86_BP;
		break;
	case DR_REG_SI:
		triton_reg = triton::arch::ID_REG_X86_SI;
		break;
	case DR_REG_DI:
		triton_reg = triton::arch::ID_REG_X86_DI;
		break;
	case DR_REG_R8W:
		triton_reg = triton::arch::ID_REG_X86_R8W;
		break;
	case DR_REG_R9W:
		triton_reg = triton::arch::ID_REG_X86_R9W;
		break;
	case DR_REG_R10W:
		triton_reg = triton::arch::ID_REG_X86_R10W;
		break;
	case DR_REG_R11W:
		triton_reg = triton::arch::ID_REG_X86_R11W;
		break;
	case DR_REG_R12W:
		triton_reg = triton::arch::ID_REG_X86_R12W;
		break;
	case DR_REG_R13W:
		triton_reg = triton::arch::ID_REG_X86_R13W;
		break;
	case DR_REG_R14W:
		triton_reg = triton::arch::ID_REG_X86_R14W;
		break;
	case DR_REG_R15W:
		triton_reg = triton::arch::ID_REG_X86_R15W;
		break;
	case DR_REG_AL:
		triton_reg = triton::arch::ID_REG_X86_AL;
		break;
	case DR_REG_CL:
		triton_reg = triton::arch::ID_REG_X86_CL;
		break;
	case DR_REG_DL:
		triton_reg = triton::arch::ID_REG_X86_DL;
		break;
	case DR_REG_BL:
		triton_reg = triton::arch::ID_REG_X86_BL;
		break;
	case DR_REG_AH:
		triton_reg = triton::arch::ID_REG_X86_AH;
		break;
	case DR_REG_CH:
		triton_reg = triton::arch::ID_REG_X86_CH;
		break;
	case DR_REG_DH:
		triton_reg = triton::arch::ID_REG_X86_DH;
		break;
	case DR_REG_BH:
		triton_reg = triton::arch::ID_REG_X86_BH;
		break;
	case DR_REG_R8L:
		triton_reg = triton::arch::ID_REG_X86_R8B;
		break;
	case DR_REG_R9L:
		triton_reg = triton::arch::ID_REG_X86_R9B;
		break;
	case DR_REG_R10L:
		triton_reg = triton::arch::ID_REG_X86_R10B;
		break;
	case DR_REG_R11L:
		triton_reg = triton::arch::ID_REG_X86_R11B;
		break;
	case DR_REG_R12L:
		triton_reg = triton::arch::ID_REG_X86_R12B;
		break;
	case DR_REG_R13L:
		triton_reg = triton::arch::ID_REG_X86_R13B;
		break;
	case DR_REG_R14L:
		triton_reg = triton::arch::ID_REG_X86_R14B;
		break;
	case DR_REG_R15L:
		triton_reg = triton::arch::ID_REG_X86_R15B;
		break;
	case DR_REG_SPL:
		triton_reg = triton::arch::ID_REG_X86_SPL;
		break;
	case DR_REG_BPL:
		triton_reg = triton::arch::ID_REG_X86_BPL;
		break;
	case DR_REG_SIL:
		triton_reg = triton::arch::ID_REG_X86_SIL;
		break;
	case DR_REG_DIL:
		triton_reg = triton::arch::ID_REG_X86_DIL;
		break;
	case DR_REG_MM0:
		triton_reg = triton::arch::ID_REG_X86_MM0;
		break;
	case DR_REG_MM1:
		triton_reg = triton::arch::ID_REG_X86_MM1;
		break;
	case DR_REG_MM2:
		triton_reg = triton::arch::ID_REG_X86_MM2;
		break;
	case DR_REG_MM3:
		triton_reg = triton::arch::ID_REG_X86_MM3;
		break;
	case DR_REG_MM4:
		triton_reg = triton::arch::ID_REG_X86_MM4;
		break;
	case DR_REG_MM5:
		triton_reg = triton::arch::ID_REG_X86_MM5;
		break;
	case DR_REG_MM6:
		triton_reg = triton::arch::ID_REG_X86_MM6;
		break;
	case DR_REG_MM7:
		triton_reg = triton::arch::ID_REG_X86_MM7;
		break;
	case DR_REG_XMM0:
		triton_reg = triton::arch::ID_REG_X86_XMM0;
		break;
	case DR_REG_XMM1:
		triton_reg = triton::arch::ID_REG_X86_XMM1;
		break;
	case DR_REG_XMM2:
		triton_reg = triton::arch::ID_REG_X86_XMM2;
		break;
	case DR_REG_XMM3:
		triton_reg = triton::arch::ID_REG_X86_XMM3;
		break;
	case DR_REG_XMM4:
		triton_reg = triton::arch::ID_REG_X86_XMM4;
		break;
	case DR_REG_XMM5:
		triton_reg = triton::arch::ID_REG_X86_XMM5;
		break;
	case DR_REG_XMM6:
		triton_reg = triton::arch::ID_REG_X86_XMM6;
		break;
	case DR_REG_XMM7:
		triton_reg = triton::arch::ID_REG_X86_XMM7;
		break;
	case DR_REG_XMM8:
		triton_reg = triton::arch::ID_REG_X86_XMM8;
		break;
	case DR_REG_XMM9:
		triton_reg = triton::arch::ID_REG_X86_XMM9;
		break;
	case DR_REG_XMM10:
		triton_reg = triton::arch::ID_REG_X86_XMM10;
		break;
	case DR_REG_XMM11:
		triton_reg = triton::arch::ID_REG_X86_XMM11;
		break;
	case DR_REG_XMM12:
		triton_reg = triton::arch::ID_REG_X86_XMM12;
		break;
	case DR_REG_XMM13:
		triton_reg = triton::arch::ID_REG_X86_XMM13;
		break;
	case DR_REG_XMM14:
		triton_reg = triton::arch::ID_REG_X86_XMM14;
		break;
	case DR_REG_XMM15:
		triton_reg = triton::arch::ID_REG_X86_XMM15;
		break;
	case DR_REG_ST0:
		triton_reg = triton::arch::ID_REG_X86_ST0;
		break;
	case DR_REG_ST1:
		triton_reg = triton::arch::ID_REG_X86_ST1;
		break;
	case DR_REG_ST2:
		triton_reg = triton::arch::ID_REG_X86_ST2;
		break;
	case DR_REG_ST3:
		triton_reg = triton::arch::ID_REG_X86_ST3;
		break;
	case DR_REG_ST4:
		triton_reg = triton::arch::ID_REG_X86_ST4;
		break;
	case DR_REG_ST5:
		triton_reg = triton::arch::ID_REG_X86_ST5;
		break;
	case DR_REG_ST6:
		triton_reg = triton::arch::ID_REG_X86_ST6;
		break;
	case DR_REG_ST7:
		triton_reg = triton::arch::ID_REG_X86_ST7;
		break;
	case DR_SEG_ES:
		triton_reg = triton::arch::ID_REG_X86_ES;
		break;
	case DR_SEG_CS:
		triton_reg = triton::arch::ID_REG_X86_CS;
		break;
	case DR_SEG_SS:
		triton_reg = triton::arch::ID_REG_X86_SS;
		break;
	case DR_SEG_DS:
		triton_reg = triton::arch::ID_REG_X86_DS;
		break;
	case DR_SEG_FS:
		triton_reg = triton::arch::ID_REG_X86_FS;
		break;
	case DR_SEG_GS:
		triton_reg = triton::arch::ID_REG_X86_GS;
		break;
	case DR_REG_DR0:
		triton_reg = triton::arch::ID_REG_X86_DR0;
		break;
	case DR_REG_DR1:
		triton_reg = triton::arch::ID_REG_X86_DR1;
		break;
	case DR_REG_DR2:
		triton_reg = triton::arch::ID_REG_X86_DR2;
		break;
	case DR_REG_DR3:
		triton_reg = triton::arch::ID_REG_X86_DR3;
		break;
		//	case DR_REG_DR4:
		//		triton_reg = triton::arch::ID_REG_X86_DR4;
		//		break;
		//	case DR_REG_DR5:
		//		triton_reg = triton::arch::ID_REG_X86_DR5;
		//		break;
	case DR_REG_DR6:
		triton_reg = triton::arch::ID_REG_X86_DR6;
		break;
	case DR_REG_DR7:
		triton_reg = triton::arch::ID_REG_X86_DR7;
		break;
		//	case DR_REG_DR8:
		//		triton_reg = triton::arch::ID_REG_X86_DR8;
		//		break;
	case DR_REG_CR0:
		triton_reg = triton::arch::ID_REG_X86_CR0;
		break;
	case DR_REG_CR1:
		triton_reg = triton::arch::ID_REG_X86_CR1;
		break;
	case DR_REG_CR2:
		triton_reg = triton::arch::ID_REG_X86_CR2;
		break;
	case DR_REG_CR3:
		triton_reg = triton::arch::ID_REG_X86_CR3;
		break;
	case DR_REG_CR4:
		triton_reg = triton::arch::ID_REG_X86_CR4;
		break;
	case DR_REG_CR5:
		triton_reg = triton::arch::ID_REG_X86_CR5;
		break;
	case DR_REG_CR6:
		triton_reg = triton::arch::ID_REG_X86_CR6;
		break;
	case DR_REG_CR7:
		triton_reg = triton::arch::ID_REG_X86_CR7;
		break;
	case DR_REG_CR8:
		triton_reg = triton::arch::ID_REG_X86_CR8;
		break;
	case DR_REG_CR9:
		triton_reg = triton::arch::ID_REG_X86_CR9;
		break;
	case DR_REG_CR10:
		triton_reg = triton::arch::ID_REG_X86_CR10;
		break;
	case DR_REG_CR11:
		triton_reg = triton::arch::ID_REG_X86_CR11;
		break;
	case DR_REG_CR12:
		triton_reg = triton::arch::ID_REG_X86_CR12;
		break;
	case DR_REG_CR13:
		triton_reg = triton::arch::ID_REG_X86_CR13;
		break;
	case DR_REG_CR14:
		triton_reg = triton::arch::ID_REG_X86_CR14;
		break;
	case DR_REG_CR15:
		triton_reg = triton::arch::ID_REG_X86_CR15;
		break;
	case DR_REG_YMM0:
		triton_reg = triton::arch::ID_REG_X86_YMM0;
		break;
	case DR_REG_YMM1:
		triton_reg = triton::arch::ID_REG_X86_YMM1;
		break;
	case DR_REG_YMM2:
		triton_reg = triton::arch::ID_REG_X86_YMM2;
		break;
	case DR_REG_YMM3:
		triton_reg = triton::arch::ID_REG_X86_YMM3;
		break;
	case DR_REG_YMM4:
		triton_reg = triton::arch::ID_REG_X86_YMM4;
		break;
	case DR_REG_YMM5:
		triton_reg = triton::arch::ID_REG_X86_YMM5;
		break;
	case DR_REG_YMM6:
		triton_reg = triton::arch::ID_REG_X86_YMM6;
		break;
	case DR_REG_YMM7:
		triton_reg = triton::arch::ID_REG_X86_YMM7;
		break;
	case DR_REG_YMM8:
		triton_reg = triton::arch::ID_REG_X86_YMM8;
		break;
	case DR_REG_YMM9:
		triton_reg = triton::arch::ID_REG_X86_YMM9;
		break;
	case DR_REG_YMM10:
		triton_reg = triton::arch::ID_REG_X86_YMM10;
		break;
	case DR_REG_YMM11:
		triton_reg = triton::arch::ID_REG_X86_YMM11;
		break;
	case DR_REG_YMM12:
		triton_reg = triton::arch::ID_REG_X86_YMM12;
		break;
	case DR_REG_YMM13:
		triton_reg = triton::arch::ID_REG_X86_YMM13;
		break;
	case DR_REG_YMM14:
		triton_reg = triton::arch::ID_REG_X86_YMM14;
		break;
	case DR_REG_YMM15:
		triton_reg = triton::arch::ID_REG_X86_YMM15;
		break;
	case DR_REG_ZMM0:
		triton_reg = triton::arch::ID_REG_X86_ZMM0;
		break;
	case DR_REG_ZMM1:
		triton_reg = triton::arch::ID_REG_X86_ZMM1;
		break;
	case DR_REG_ZMM2:
		triton_reg = triton::arch::ID_REG_X86_ZMM2;
		break;
	case DR_REG_ZMM3:
		triton_reg = triton::arch::ID_REG_X86_ZMM3;
		break;
	case DR_REG_ZMM4:
		triton_reg = triton::arch::ID_REG_X86_ZMM4;
		break;
	case DR_REG_ZMM5:
		triton_reg = triton::arch::ID_REG_X86_ZMM5;
		break;
	case DR_REG_ZMM6:
		triton_reg = triton::arch::ID_REG_X86_ZMM6;
		break;
	case DR_REG_ZMM7:
		triton_reg = triton::arch::ID_REG_X86_ZMM7;
		break;
	case DR_REG_ZMM8:
		triton_reg = triton::arch::ID_REG_X86_ZMM8;
		break;
	case DR_REG_ZMM9:
		triton_reg = triton::arch::ID_REG_X86_ZMM9;
		break;
	case DR_REG_ZMM10:
		triton_reg = triton::arch::ID_REG_X86_ZMM10;
		break;
	case DR_REG_ZMM11:
		triton_reg = triton::arch::ID_REG_X86_ZMM11;
		break;
	case DR_REG_ZMM12:
		triton_reg = triton::arch::ID_REG_X86_ZMM12;
		break;
	case DR_REG_ZMM13:
		triton_reg = triton::arch::ID_REG_X86_ZMM13;
		break;
	case DR_REG_ZMM14:
		triton_reg = triton::arch::ID_REG_X86_ZMM14;
		break;
	case DR_REG_ZMM15:
		triton_reg = triton::arch::ID_REG_X86_ZMM15;
		break;
	case DR_REG_ZMM16:
		triton_reg = triton::arch::ID_REG_X86_ZMM16;
		break;
	case DR_REG_ZMM17:
		triton_reg = triton::arch::ID_REG_X86_ZMM17;
		break;
	case DR_REG_ZMM18:
		triton_reg = triton::arch::ID_REG_X86_ZMM18;
		break;
	case DR_REG_ZMM19:
		triton_reg = triton::arch::ID_REG_X86_ZMM19;
		break;
	case DR_REG_ZMM20:
		triton_reg = triton::arch::ID_REG_X86_ZMM20;
		break;
	case DR_REG_ZMM21:
		triton_reg = triton::arch::ID_REG_X86_ZMM21;
		break;
	case DR_REG_ZMM22:
		triton_reg = triton::arch::ID_REG_X86_ZMM22;
		break;
	case DR_REG_ZMM23:
		triton_reg = triton::arch::ID_REG_X86_ZMM23;
		break;
	case DR_REG_ZMM24:
		triton_reg = triton::arch::ID_REG_X86_ZMM24;
		break;
	case DR_REG_ZMM25:
		triton_reg = triton::arch::ID_REG_X86_ZMM25;
		break;
	case DR_REG_ZMM26:
		triton_reg = triton::arch::ID_REG_X86_ZMM26;
		break;
	case DR_REG_ZMM27:
		triton_reg = triton::arch::ID_REG_X86_ZMM27;
		break;
	case DR_REG_ZMM28:
		triton_reg = triton::arch::ID_REG_X86_ZMM28;
		break;
	case DR_REG_ZMM29:
		triton_reg = triton::arch::ID_REG_X86_ZMM29;
		break;
	case DR_REG_ZMM30:
		triton_reg = triton::arch::ID_REG_X86_ZMM30;
		break;
	case DR_REG_ZMM31:
		triton_reg = triton::arch::ID_REG_X86_ZMM31;
		break;
	default:
		std::cerr << "No case matched." << std::endl;
		y_assert(false, "unsupported reg.", __FILE__, __LINE__);
		break;
	}
	return triton_reg;
}







