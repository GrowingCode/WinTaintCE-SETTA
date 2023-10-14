#include "yyx_trace.h"
#include "yyx_trace_taint.h"
#include "yyx_taint_test.h"


void test_sub()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_TestReadFile.exe_45057,4896,140696524952352:sub,1,2051656999202,582928037648,0,587776,0,4881ec90010000;\n3,1,1,5,reg,8,80f537b987000000;\n2,3,1,400,immed_int,4;\n2,1,1,5,reg,8,10f737b987000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(5, 0, 8, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);
	}
	
	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(5, 0, 8, bts);

		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_rep_movs()
{
	// the file must be ended with '\n'.
	YTrace* yte = new YTrace(false, "C:/HomeSpace/CTaintAnalysis/yyx_taint/run-env/jpeg_trace/sliced_trace_for_rep/rep_movs_test.txt");
	YTaint* yt = new YTaint(yte);

	slot* slot_rep_movs_instr = yte->vect.at(1);
	instr* rep_movs_instr = (instr*) slot_rep_movs_instr->object;
	{
		opnd* opd_src_0 = rep_movs_instr->srcs.at(0);
		std::vector<MCByteID> src_0_bids;
		get_bytes_in_expanded(opd_src_0, -1, src_0_bids);

		VirtualTaintInfo bti(src_0_bids);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);
	}

	yt->HandleTaintInTrace();

	{
		opnd* opd_dst_0 = rep_movs_instr->dsts.at(0);
		std::vector<MCByteID> dst_0_bids;
		get_bytes_in_expanded(opd_dst_0, -1, dst_0_bids);

		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : dst_0_bids) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_vmovdqa()
{
	// the content must be ended with '\n'. 
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_VCRUNTIME140.dll_110593,6896,140728857926384:vmovdqa,1,2143872032821,719598907736,0,0,0,c5fd7f01;1,2,8,e0f36f8ba7000000;\n3,2,1,719598908384,mem,32,0000000000000000000000000000000000000000000000000000000000000000;\n2,1,1,188,reg,32,0000000000000000000000000000000000000000000000000000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(188, 0, 32, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_mem_bytes((byte*)719598908384, 32, bts);

		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}
void test_paddd()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_jpeg62.dll_438273,95715,140728721372643:paddd,1,2093049308132,681818912496,0,0,0,660ffed9;2,191,32,0000000002000000010000000300000000000000000000000000000000000000;\n3,1,1,80,reg,16,05000000070000000500000007000000;\n2,1,1,78,reg,16,05000000050000000400000004000000;\n2,1,1,80,reg,16,00000000020000000100000003000000;\n");
	YTaint* yt = new YTaint(yte);
	{
		std::vector<MCByteID> bts;
		get_reg_bytes(80, 0, 4, bts);
		get_reg_bytes(78, 5, 1, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(80, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pslld()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_jpeg62.dll_438273,14769,140728721291697:pslld,1,2093049435429,681818912336,0,0,0,66410ff2c2;2,188,32,e4000000e5000000e6000000e700000000000000000000000000000000000000;\n3,1,1,77,reg,16,00007200008072000000730000807300;\n2,1,1,87,reg,16,0f000000000000000000000000000000;\n2,1,1,77,reg,16,e4000000e5000000e6000000e7000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 2, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_punpcklwd()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_jpeg62.dll_438273,87568,140728721364496:punpcklwd,1,2093049729529,681818912464,0,0,0,660f61c8;2,189,32,0400040003000400000000000000000000000000000000000000000000000000;\n3,1,1,78,reg,16,04000000040000000300000004000000;\n2,1,1,77,reg,16,00000000000000000000000000000000;\n2,1,1,78,reg,16,04000400030004000000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 10, 1, bts);
//		get_reg_bytes(77, 3, 3, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : bts) {
			bool bt_is_tainted = false;
			if (itri != NULL) {
				auto it = itri->origin_taint.find(bt);
				// this statement proves bt is tainted. 
				if (it != itri->origin_taint.end()) {
					std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
					std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
					std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
					printf("%s\n", pr.c_str());
					bt_is_tainted = true;
				}
			}
			if (not bt_is_tainted) {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pmulld()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_jpeg62.dll_438273,14820,140728721291748:pmulld,1,2093049439372,681818912336,0,0,0,66410f3840d5;2,190,32,fc000000fd000000fe000000ff00000000000000000000000000000000000000;\n3,1,1,79,reg,16,4482ebff736debffa258ebffd143ebff;\n2,1,1,90,reg,16,2febffff2febffff2febffff2febffff;\n2,1,1,79,reg,16,fc000000fd000000fe000000ff000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 2, 2, bts);
		get_reg_bytes(90, 0, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pshufd()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_jpeg62.dll_438273,14696,140728721291624:pshufd,1,2093049406452,681818912336,0,0,0,660f70d200;2,190,32,0000000000000000000000000000000000000000000000000000000000000000;\n3,1,1,79,reg,16,00000000000000000000000000000000;\n2,1,1,79,reg,16,00000000000000000000000000000000;\n2,3,1,0,immed_int,1;\n");
	YTaint* yt = new YTaint(yte);

	{
		// std::vector<MCByteID> bts;
		// get_reg_bytes(5, 0, 8, bts);
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 1, bts);
		// int imm;
		// memcpy_s(imm,1,,1);

		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);

		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			// y_assert(it != itri->origin_taint.end());

			if (it != itri->origin_taint.end())
			{
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_aesenc()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,96235,140727261689835:aesenc,1,3429363550,66204723176,0,0,0,660f38dcd1;2,190,32,000102030405060708090a0b0c0d0e0f00000000000000000000000000000000;\n3,1,1,79,reg,16,7a7b4e5638782546a8c0477a3b813f43;\n2,1,1,78,reg,16,101112131415161718191a1b1c1d1e1f;\n2,1,1,79,reg,16,000102030405060708090a0b0c0d0e0f;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 8, bts);
		get_reg_bytes(79, 0, 16, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_aesenclast()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,96249,140727261689849:aesenclast,1,3429364400,66204723176,0,0,0,660f38ddd0;2,190,32,4a985e5badb8b7b9df72af79fcebf5bd00000000000000000000000000000000;\n3,1,1,79,reg,16,f29000b62a499fd0a9f39a6add2e7780;\n2,1,1,77,reg,16,24fc79ccbf0979e9371ac23c6d68de36;\n2,1,1,79,reg,16,4a985e5badb8b7b9df72af79fcebf5bd;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 4, bts);
		get_reg_bytes(79, 0, 16, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_aeskeygenassist()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,115435,140727261709035:aeskeygenassist,1,3429390358,66204723200,0,0,0,660f3adfc800;2,189,32,8987904987904989898790498790498900000000000000000000000000000000;\n3,1,1,78,reg,16,9444d4c744d4c7949444d4c744d4c794;\n2,1,1,77,reg,16,e7861931e7861931e7861931e7861931;\n2,3,1,0,immed_int,1;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_bswap()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,93271,140727261686871:bswap,1,3429493292,66204723488,0,0,0,480fcb;\n3,1,1,4,reg,8,0000000000000003;\n2,1,1,4,reg,8,0300000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(4, 0, 1, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(4, 0, 8, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_paddq()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,94179,140727261687779:paddq,1,3429652880,66204726560,0,0,0,660fd4f2;2,194,32,0200000000000000000000000000000000000000000000000000000000000000;\n3,1,1,83,reg,16,a5df1050e136b29d23ba793725bca2f6;\n2,1,1,79,reg,16,a3df1050e136b29d23ba793725bca2f6;\n2,1,1,83,reg,16,02000000000000000000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 2, bts);
		get_reg_bytes(83, 5, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(83, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_por()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,96444,140727261690044:por,1,3429439302,66204724144,0,0,0,660febc1;2,188,32,0000000000000000000000000000000000000000000000000000000000000000;\n3,1,1,77,reg,16,00000000000000000000000000000000;\n2,1,1,78,reg,16,00000000000000000000000000000000;\n2,1,1,77,reg,16,00000000000000000000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 2, bts);
		get_reg_bytes(77, 5, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pshufb()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,93945,140727261687545:pshufb,1,3429786463,66204727232,0,0,0,66410f3800d3;2,190,32,b80c26183197a01ae0fa8a946a3719ed00000000000000000000000000000000;\n3,1,1,79,reg,16,ed19376a948afae01aa0973118260cb8;\n2,1,1,88,reg,16,0f0e0d0c0b0a09080706050403020100;\n2,1,1,79,reg,16,b80c26183197a01ae0fa8a946a3719ed;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(88, 0, 2, bts);
		get_reg_bytes(79, 5, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pxor()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_bcryptPrimitives.dll_532481,96211,140727261689811:pxor,1,3429751972,66204727096,0,0,0,660fefd3;2,190,32,e6d4fdf1c9d60b1576708ecd31bbc87200000000000000000000000000000000;\n3,1,1,79,reg,16,e6d5fff2cdd30d127e7984c63db6c67d;\n2,1,1,80,reg,16,000102030405060708090a0b0c0d0e0f;\n2,1,1,79,reg,16,e6d4fdf1c9d60b1576708ecd31bbc872;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(80, 1, 2, bts);
		get_reg_bytes(79, 5, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(79, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_rdtscp()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ntdll.dll_2064385,662336,140727303478080:rdtscp,1,3429609747,66204728200,0,0,0,0f01f9;2,1,8,0100000000000000;2,2,8,b0fb1b6a0f000000;2,3,8,1000000000000000;\n3,1,1,19,reg,4,83080000;\n3,1,1,17,reg,4,a711ff68;\n3,1,1,18,reg,4,00000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(17, 0, 2, bts);
		get_reg_bytes(18, 2, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(19, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pcmpeqw()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,299855,140727266087759:pcmpeqw,1,6905757366,94874563128,0,0,0,660f75c8;2,189,32,0000000000000000000000000000000000000000000000000000000000000000;\n3,1,1,78,reg,16,00000000000000000000ffffffffffff;\n2,1,1,77,reg,16,4300680069006e006100000000000000;\n2,1,1,78,reg,16,00000000000000000000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 1, 2, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pmovmskb()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,299867,140727266087771:pmovmskb,1,6905757371,94874563128,0,0,0,660fd7c1;2,1,8,a40a1b704c010000;\n3,1,1,17,reg,4,00fc0000;\n2,1,1,78,reg,16,00000000000000000000ffffffffffff;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 10, 1, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(17, 0, 4, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_pshuflw()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,299821,140727266087725:pshuflw,1,6905757353,94874563128,0,0,0,f20f70c800;2,189,32,00000000000000000000ffffffffffff00000000000000000000000000000000;\n3,1,1,78,reg,16,2e002e002e002e000000000000000000;\n2,1,1,77,reg,16,2e000000000000000000000000000000;\n2,3,1,0,immed_int,1;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 1, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(78, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_psrad()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_tidy.dll_806913,97766,140726105636326:psrad,1,6915484215,94874564752,0,0,0,660f72e018;2,188,32,6868686874747474000000000000000000000000000000000000000000000000;\n3,1,1,77,reg,16,68000000740000000000000000000000;\n2,3,1,24,immed_int,1;\n2,1,1,77,reg,16,68686868747474740000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 4, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(77, 0, 16, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_vpcmpeqb()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,158961,140727265946865:vpcmpeqb,1,6912534902,94874562312,0,0,0,c5f57409;1,2,8,601e9159fd7f0000;2,189,32,0000000000000000000000000000000000000000000000000000000000000000;\n3,1,1,189,reg,32,000000000000000000ffffffffffffff0000000000000000ffffffffffffffff;\n2,1,1,189,reg,32,0000000000000000000000000000000000000000000000000000000000000000;\n2,2,1,140726106136160,mem,32,5761726e696e673a2000000000000000436f6e6669673a200000000000000000;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(189, 0, 4, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(189, 0, 32, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_vpcmpeqw()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,159675,140727265947579:vpcmpeqw,1,6907215754,94874562808,0,0,0,c4c1757509;1,10,8,e0261d704c010000;2,189,32,0000000000000000000000000000000000000000000000000000000000000000;\n3,1,1,189,reg,32,00000000000000000000ffffffffffffffffffffffffffff0000000000000000;\n2,1,1,189,reg,32,0000000000000000000000000000000000000000000000000000000000000000;\n2,2,1,1427810100960,mem,32,7a0068002d0043004e000000000000000000000000000000412173bc00260080;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(189, 0, 4, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(189, 0, 32, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_vpmovmskb()
{
	// Alert! must no white space!
	YTrace* yte = new YTrace(true, "4,0,0,0,main_entry;\n1,Resolved_ucrtbase.dll_1048577,158965,140727265946869:vpmovmskb,1,6909803551,94874562312,0,0,0,c5fdd7c1;2,1,8,a40a1b704c010000;\n3,1,1,17,reg,4,00fe00ff;\n2,1,1,189,reg,32,000000000000000000ffffffffffffff0000000000000000ffffffffffffffff;\n");
	YTaint* yt = new YTaint(yte);

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(189, 6, 4, bts);
		VirtualTaintInfo bti(bts);
		yt->SetUpPreSetTaintInfoForInstruction(0, bti);

		//	std::vector<MCByteID> bts;
		//	get_mem_bytes((byte*)31332191, 0, 4, bts);
	}

	yt->HandleTaintInTrace();

	{
		std::vector<MCByteID> bts;
		get_reg_bytes(17, 0, 4, bts);
		InstrTaintRootInfo* itri = yt->each_instr_taint_root_info.at(1);
		//for (const auto& pair : itri->origin_taint) {
		//	printf("map: %lu\n", pair.first.reg_id_or_mem_with_byte_offset);
		//}
		for (MCByteID bt : bts) {
			auto it = itri->origin_taint.find(bt);
			// this statement proves bt is tainted. 
			if (it != itri->origin_taint.end()) {
				std::set<TraceableByteTaintSetPosition> origin_taint_bytes = it->second;
				std::string str = YPrintUtil::print_to_string(origin_taint_bytes);
				std::string pr = "new_tainted_byte:" + bt.to_string() + ",all sources taint bytes:" + str;
				printf("%s\n", pr.c_str());
			}
			else {
				printf("byte:%s is not tainted.\n", bt.to_string().c_str());
			}
		}
	}
}

void test_main()
{
//	test_sub();
//	test_rep_movs();
//	test_vmovdqa();
//	test_paddd();
	test_punpcklwd();
//	test_pshufb();
//	test_pshufd();
//	test_pshuflw();
//	test_paddq();
//	test_pcmpeqw();
}



