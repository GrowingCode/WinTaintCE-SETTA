#include "yyx_global_info.h"


int get_return_dr_reg_size_in_bytes(uint16_t reg_id) {
	int sz = 0;
	switch (reg_id) {
	case DR_REG_AL:
		sz = 1;
		break;
	case DR_REG_AX:
		sz = 2;
		break;
	case DR_REG_EAX:
		sz = 4;
		break;
	case DR_REG_RAX:
		sz = 8;
		break;
	default:
		y_assert(false, "return reg out of range?", __FILE__, __LINE__);
		break;
	}
	return sz;
}

//void y_assert(bool cond) {
//	y_assert(cond, "");
//}

void y_assert(bool cond, const std::string& info, const char* file_info, int line) {
	if (cond == true) {
		// do nothing. 
	}
	else {
		int msgBoxID = MessageBox(NULL, (LPCSTR)info.c_str(), (LPCSTR)"WarningTitle", MB_ICONEXCLAMATION);
		printf("Assertion Failed! Info:%s at %s#line:%d, MsgBoxID:%d.\n", info.c_str(), file_info, line, msgBoxID);
		abort();
	}
}







