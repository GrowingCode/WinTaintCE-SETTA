#include "yyx_trace.h"


bool check_op = true;

slot::slot(slot* s_cpy) {
	this->kind = s_cpy->kind;
	if (this->kind == trace_unit_type::is_op_meta) {
		instr* s_cpy_itr = (instr*)s_cpy->object;
		instr* itr = new instr(this, s_cpy_itr);
		object = itr;
	}
	else if (this->kind == trace_unit_type::is_high_level_op_type) {
		high_level_op* s_cpy_hop = (high_level_op*)s_cpy->object;
		high_level_op* hop = new high_level_op(this, s_cpy_hop);
		object = hop;
	}
	else {
		y_assert(false, "slot kind wrong", __FILE__, __LINE__);
	}
	this->index = s_cpy->index;
	this->line_idx = s_cpy->line_idx;
}

bool opnd_value_same(opnd* opd1, opnd* opd2) {
	bool res = true;
	if (opd1->actual_size != opd2->actual_size) {
		res = false;
	}
	else {
		for (int i = 0; i < opd1->actual_size; i++) {
			bool val_i_same = (*(opd1->value + i) == *(opd2->value + i));
			res = res && val_i_same;
			if (not res) {
				break;
			}
		}
	}
	return res;
}

bool opnd_value_same(opnd** opd1, int opd1_size, opnd* opd2) {
	bool res = true;
	int opd1_total_size = 0;
	for (int i = 0; i < opd1_size; i++) {
		opnd* opd1_i = opd1[i];
		opd1_total_size += opd1_i->actual_size;
	}
	if (opd1_total_size != opd2->actual_size) {
		res = false;
	}
	else {
		int opd2_byte_cmpeds = 0;
		for (int i = 0; i < opd1_size; i++) {
			opnd* opd1_i = opd1[i];
			for (int j = 0; j < opd1_i->actual_size; j++) {
				bool val_i_same = (*(opd1_i->value + j) == *(opd2->value + opd2_byte_cmpeds));
				opd2_byte_cmpeds++;
				res = res && val_i_same;
				if (not res) {
					break;
				}
			}
		}
	}
	return res;
}






