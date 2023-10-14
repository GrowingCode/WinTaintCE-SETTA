#include <string>

#include "trace_analysis.h"
#include "yyx_global_info.h"


std::string resolved_pfx = "Resolved_";
std::string system_level_module_name[] = { "ntdll.dll", "ucrtbase.dll", "KERNELBASE.dll" };
std::string lc_resolved_pfx = "resolved_";

bool module_name_should_be_ignored_when_computing_branch(std::string module_name) {
	YStringUtil::toLowerCase(module_name);
	bool res = false;
	if (module_name.rfind(lc_resolved_pfx, 0) == 0) {
		for (std::string sys_mname : system_level_module_name) {
			YStringUtil::toLowerCase(sys_mname);
			size_t lc_rpsz = lc_resolved_pfx.size();
			int64_t found_pos = module_name.find(sys_mname, lc_rpsz);
			int64_t next_c_idx = found_pos + sys_mname.size();
			if (found_pos == lc_rpsz and module_name[next_c_idx] == '_') {
				res = true;
			}
		}
		//		std::cout << "String starts with the given prefix" << std::endl;
	}
	else {
		// do nothing. 
//		std::cout << "String doesn't starts with prefix" << std::endl;
	}
	return res;
}

template<typename datatype>
static TrendType ComputeTrendConsiderOverflow(InstrVal diff1_v0, InstrVal diff1_v1, InstrVal diff2_v0, InstrVal diff2_v1) {
	datatype diff1_left;
	datatype diff1_right;
	datatype diff2_left;
	datatype diff2_right;
	memcpy_s(&diff1_left, diff1_v0.val_size, diff1_v0.val, diff1_v0.val_size);
	memcpy_s(&diff1_right, diff1_v1.val_size, diff1_v1.val, diff1_v1.val_size);
	memcpy_s(&diff2_left, diff2_v0.val_size, diff2_v0.val, diff2_v0.val_size);
	memcpy_s(&diff2_right, diff2_v1.val_size, diff2_v1.val, diff2_v1.val_size);
	
	datatype diff1_diff = diff1_right - diff1_left;
	datatype diff2_diff = diff2_right - diff2_left;

	bool diff1_diff_positive = diff1_right >= diff1_left ? true : false;
	bool diff2_diff_positive = diff2_right >= diff2_left ? true : false;

	bool dd1_overflow = is_overflow<datatype>(diff1_diff, diff1_right);
	bool dd2_overflow = is_overflow<datatype>(diff2_diff, diff2_right);

	TrendType trendType;
	if (diff2_left == diff2_right) {
		trendType = TrendType::MoveToFlipButFlipToEqual;
	}
	else {
		// diff2_left and diff2_right must be different
		if ((diff1_diff_positive xor diff2_diff_positive) == 1) {
			// sign different
			trendType = TrendType::MoveToFlipButFlip;
		}
		else {
			// sign same
			if (dd1_overflow and dd2_overflow) {
				// must be same sign for both left, right of dd1 and dd2. 
				bool diff1_left_positive = diff1_left >= 0;
				bool diff2_left_positive = diff2_left >= 0;
				bool diff1_right_positive = diff1_right >= 0;
				bool diff2_right_positive = diff2_right >= 0;
				y_assert(((diff1_left_positive xor diff2_left_positive) == 0) and ((diff1_right_positive xor diff2_right_positive) == 0), "siff sign wrong.", __FILE__, __LINE__);
				datatype right_diff = diff2_right - diff1_right;
				datatype left_diff = diff2_left - diff1_left;
				bool right_diff_positive = right_diff >= 0;
				bool left_diff_positive = left_diff >= 0;
				datatype df1_sign = diff1_diff_positive == 1 ? 1 : -1;
				if ((right_diff_positive xor left_diff_positive) == 1) {
					// sign different
					// left lt right normal situation 
					int normal_situation = (left_diff_positive == true and right_diff_positive == false) ? 1 : -1;
					int full_situation = df1_sign * normal_situation;
					if (full_situation) {
						trendType = TrendType::MoveToFlipButNotFlip;
					}
					else {
						trendType = TrendType::NotMoveToFlip;
					}
				}
				else {
					// sign same
					if (left_diff == right_diff) {
						trendType = TrendType::NotChange;
					}
					else {
						int dec_less_inc = left_diff < right_diff ? 1 : -1;
						if (df1_sign * dec_less_inc == 1) {
							trendType = TrendType::NotMoveToFlip;
						}
						else {
							trendType = TrendType::MoveToFlipButNotFlip;
						}
					}
				}
			}
			else if ((not dd1_overflow) and dd2_overflow) {
				trendType = TrendType::NotMoveToFlip;
			}
			else if (dd1_overflow and (not dd2_overflow)) {
				trendType = TrendType::MoveToFlipButNotFlip;
			}
			else {
				// not dd1_overflow and not dd2_overflow
				if (diff1_diff == diff2_diff) {
					trendType = TrendType::NotChange;
				}
				else if (abs(diff1_diff) < abs(diff2_diff)) {
					trendType = TrendType::NotMoveToFlip;
				}
				else {
					trendType = TrendType::MoveToFlipButNotFlip;
				}
			}
		}
	}

	//if (diff2_left == diff2_right) {
	//	trendType = MoveToFlipButFlipToEqual;
	//}
	//else if (!sub_overflow<datatype>(diff1_left, diff2_right) && !sub_overflow<datatype>(diff1_left, diff2_right)) { //both not overflow
	//	datatype diff1_int = diff1_left - diff1_right;
	//	datatype diff2_int = diff2_left - diff2_right;
	//	if (diff1_int == diff2_int) {
	//		trendType = NotChange;
	//	}
	//	else if ((diff1_int > 0 && diff2_int > 0) || (diff1_int < 0 && diff2_int < 0)) {
	//		if (std::abs(diff1_int) < std::abs(diff2_int)) {
	//			trendType = NotMoveToFlip;
	//		}
	//		else if (std::abs(diff1_int) > std::abs(diff2_int)) {
	//			trendType = MoveToFlipButNotFlip;
	//		}
	//	}
	//	else if ((diff1_int > 0 && diff2_int < 0) || (diff1_int < 0 && diff2_int > 0)) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//}
	//else if (!sub_overflow<datatype>(diff1_left, diff2_right) && sub_overflow<datatype>(diff1_left, diff2_right)) { //diff1 overflow
	//	if (diff1_left < diff1_right && diff2_left < diff2_right) {
	//		trendType = MoveToFlipButNotFlip;
	//	}
	//	else if (diff1_left < diff1_right && diff2_left > diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//	else if (diff1_left > diff1_right && diff2_left > diff2_right) {
	//		trendType = MoveToFlipButNotFlip;
	//	}
	//	else if (diff1_left > diff1_right && diff2_left < diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//}
	//else if (sub_overflow<datatype>(diff1_left, diff2_right) && !sub_overflow<datatype>(diff1_left, diff2_right)) { //diff2 overflow
	//	if (diff1_left < diff1_right && diff2_left < diff2_right) {
	//		trendType = NotMoveToFlip;
	//	}
	//	else if (diff1_left < diff1_right && diff2_left > diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//	else if (diff1_left > diff1_right && diff2_left > diff2_right) {
	//		trendType = NotMoveToFlip;
	//	}
	//	else if (diff1_left > diff1_right && diff2_left < diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//}
	//else if (sub_overflow<datatype>(diff1_left, diff2_right) && sub_overflow<datatype>(diff1_left, diff2_right)) { //both overflow
	//	if (diff1_left < diff1_right && diff2_left < diff2_right) {
	//		if (diff1_left - diff2_left < diff1_right - diff2_right) {
	//			trendType = NotMoveToFlip;
	//		}
	//		else if (diff1_left - diff2_left == diff1_right - diff2_right) {
	//			trendType = NotChange;
	//		}
	//		else if (diff1_left - diff2_left > diff1_right - diff2_right) {
	//			trendType = MoveToFlipButNotFlip;
	//		}
	//	}
	//	else if (diff1_left < diff1_right && diff2_left > diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//	else if (diff1_left > diff1_right && diff2_left > diff2_right) {
	//		if (diff1_left - diff2_left < diff1_right - diff2_right) {
	//			trendType = NotMoveToFlip;
	//		}
	//		else if (diff1_left - diff2_left == diff1_right - diff2_right) {
	//			trendType = NotChange;
	//		}
	//		else if (diff1_left - diff2_left > diff1_right - diff2_right) {
	//			trendType = MoveToFlipButNotFlip;
	//		}
	//	}
	//	else if (diff1_left > diff1_right && diff2_left < diff2_right) {
	//		trendType = MoveToFlipButFlip;
	//	}
	//}

	return trendType;
}

Trend YTraceCompareUtil::ComputeOneValDiffPairTrend(InstrValDifference& diff1, InstrValDifference& diff2)
{
	Trend trend;
	if (diff1.v_diff_type == ValDiffType::NoDiff) {
		y_assert(diff2.v_diff_type != ValDiffType::NoDiff, "diff2.v_diff_type != ValDiffType::NoDiff", __FILE__, __LINE__);
		trend.oet = TrendType::LeftToRightNewData;
	}
	else if (diff2.v_diff_type == ValDiffType::NoDiff) {
		trend.oet = TrendType::LeftToRightDeleteData;
	}
	else {
		y_assert(diff1.v_diff_type != ValDiffType::NoDiff and diff2.v_diff_type != ValDiffType::NoDiff, "val diff type wrong.", __FILE__, __LINE__);
		// compare diff_value and compute both-exist trend. 
		// TrendType* trend_for_different_bit_1_in_xor_value_of_each_byte = 0;

		//	MoveToFlipButNotFlip, //move to 0, but not flip
		//	MoveToFlipButFlipToEqual, // ==0
		//	MoveToFlipButFlip, //move to 0, but flip
		//	NotChange, //no change
		//	NotMoveToFlip, //not move to 0

		TrendType trendType = TrendType::NoTrend;
		if (diff1.v_diff_type == ValDiffType::IntDiff) {
			if (diff1.vals[0].val_size == 1) {
				trendType = ComputeTrendConsiderOverflow<char>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
			}
			else if (diff1.vals[0].val_size == 2) {
				trendType = ComputeTrendConsiderOverflow<short>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
			}
			else if (diff1.vals[0].val_size == 4) {
				trendType = ComputeTrendConsiderOverflow<int>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
			}
			else if (diff1.vals[0].val_size == 8) {
				trendType = ComputeTrendConsiderOverflow<long long>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
			}
			else {
				y_assert(false, "diff val size wrong.", __FILE__, __LINE__);
			}
		}
		else if (diff1.v_diff_type == ValDiffType::FloatDiff) {
			trendType = ComputeTrendConsiderOverflow<float>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
		}
		else if (diff1.v_diff_type == ValDiffType::DoubleDiff) {
			trendType = ComputeTrendConsiderOverflow<double>(diff1.vals[0], diff1.vals[1], diff2.vals[0], diff2.vals[1]);
		}
		else {
			y_assert(false, "float diff val type wrong.", __FILE__, __LINE__);
		}
		trend.oet = trendType;
	}
	return trend;
}


