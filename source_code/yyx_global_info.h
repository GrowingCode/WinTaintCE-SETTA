#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <time.h>
#include <string>
#include <algorithm>
#include <limits>

#define taint_simplified_mode 0

enum TraceReg {
	/* The entire enum below overlaps with the OPSZ_ enum but all cases where the two are
	 * used in the same field (instr_info_t operand sizes) have the type and distinguish
	 * properly.
	 * XXX i#3528: Switch from guaranteed-contiguous exposed enum ranges, which are not
	 * possible to maintain long-term, to function interfaces.
	 */
	DR_REG_NULL, /**< Sentinel value indicating no register, for address modes. */
	/*#ifdef X86*/
	/* 64-bit general purpose */
	DR_REG_RAX, /**< The "rax" register. */
	DR_REG_RCX, /**< The "rcx" register. */
	DR_REG_RDX, /**< The "rdx" register. */
	DR_REG_RBX, /**< The "rbx" register. */
	DR_REG_RSP, /**< The "rsp" register. */
	DR_REG_RBP, /**< The "rbp" register. */
	DR_REG_RSI, /**< The "rsi" register. */
	DR_REG_RDI, /**< The "rdi" register. */
	DR_REG_R8,  /**< The "r8" register. */
	DR_REG_R9,  /**< The "r9" register. */
	DR_REG_R10, /**< The "r10" register. */
	DR_REG_R11, /**< The "r11" register. */
	DR_REG_R12, /**< The "r12" register. */
	DR_REG_R13, /**< The "r13" register. */
	DR_REG_R14, /**< The "r14" register. */
	DR_REG_R15, /**< The "r15" register. */
	/* 32-bit general purpose */
	DR_REG_EAX,  /**< The "eax" register. */
	DR_REG_ECX,  /**< The "ecx" register. */
	DR_REG_EDX,  /**< The "edx" register. */
	DR_REG_EBX,  /**< The "ebx" register. */
	DR_REG_ESP,  /**< The "esp" register. */
	DR_REG_EBP,  /**< The "ebp" register. */
	DR_REG_ESI,  /**< The "esi" register. */
	DR_REG_EDI,  /**< The "edi" register. */
	DR_REG_R8D,  /**< The "r8d" register. */
	DR_REG_R9D,  /**< The "r9d" register. */
	DR_REG_R10D, /**< The "r10d" register. */
	DR_REG_R11D, /**< The "r11d" register. */
	DR_REG_R12D, /**< The "r12d" register. */
	DR_REG_R13D, /**< The "r13d" register. */
	DR_REG_R14D, /**< The "r14d" register. */
	DR_REG_R15D, /**< The "r15d" register. */
	/* 16-bit general purpose */
	DR_REG_AX,   /**< The "ax" register. */
	DR_REG_CX,   /**< The "cx" register. */
	DR_REG_DX,   /**< The "dx" register. */
	DR_REG_BX,   /**< The "bx" register. */
	DR_REG_SP,   /**< The "sp" register. */
	DR_REG_BP,   /**< The "bp" register. */
	DR_REG_SI,   /**< The "si" register. */
	DR_REG_DI,   /**< The "di" register. */
	DR_REG_R8W,  /**< The "r8w" register. */
	DR_REG_R9W,  /**< The "r9w" register. */
	DR_REG_R10W, /**< The "r10w" register. */
	DR_REG_R11W, /**< The "r11w" register. */
	DR_REG_R12W, /**< The "r12w" register. */
	DR_REG_R13W, /**< The "r13w" register. */
	DR_REG_R14W, /**< The "r14w" register. */
	DR_REG_R15W, /**< The "r15w" register. */
	/* 8-bit general purpose */
	DR_REG_AL,   /**< The "al" register. */
	DR_REG_CL,   /**< The "cl" register. */
	DR_REG_DL,   /**< The "dl" register. */
	DR_REG_BL,   /**< The "bl" register. */
	DR_REG_AH,   /**< The "ah" register. */
	DR_REG_CH,   /**< The "ch" register. */
	DR_REG_DH,   /**< The "dh" register. */
	DR_REG_BH,   /**< The "bh" register. */
	DR_REG_R8L,  /**< The "r8l" register. */
	DR_REG_R9L,  /**< The "r9l" register. */
	DR_REG_R10L, /**< The "r10l" register. */
	DR_REG_R11L, /**< The "r11l" register. */
	DR_REG_R12L, /**< The "r12l" register. */
	DR_REG_R13L, /**< The "r13l" register. */
	DR_REG_R14L, /**< The "r14l" register. */
	DR_REG_R15L, /**< The "r15l" register. */
	DR_REG_SPL,  /**< The "spl" register. */
	DR_REG_BPL,  /**< The "bpl" register. */
	DR_REG_SIL,  /**< The "sil" register. */
	DR_REG_DIL,  /**< The "dil" register. */
	/* 64-BIT MMX */
	DR_REG_MM0, /**< The "mm0" register. */
	DR_REG_MM1, /**< The "mm1" register. */
	DR_REG_MM2, /**< The "mm2" register. */
	DR_REG_MM3, /**< The "mm3" register. */
	DR_REG_MM4, /**< The "mm4" register. */
	DR_REG_MM5, /**< The "mm5" register. */
	DR_REG_MM6, /**< The "mm6" register. */
	DR_REG_MM7, /**< The "mm7" register. */
	/* 128-BIT XMM */
	DR_REG_XMM0,  /**< The "xmm0" register. */
	DR_REG_XMM1,  /**< The "xmm1" register. */
	DR_REG_XMM2,  /**< The "xmm2" register. */
	DR_REG_XMM3,  /**< The "xmm3" register. */
	DR_REG_XMM4,  /**< The "xmm4" register. */
	DR_REG_XMM5,  /**< The "xmm5" register. */
	DR_REG_XMM6,  /**< The "xmm6" register. */
	DR_REG_XMM7,  /**< The "xmm7" register. */
	DR_REG_XMM8,  /**< The "xmm8" register. */
	DR_REG_XMM9,  /**< The "xmm9" register. */
	DR_REG_XMM10, /**< The "xmm10" register. */
	DR_REG_XMM11, /**< The "xmm11" register. */
	DR_REG_XMM12, /**< The "xmm12" register. */
	DR_REG_XMM13, /**< The "xmm13" register. */
	DR_REG_XMM14, /**< The "xmm14" register. */
	DR_REG_XMM15, /**< The "xmm15" register. */
	DR_REG_XMM16, /**< The "xmm16" register. */
	DR_REG_XMM17, /**< The "xmm17" register. */
	DR_REG_XMM18, /**< The "xmm18" register. */
	DR_REG_XMM19, /**< The "xmm19" register. */
	DR_REG_XMM20, /**< The "xmm20" register. */
	DR_REG_XMM21, /**< The "xmm21" register. */
	DR_REG_XMM22, /**< The "xmm22" register. */
	DR_REG_XMM23, /**< The "xmm23" register. */
	DR_REG_XMM24, /**< The "xmm24" register. */
	DR_REG_XMM25, /**< The "xmm25" register. */
	DR_REG_XMM26, /**< The "xmm26" register. */
	DR_REG_XMM27, /**< The "xmm27" register. */
	DR_REG_XMM28, /**< The "xmm28" register. */
	DR_REG_XMM29, /**< The "xmm29" register. */
	DR_REG_XMM30, /**< The "xmm30" register. */
	DR_REG_XMM31, /**< The "xmm31" register. */
	/* 32 enums are reserved for future Intel SIMD extensions. */
	RESERVED_XMM = DR_REG_XMM31 + 32,
	/* floating point registers */
	DR_REG_ST0, /**< The "st0" register. */
	DR_REG_ST1, /**< The "st1" register. */
	DR_REG_ST2, /**< The "st2" register. */
	DR_REG_ST3, /**< The "st3" register. */
	DR_REG_ST4, /**< The "st4" register. */
	DR_REG_ST5, /**< The "st5" register. */
	DR_REG_ST6, /**< The "st6" register. */
	DR_REG_ST7, /**< The "st7" register. */
	/* segments (order from "Sreg" description in Intel manual) */
	DR_SEG_ES, /**< The "es" register. */
	DR_SEG_CS, /**< The "cs" register. */
	DR_SEG_SS, /**< The "ss" register. */
	DR_SEG_DS, /**< The "ds" register. */
	DR_SEG_FS, /**< The "fs" register. */
	DR_SEG_GS, /**< The "gs" register. */
	/* debug & control registers (privileged access only; 8-15 for future processors)
	 */
	DR_REG_DR0,  /**< The "dr0" register. */
	DR_REG_DR1,  /**< The "dr1" register. */
	DR_REG_DR2,  /**< The "dr2" register. */
	DR_REG_DR3,  /**< The "dr3" register. */
	DR_REG_DR4,  /**< The "dr4" register. */
	DR_REG_DR5,  /**< The "dr5" register. */
	DR_REG_DR6,  /**< The "dr6" register. */
	DR_REG_DR7,  /**< The "dr7" register. */
	DR_REG_DR8,  /**< The "dr8" register. */
	DR_REG_DR9,  /**< The "dr9" register. */
	DR_REG_DR10, /**< The "dr10" register. */
	DR_REG_DR11, /**< The "dr11" register. */
	DR_REG_DR12, /**< The "dr12" register. */
	DR_REG_DR13, /**< The "dr13" register. */
	DR_REG_DR14, /**< The "dr14" register. */
	DR_REG_DR15, /**< The "dr15" register. */
	/* cr9-cr15 do not yet exist on current x64 hardware */
	DR_REG_CR0,  /**< The "cr0" register. */
	DR_REG_CR1,  /**< The "cr1" register. */
	DR_REG_CR2,  /**< The "cr2" register. */
	DR_REG_CR3,  /**< The "cr3" register. */
	DR_REG_CR4,  /**< The "cr4" register. */
	DR_REG_CR5,  /**< The "cr5" register. */
	DR_REG_CR6,  /**< The "cr6" register. */
	DR_REG_CR7,  /**< The "cr7" register. */
	DR_REG_CR8,  /**< The "cr8" register. */
	DR_REG_CR9,  /**< The "cr9" register. */
	DR_REG_CR10, /**< The "cr10" register. */
	DR_REG_CR11, /**< The "cr11" register. */
	DR_REG_CR12, /**< The "cr12" register. */
	DR_REG_CR13, /**< The "cr13" register. */
	DR_REG_CR14, /**< The "cr14" register. */
	DR_REG_CR15, /**< The "cr15" register. */
	/* All registers above this point may be used as opnd_size_t and therefore
	 * need to fit into a byte (checked in d_r_arch_init()). Register enums
	 * below this point must not be used as opnd_size_t.
	 */
	DR_REG_MAX_AS_OPSZ = DR_REG_CR15, /**< The "cr15" register. */
	DR_REG_INVALID, /**< Sentinel value indicating an invalid register. */
	/* 256-BIT YMM */
	DR_REG_YMM0,  /**< The "ymm0" register. */
	DR_REG_YMM1,  /**< The "ymm1" register. */
	DR_REG_YMM2,  /**< The "ymm2" register. */
	DR_REG_YMM3,  /**< The "ymm3" register. */
	DR_REG_YMM4,  /**< The "ymm4" register. */
	DR_REG_YMM5,  /**< The "ymm5" register. */
	DR_REG_YMM6,  /**< The "ymm6" register. */
	DR_REG_YMM7,  /**< The "ymm7" register. */
	DR_REG_YMM8,  /**< The "ymm8" register. */
	DR_REG_YMM9,  /**< The "ymm9" register. */
	DR_REG_YMM10, /**< The "ymm10" register. */
	DR_REG_YMM11, /**< The "ymm11" register. */
	DR_REG_YMM12, /**< The "ymm12" register. */
	DR_REG_YMM13, /**< The "ymm13" register. */
	DR_REG_YMM14, /**< The "ymm14" register. */
	DR_REG_YMM15, /**< The "ymm15" register. */
	DR_REG_YMM16, /**< The "ymm16" register. */
	DR_REG_YMM17, /**< The "ymm17" register. */
	DR_REG_YMM18, /**< The "ymm18" register. */
	DR_REG_YMM19, /**< The "ymm19" register. */
	DR_REG_YMM20, /**< The "ymm20" register. */
	DR_REG_YMM21, /**< The "ymm21" register. */
	DR_REG_YMM22, /**< The "ymm22" register. */
	DR_REG_YMM23, /**< The "ymm23" register. */
	DR_REG_YMM24, /**< The "ymm24" register. */
	DR_REG_YMM25, /**< The "ymm25" register. */
	DR_REG_YMM26, /**< The "ymm26" register. */
	DR_REG_YMM27, /**< The "ymm27" register. */
	DR_REG_YMM28, /**< The "ymm28" register. */
	DR_REG_YMM29, /**< The "ymm29" register. */
	DR_REG_YMM30, /**< The "ymm30" register. */
	DR_REG_YMM31, /**< The "ymm31" register. */
	/* 32 enums are reserved for future Intel SIMD extensions. */
	RESERVED_YMM = DR_REG_YMM31 + 32,
	/* 512-BIT ZMM */
	DR_REG_ZMM0,  /**< The "zmm0" register. */
	DR_REG_ZMM1,  /**< The "zmm1" register. */
	DR_REG_ZMM2,  /**< The "zmm2" register. */
	DR_REG_ZMM3,  /**< The "zmm3" register. */
	DR_REG_ZMM4,  /**< The "zmm4" register. */
	DR_REG_ZMM5,  /**< The "zmm5" register. */
	DR_REG_ZMM6,  /**< The "zmm6" register. */
	DR_REG_ZMM7,  /**< The "zmm7" register. */
	DR_REG_ZMM8,  /**< The "zmm8" register. */
	DR_REG_ZMM9,  /**< The "zmm9" register. */
	DR_REG_ZMM10, /**< The "zmm10" register. */
	DR_REG_ZMM11, /**< The "zmm11" register. */
	DR_REG_ZMM12, /**< The "zmm12" register. */
	DR_REG_ZMM13, /**< The "zmm13" register. */
	DR_REG_ZMM14, /**< The "zmm14" register. */
	DR_REG_ZMM15, /**< The "zmm15" register. */
	DR_REG_ZMM16, /**< The "zmm16" register. */
	DR_REG_ZMM17, /**< The "zmm17" register. */
	DR_REG_ZMM18, /**< The "zmm18" register. */
	DR_REG_ZMM19, /**< The "zmm19" register. */
	DR_REG_ZMM20, /**< The "zmm20" register. */
	DR_REG_ZMM21, /**< The "zmm21" register. */
	DR_REG_ZMM22, /**< The "zmm22" register. */
	DR_REG_ZMM23, /**< The "zmm23" register. */
	DR_REG_ZMM24, /**< The "zmm24" register. */
	DR_REG_ZMM25, /**< The "zmm25" register. */
	DR_REG_ZMM26, /**< The "zmm26" register. */
	DR_REG_ZMM27, /**< The "zmm27" register. */
	DR_REG_ZMM28, /**< The "zmm28" register. */
	DR_REG_ZMM29, /**< The "zmm29" register. */
	DR_REG_ZMM30, /**< The "zmm30" register. */
	DR_REG_ZMM31, /**< The "zmm31" register. */
	/* 32 enums are reserved for future Intel SIMD extensions. */
	RESERVED_ZMM = DR_REG_ZMM31 + 32,
	/* opmask registers */
	DR_REG_K0, /**< The "k0" register. */
	DR_REG_K1, /**< The "k1" register. */
	DR_REG_K2, /**< The "k2" register. */
	DR_REG_K3, /**< The "k3" register. */
	DR_REG_K4, /**< The "k4" register. */
	DR_REG_K5, /**< The "k5" register. */
	DR_REG_K6, /**< The "k6" register. */
	DR_REG_K7, /**< The "k7" register. */
	/* 8 enums are reserved for future Intel SIMD mask extensions. */
	RESERVED_OPMASK = DR_REG_K7 + 8,
	/* Bounds registers for MPX. */
	DR_REG_BND0, /**< The "bnd0" register. */
	DR_REG_BND1, /**< The "bnd1" register. */
	DR_REG_BND2, /**< The "bnd2" register. */
	DR_REG_BND3, /**< The "bnd3" register. */
};

enum InstrPredicate {
	DR_PRED_NONE, /**< No predicate is present. */
	DR_PRED_O,   /**< x86 condition: overflow (OF=1). */
	DR_PRED_NO,  /**< x86 condition: no overflow (OF=0). */
	DR_PRED_B,   /**< x86 condition: below (CF=1). */
	DR_PRED_NB,  /**< x86 condition: not below (CF=0). */
	DR_PRED_Z,   /**< x86 condition: zero (ZF=1). */
	DR_PRED_NZ,  /**< x86 condition: not zero (ZF=0). */
	DR_PRED_BE,  /**< x86 condition: below or equal (CF=1 or ZF=1). */
	DR_PRED_NBE, /**< x86 condition: not below or equal (CF=0 and ZF=0). */
	DR_PRED_S,   /**< x86 condition: sign (SF=1). */
	DR_PRED_NS,  /**< x86 condition: not sign (SF=0). */
	DR_PRED_P,   /**< x86 condition: parity (PF=1). */
	DR_PRED_NP,  /**< x86 condition: not parity (PF=0). */
	DR_PRED_L,   /**< x86 condition: less (SF != OF). */
	DR_PRED_NL,  /**< x86 condition: not less (SF=OF). */
	DR_PRED_LE,  /**< x86 condition: less or equal (ZF=1 or SF != OF). */
	DR_PRED_NLE, /**< x86 condition: not less or equal (ZF=0 and SF=OF). */
	/**
	 * x86 condition: special opcode-specific condition that depends on the
	 * values of the source operands.  Thus, unlike all of the other conditions,
	 * the source operands will be accessed even if the condition then fails
	 * and the destinations are not touched.  Any written eflags are
	 * unconditionally written, unlike regular destination operands.
	 */
	DR_PRED_COMPLEX,
	/* Aliases for XINST_CREATE_jump_cond() and other cross-platform routines. */
	DR_PRED_EQ = DR_PRED_Z,  /**< Condition code: equal. */
	DR_PRED_NE = DR_PRED_NZ, /**< Condition code: not equal. */
	DR_PRED_LT = DR_PRED_L,  /**< Condition code: signed less than. */
	/* DR_PRED_LE already matches aarchxx */
	DR_PRED_GT = DR_PRED_NLE, /**< Condition code: signed greater than. */
	DR_PRED_GE = DR_PRED_NL,  /**< Condition code: signed greater than or equal. */
};
/*
enum InstrPredicate {
	DR_PRED_NONE,//No predicate is present.
	DR_PRED_O,//x86 condition : overflow(OF = 1).
	DR_PRED_NO,//x86 condition : no overflow(OF = 0).
	DR_PRED_B,//x86 condition : below(CF = 1).
	DR_PRED_NB,//x86 condition : not below(CF = 0).
	DR_PRED_Z,//x86 condition : zero(ZF = 1).
	DR_PRED_NZ,//x86 condition : not zero(ZF = 0).
	DR_PRED_BE,//x86 condition : below or equal(CF = 1 or ZF = 1).
	DR_PRED_NBE,//x86 condition : not below or equal(CF = 0 and ZF = 0).
	DR_PRED_S,//x86 condition : sign(SF = 1).
	DR_PRED_NS,//x86 condition : not sign(SF = 0).
	DR_PRED_P,//x86 condition : parity(PF = 1).
	DR_PRED_NP,//x86 condition : not parity(PF = 0).
	DR_PRED_L,//x86 condition : less(SF != OF).
	DR_PRED_NL,//x86 condition : not less(SF = OF).
	DR_PRED_LE,//x86 condition : less or equal(ZF = 1 or SF != OF),ARM condition : 1101 Signed <= (Z == 1 or N != V)
	DR_PRED_NLE,//x86 condition : not less or equal(ZF = 0 and SF = OF).
	
	DR_PRED_COMPLEX,//x86 condition : special opcode - specific condition that depends on the values of the source operands.Thus, unlike all of the other conditions, the source operands will be accessed even if the condition then fails and the destinations are not touched.Any written eflags are unconditionally written, unlike regular destination operands.

	DR_PRED_EQ,//Condition code : equal,ARM condition : 0000 Equal(Z == 1)
	DR_PRED_NE,//Condition code : not equal,ARM condition : 0001 Not equal(Z == 0)
	DR_PRED_LT,//Condition code : signed less than,ARM condition : 1011 Signed less than(N != V)
	DR_PRED_GT,//Condition code : signed greater than,ARM condition : 1100 Signed greater than(Z == 0 and N == V)
	DR_PRED_GE,//Condition code : signed greater than or equal,ARM condition : 1010 Signed >= (N == V)

//	DR_PRED_CS,//ARM condition : 0010 Carry set(C == 1)
//	DR_PRED_CC,//ARM condition : 0011 Carry clear(C == 0)
//	DR_PRED_MI,//ARM condition : 0100 Minus, negative(N == 1)
//	DR_PRED_PL,//ARM condition : 0101 Plus, positive or zero(N == 0)
//	DR_PRED_VS,//ARM condition : 0110 Overflow(V == 1)
//	DR_PRED_VC,//ARM condition : 0111 No overflow(V == 0)
//	DR_PRED_HI,//ARM condition : 1000 Unsigned higher(C == 1 and Z == 0)
//	DR_PRED_LS,//ARM condition : 1001 Unsigned lower or same(C == 1 or Z == 0)
//	DR_PRED_AL,//ARM condition : 1110 Always(unconditional)
//	DR_PRED_NV,//ARM condition : 1111 Never, meaning always
//	DR_PRED_OP,//ARM condition : 1111 Part of opcode
//	DR_PRED_HS,//ARM condition : alias for DR_PRED_CS.
//	DR_PRED_LO,//ARM condition : alias for DR_PRED_CC.
	DR_PRED_SVE_NONE,//0000 All active elements were false or no active elements(Z == 1)
	DR_PRED_SVE_ANY,//0001 An active element was true (Z == 0)
	DR_PRED_SVE_NLAST,//0010 Last active element was false or no active elements(C == 1)
	DR_PRED_SVE_LAST,//0011 Last active element was true (C == 0)
	DR_PRED_SVE_FIRST,//0100 First active element was true (N == 1)
	DR_PRED_SVE_NFRST,//0101 First active element was false or no active elements(N == 0)
	DR_PRED_SVE_PLAST,//1001 Last active element was true, all active elements were false, or no active elements(C == 1 or Z == 0)
	DR_PRED_SVE_TCONT,//1010 CTERM termination condition not detected, continue loop(N == V)
	DR_PRED_SVE_TSTOP,
};
*/

//void y_assert(bool cond);

void y_assert(bool cond, const std::string& info, const char* file_info, int line);

template <typename K, typename V>
class YMapUtil {

public:

	static bool specified_range_cover_some_key_in_map(K k_min, K k_max, std::map<K, V>& mp) {
		bool has_ele_in_range = false;
		auto low_it = mp.lower_bound(k_min);
		if (low_it != mp.end()) {
			K low_it_k = low_it->first;
			if (low_it_k < k_max) {
				has_ele_in_range = true;
			}
		}
		return has_ele_in_range;
	}

};

class FileReadContent {

public:

	byte* addr;
	size_t rlen;

	FileReadContent() {
		this->addr = NULL;
		this->rlen = 0;
	}

	FileReadContent(byte* addr, size_t rlen) {
		this->addr = addr;
		this->rlen = rlen;
	}

	FileReadContent(FileReadContent* fri) {
		this->rlen = fri->rlen;
		this->addr = new byte[fri->rlen];
		memcpy_s(this->addr, this->rlen, fri->addr, fri->rlen);
	}

	~FileReadContent() {
		if (addr != NULL) {
			delete[] addr;
		}
	}

};

class YFileUtil {

public:

	static void read_whole_file(const std::string& path, FileReadContent* fri) {
		std::fstream tf(path, std::ios::in);
		if (!tf) {
			std::cout << "Wrong, I can't open the tf file:" << path << ";" << std::endl;
			y_assert(false, "file cannot open", __FILE__, __LINE__);
		}
		else {
			tf.seekg(0, std::ios::end);
			std::ifstream::pos_type filesize = tf.tellg();
			tf.seekg(0);
			char* buffer = new char[filesize];
			tf.read(buffer, filesize);

			tf.close();
			fri->addr = (byte*)buffer;
			fri->rlen = filesize;
		}
	}

	static void write_whole_file(std::string& path, FileReadContent* fri) {
		std::fstream tf(path, std::ios::out);
		if (!tf) {
			std::cout << "Wrong, I can't open the tf file:" << path << ";" << std::endl;
		}
		else {
//			tf.seekg(0);
			tf.write((char*) fri->addr, fri->rlen);
			tf.close();
		}
	}

};

class YStringUtil {
	
public:

	static int replace_all(std::string& str, const std::string& pattern, const std::string& newpat)
	{
		int count = 0;
		const size_t nsize = newpat.size();
		const size_t psize = pattern.size();

		for (size_t pos = str.find(pattern, 0); pos != std::string::npos; pos = str.find(pattern, pos + nsize))
		{
			str.replace(pos, psize, newpat);
			count++;
		}
		return count;
	}

	static int startsWith(const std::string& s, const std::string& sub) {
		return s.find(sub) == 0 ? 1 : 0;
	}

	static int endsWith(const std::string& s, const std::string& sub) {
		return s.rfind(sub) == (s.length() - sub.length()) ? 1 : 0;
	}

	static std::string getContentAfterLastAppearOfSpecified(const std::string& path, const std::string& pattern) {
		auto last_appear = path.find_last_of(pattern);
//		std::string::size_type iPos = (last_appear + 1) == 0 ? last_appear + 1 : last_appear + 1;
		std::string::size_type iPos = (last_appear + 1);
		std::string ImgName = path.substr(iPos, path.length() - iPos);
		return ImgName;
	}

	static void toUpperCase(std::string& source) {
		std::transform(source.begin(), source.end(), source.begin(), ::toupper);
	}

	static void toLowerCase(std::string& source) {
		std::transform(source.begin(), source.end(), source.begin(), ::tolower);
	}

};

class YTimeUtil {

public:

	static std::string getCurrTimeString() {
		time_t t = time(NULL);
		struct tm* tmv = localtime(&t);
		char str_time[32];
		strftime(str_time, 32, "%Y-%m-%d_%H-%M-%S", tmv);
		return std::string(str_time);
	}

};

class YPrintUtil{

public:

	template<typename K, typename V>
	static std::string print_to_string(std::map<K, V>& mp) {
		std::stringstream ss;
		
		ss << "{";
		for (auto it = mp->begin(); it != mp->end(); it++) {
			ss << "{" << it->first << ":" << it->second << "}" << ",";
		}
		ss << "}";

		return ss.str();
	}
	
	template<typename V>
	static std::string print_to_string(std::set<V>& st) {
		std::stringstream ss;

		ss << "{";
		for (auto it = st.begin(); it != st.end(); it++) {
			ss << *it << ",";
		}
		ss << "}";

		return ss.str();
	}

};

int get_return_dr_reg_size_in_bytes(uint16_t reg_id);

template<typename V>
bool is_overflow(V final_opnd, V first_opnd) {
	bool overflow = false;

	bool has_inf = (std::numeric_limits<V>::has_infinity);
	if (has_inf) {
		bool equal_inf = (std::numeric_limits<V>::infinity)() == abs(final_opnd);
		if (equal_inf) {
			overflow = true;
		}
	}
	else {
		if (final_opnd == 0 || first_opnd == 0) {
			// do nothing. 
		}
		else {
			bool gap_value_sign_positive = final_opnd > 0;
			bool first_value_sign_positive = first_opnd > 0;
			if ((gap_value_sign_positive xor first_value_sign_positive) == 1) {
				// overflow happens
				overflow = true;
			}
		}
	}
	return overflow;
}

template<typename V>
std::vector<V> vector_slicing(std::vector<V>& arr, size_t X, size_t Len)
{
	// Starting and Ending iterators
	auto start = arr.begin() + X;
	auto end = start + Len;

	std::vector<V> vect(start, end);

	// Return the final sliced vector
	return vect;
}








