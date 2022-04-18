//go:build gc && !purego

#include "textflag.h"
#include "go_asm.h"

// AESE_AESMC performs AESE and AESMC.
//
// The instructions are paried to take advantage of instruction
// fusion.
#define AESE_AESMC(rk, v) \
	AESE  rk.B16, v.B16 \
	AESMC v.B16, v.B16

#define ENCRYPT256x1(v0, rk1, rk2, rk3, rk4) \
	AESE_AESMC(rk1, v0) \
	AESE_AESMC(rk2, v0) \
	AESE_AESMC(rk3, v0) \
	AESE_AESMC(rk4, v0)

#define ENCRYPT128x1(v0, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14, rk15) \
	AESE_AESMC(rk5, v0)           \
	AESE_AESMC(rk6, v0)           \
	AESE_AESMC(rk7, v0)           \
	AESE_AESMC(rk8, v0)           \
	AESE_AESMC(rk9, v0)           \
	AESE_AESMC(rk10, v0)          \
	AESE_AESMC(rk11, v0)          \
	AESE_AESMC(rk12, v0)          \
	AESE_AESMC(rk13, v0)          \
	AESE rk14.B16, v0.B16         \
	VEOR v0.B16, rk15.B16, v0.B16

#define ENCRYPT256x8(v0, v1, v2, v3, v4, v5, v6, v7, rk1, rk2, rk3, rk4) \
	AESE_AESMC(rk1, v0) \
	AESE_AESMC(rk1, v1) \
	AESE_AESMC(rk1, v2) \
	AESE_AESMC(rk1, v3) \
	AESE_AESMC(rk1, v4) \
	AESE_AESMC(rk1, v5) \
	AESE_AESMC(rk1, v6) \
	AESE_AESMC(rk1, v7) \
	                    \
	AESE_AESMC(rk2, v0) \
	AESE_AESMC(rk2, v1) \
	AESE_AESMC(rk2, v2) \
	AESE_AESMC(rk2, v3) \
	AESE_AESMC(rk2, v4) \
	AESE_AESMC(rk2, v5) \
	AESE_AESMC(rk2, v6) \
	AESE_AESMC(rk2, v7) \
	                    \
	AESE_AESMC(rk3, v0) \
	AESE_AESMC(rk3, v1) \
	AESE_AESMC(rk3, v2) \
	AESE_AESMC(rk3, v3) \
	AESE_AESMC(rk3, v4) \
	AESE_AESMC(rk3, v5) \
	AESE_AESMC(rk3, v6) \
	AESE_AESMC(rk3, v7) \
	                    \
	AESE_AESMC(rk4, v0) \
	AESE_AESMC(rk4, v1) \
	AESE_AESMC(rk4, v2) \
	AESE_AESMC(rk4, v3) \
	AESE_AESMC(rk4, v4) \
	AESE_AESMC(rk4, v5) \
	AESE_AESMC(rk4, v6) \
	AESE_AESMC(rk4, v7)

#define ENCRYPT128x8(v0, v1, v2, v3, v4, v5, v6, v7, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14, rk15) \
	AESE_AESMC(rk5, v0)           \
	AESE_AESMC(rk5, v1)           \
	AESE_AESMC(rk5, v2)           \
	AESE_AESMC(rk5, v3)           \
	AESE_AESMC(rk5, v4)           \
	AESE_AESMC(rk5, v5)           \
	AESE_AESMC(rk5, v6)           \
	AESE_AESMC(rk5, v7)           \
	                              \
	AESE_AESMC(rk6, v0)           \
	AESE_AESMC(rk6, v1)           \
	AESE_AESMC(rk6, v2)           \
	AESE_AESMC(rk6, v3)           \
	AESE_AESMC(rk6, v4)           \
	AESE_AESMC(rk6, v5)           \
	AESE_AESMC(rk6, v6)           \
	AESE_AESMC(rk6, v7)           \
	                              \
	AESE_AESMC(rk7, v0)           \
	AESE_AESMC(rk7, v1)           \
	AESE_AESMC(rk7, v2)           \
	AESE_AESMC(rk7, v3)           \
	AESE_AESMC(rk7, v4)           \
	AESE_AESMC(rk7, v5)           \
	AESE_AESMC(rk7, v6)           \
	AESE_AESMC(rk7, v7)           \
	                              \
	AESE_AESMC(rk8, v0)           \
	AESE_AESMC(rk8, v1)           \
	AESE_AESMC(rk8, v2)           \
	AESE_AESMC(rk8, v3)           \
	AESE_AESMC(rk8, v4)           \
	AESE_AESMC(rk8, v5)           \
	AESE_AESMC(rk8, v6)           \
	AESE_AESMC(rk8, v7)           \
	                              \
	AESE_AESMC(rk9, v0)           \
	AESE_AESMC(rk9, v1)           \
	AESE_AESMC(rk9, v2)           \
	AESE_AESMC(rk9, v3)           \
	AESE_AESMC(rk9, v4)           \
	AESE_AESMC(rk9, v5)           \
	AESE_AESMC(rk9, v6)           \
	AESE_AESMC(rk9, v7)           \
	                              \
	AESE_AESMC(rk10, v0)          \
	AESE_AESMC(rk10, v1)          \
	AESE_AESMC(rk10, v2)          \
	AESE_AESMC(rk10, v3)          \
	AESE_AESMC(rk10, v4)          \
	AESE_AESMC(rk10, v5)          \
	AESE_AESMC(rk10, v6)          \
	AESE_AESMC(rk10, v7)          \
	                              \
	AESE_AESMC(rk11, v0)          \
	AESE_AESMC(rk11, v1)          \
	AESE_AESMC(rk11, v2)          \
	AESE_AESMC(rk11, v3)          \
	AESE_AESMC(rk11, v4)          \
	AESE_AESMC(rk11, v5)          \
	AESE_AESMC(rk11, v6)          \
	AESE_AESMC(rk11, v7)          \
	                              \
	AESE_AESMC(rk12, v0)          \
	AESE_AESMC(rk12, v1)          \
	AESE_AESMC(rk12, v2)          \
	AESE_AESMC(rk12, v3)          \
	AESE_AESMC(rk12, v4)          \
	AESE_AESMC(rk12, v5)          \
	AESE_AESMC(rk12, v6)          \
	AESE_AESMC(rk12, v7)          \
	                              \
	AESE_AESMC(rk13, v0)          \
	AESE_AESMC(rk13, v1)          \
	AESE_AESMC(rk13, v2)          \
	AESE_AESMC(rk13, v3)          \
	AESE_AESMC(rk13, v4)          \
	AESE_AESMC(rk13, v5)          \
	AESE_AESMC(rk13, v6)          \
	AESE_AESMC(rk13, v7)          \
	                              \
	AESE rk14.B16, v0.B16         \
	AESE rk14.B16, v1.B16         \
	AESE rk14.B16, v2.B16         \
	AESE rk14.B16, v3.B16         \
	AESE rk14.B16, v4.B16         \
	AESE rk14.B16, v5.B16         \
	AESE rk14.B16, v6.B16         \
	AESE rk14.B16, v7.B16         \
	                              \
	VEOR v0.B16, rk15.B16, v0.B16 \
	VEOR v1.B16, rk15.B16, v1.B16 \
	VEOR v2.B16, rk15.B16, v2.B16 \
	VEOR v3.B16, rk15.B16, v3.B16 \
	VEOR v4.B16, rk15.B16, v4.B16 \
	VEOR v5.B16, rk15.B16, v5.B16 \
	VEOR v6.B16, rk15.B16, v6.B16 \
	VEOR v7.B16, rk15.B16, v7.B16

// func aesctrAsm(nr int, enc *uint32, iv *[blockSize]byte, dst, src *byte, nblocks int)
TEXT ·aesctrAsm(SB), NOSPLIT, $0-48
#define nrounds R0
#define enc_ptr R1
#define dst_ptr R2
#define src_ptr R3
#define remain R4
#define block_ptr R5
#define nwide R6
#define nsingle R7

#define idx0 R8
#define idx1 R9
#define idx2 R10
#define idx3 R11
#define idx4 R12
#define idx5 R13
#define idx6 R14
#define idx7 R15

#define block V0

#define rk1 V1
#define rk2 V2
#define rk3 V3
#define rk4 V4
#define rk5 V5
#define rk6 V6
#define rk7 V7
#define rk8 V8
#define rk9 V9
#define rk10 V10
#define rk11 V11
#define rk12 V12
#define rk13 V13
#define rk14 V14
#define rk15 V15

#define src0 V16
#define src1 V17
#define src2 V18
#define src3 V19
#define src4 V20
#define src5 V21
#define src6 V22
#define src7 V23

#define ks0 V24
#define ks1 V25
#define ks2 V26
#define ks3 V27
#define ks4 V28
#define ks5 V29
#define ks6 V30
#define ks7 V31

	MOVD nr+0(FP), nrounds
	MOVD enc+8(FP), enc_ptr
	MOVD nblocks+40(FP), remain
	MOVD iv+16(FP), block_ptr
	MOVD dst+24(FP), dst_ptr
	MOVD src+32(FP), src_ptr

	VLD1 (block_ptr), [block.B16]

loadKeys:
	CMP $12, nrounds
	BLT load128

load256:
	VLD1.P 64(enc_ptr), [rk1.B16, rk2.B16, rk3.B16, rk4.B16]

load128:
	VLD1.P 64(enc_ptr), [rk5.B16, rk6.B16, rk7.B16, rk8.B16]
	VLD1.P 64(enc_ptr), [rk9.B16, rk10.B16, rk11.B16, rk12.B16]
	VLD1.P 48(enc_ptr), [rk13.B16, rk14.B16, rk15.B16]

initLoops:
	MOVD ZR, idx0
	VMOV block.S[0], idx0

initSingleLoop:
#ifdef const_useMultiBlock
	ANDS $7, remain, nsingle
	BEQ  initWideLoop

#else
	MOVD remain, nsingle

#endif // const_useMultiBlock

// Handle any blocks in excess of the stride.
singleLoop:
	VLD1.P 16(src_ptr), [src0.B16]

	VMOV block.B16, ks0.B16

	CMP $12, nrounds
	BLT enc128x1

enc256x1:
	ENCRYPT256x1(ks0, rk1, rk2, rk3, rk4)

enc128x1:
	ENCRYPT128x1(ks0, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14, rk15)

	ADD  $1, idx0
	VMOV idx0, block.S[0]

	VEOR   ks0.B16, src0.B16, src0.B16
	VST1.P [src0.B16], 16(dst_ptr)

	SUBS $1, nsingle
	BNE  singleLoop

#ifndef const_useMultiBlock
	B done

#endif // const_useMultiBlock

initWideLoop:
	ASR $3, remain, nwide
	CBZ nwide, done

	// Now handle the full stride.
wideLoop:
	ADD $1, idx0, idx1
	ADD $2, idx0, idx2
	ADD $3, idx0, idx3
	ADD $4, idx0, idx4
	ADD $5, idx0, idx5
	ADD $6, idx0, idx6
	ADD $7, idx0, idx7

	VMOV block.B16, ks0.B16
	VMOV idx0, ks0.S[0]
	VMOV block.B16, ks1.B16
	VMOV idx1, ks1.S[0]
	VMOV block.B16, ks2.B16
	VMOV idx2, ks2.S[0]
	VMOV block.B16, ks3.B16
	VMOV idx3, ks3.S[0]
	VMOV block.B16, ks4.B16
	VMOV idx4, ks4.S[0]
	VMOV block.B16, ks5.B16
	VMOV idx5, ks5.S[0]
	VMOV block.B16, ks6.B16
	VMOV idx6, ks6.S[0]
	VMOV block.B16, ks7.B16
	VMOV idx7, ks7.S[0]

	VLD1.P 64(src_ptr), [src0.B16, src1.B16, src2.B16, src3.B16]
	VLD1.P 64(src_ptr), [src4.B16, src5.B16, src6.B16, src7.B16]

	CMP $12, nrounds
	BLT enc128x8

enc256x8:
	ENCRYPT256x8(ks0, ks1, ks2, ks3, ks4, ks5, ks6, ks7, rk1, rk2, rk3, rk4)

enc128x8:
	ENCRYPT128x8(ks0, ks1, ks2, ks3, ks4, ks5, ks6, ks7, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14, rk15)

	VEOR ks0.B16, src0.B16, src0.B16
	VEOR ks1.B16, src1.B16, src1.B16
	VEOR ks2.B16, src2.B16, src2.B16
	VEOR ks3.B16, src3.B16, src3.B16
	VEOR ks4.B16, src4.B16, src4.B16
	VEOR ks5.B16, src5.B16, src5.B16
	VEOR ks6.B16, src6.B16, src6.B16
	VEOR ks7.B16, src7.B16, src7.B16

	VST1.P [src0.B16, src1.B16, src2.B16, src3.B16], 64(dst_ptr)
	VST1.P [src4.B16, src5.B16, src6.B16, src7.B16], 64(dst_ptr)

	ADD  $8, idx0
	SUBS $1, nwide
	BNE  wideLoop

done:
	// Clear the registers.
	VEOR block.B16, block.B16, block.B16

	VEOR src0.B16, src0.B16, src0.B16
	VEOR src1.B16, src1.B16, src1.B16
	VEOR src2.B16, src2.B16, src2.B16
	VEOR src3.B16, src3.B16, src3.B16

	VEOR ks0.B16, ks0.B16, ks0.B16
	VEOR ks1.B16, ks1.B16, ks1.B16
	VEOR ks2.B16, ks2.B16, ks2.B16
	VEOR ks3.B16, ks3.B16, ks3.B16

#ifdef const_useMultiBlock
	VEOR src4.B16, src4.B16, src4.B16
	VEOR src5.B16, src5.B16, src5.B16
	VEOR src6.B16, src6.B16, src6.B16
	VEOR src7.B16, src7.B16, src7.B16

	VEOR ks4.B16, ks4.B16, ks4.B16
	VEOR ks5.B16, ks5.B16, ks5.B16
	VEOR ks6.B16, ks6.B16, ks6.B16
	VEOR ks7.B16, ks7.B16, ks7.B16

#endif

	VEOR rk1.B16, rk1.B16, rk1.B16
	VEOR rk2.B16, rk2.B16, rk2.B16
	VEOR rk3.B16, rk3.B16, rk3.B16
	VEOR rk4.B16, rk4.B16, rk4.B16
	VEOR rk5.B16, rk5.B16, rk5.B16
	VEOR rk6.B16, rk6.B16, rk6.B16
	VEOR rk7.B16, rk7.B16, rk7.B16
	VEOR rk8.B16, rk8.B16, rk8.B16
	VEOR rk9.B16, rk9.B16, rk9.B16
	VEOR rk10.B16, rk10.B16, rk10.B16
	VEOR rk11.B16, rk11.B16, rk11.B16
	VEOR rk12.B16, rk12.B16, rk12.B16
	VEOR rk13.B16, rk13.B16, rk13.B16
	VEOR rk14.B16, rk14.B16, rk14.B16
	VEOR rk15.B16, rk15.B16, rk15.B16

	RET
