/*
 * lbn960jx.h - This file defines the interfaces to assembly primitives
 * for the the Intel i960Jx series of processors.  In fact, these thould
 * work on any i960 series processor, but haven't been tested.
 * It is intended to be included in "lbn.h"
 * via the "#include BNINCLUDE" mechanism.
 */
 
#define BN_LITTLE_ENDIAN 1

typedef unsigned long bnword32;
#define BNWORD32 bnword32;


#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for the asm routines */
void
lbnMulN1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#define lbnMulN1_32 lbnMulN1_32
            
BNWORD32
lbnMulAdd1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#define lbnMulAdd1_32 lbnMulAdd1_32
       
BNWORD32
lbnMulSub1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#define lbnMulSub1_32 lbnMulSub1_32

#ifdef __cplusplus
}
#endif
