/*
 * lbn68000.h - 16-bit bignum primitives for the 68000 (or 68010) processors.
 *
 * These primitives use little-endian word order.
 * (The order of bytes within words is irrelevant.)
 */
#define BN_LITTLE_ENDIAN 1

#ifdef __cplusplus
extern "C" {
#endif

unsigned short lbnSub1_16(unsigned short *num, unsigned len, unsigned short borrow);
unsigned short lbnAdd1_16(unsigned short *num, unsigned len, unsigned short carry);
void
lbnMulN1_16(unsigned short *out, unsigned short const *in, unsigned len, unsigned short k);
unsigned short
lbnMulAdd1_16(unsigned short *out, unsigned short const *in, unsigned len, unsigned short k);
unsigned short
lbnMulSub1_16(unsigned short *out, unsigned short const *in, unsigned len, unsigned short k);
unsigned short
lbnDiv21_16(unsigned short *q, unsigned short nh, unsigned short nl, unsigned short d);
unsigned lbnModQ_16(unsigned short const *n, unsigned len, unsigned short d);

int is68020(void);

#ifdef __cplusplus
}
#endif

/* #define the values to exclude the C versions */
#define lbnSub1_16 lbnSub1_16
#define lbnAdd1_16 lbnAdd1_16
#define lbnMulN1_16 lbnMulN1_16
#define lbnMulAdd1_16 lbnMulAdd1_16
#define lbnMulSub1_16 lbnMulSub1_16
#define lbnDiv21_16 lbnDiv21_16
#define lbnModQ_16 lbnModQ_16

/* Also include the 68020 definitions for 16/32 bit switching versions. */
#include <lbn68020.h>
