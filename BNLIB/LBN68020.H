/*
 * lbn68020.h - 32-bit bignum primitives for the 68020 (or 683xx) processors.
 *
 * These primitives use little-endian word order.
 * (The order of bytes within words is irrelevant.)
 */
#define BN_LITTLE_ENDIAN 1

#ifdef __cplusplus
extern "C" {
#endif

unsigned long lbnSub1_32(unsigned long *num, unsigned len, unsigned long borrow);
unsigned long lbnAdd1_32(unsigned long *num, unsigned len, unsigned long carry);
void
lbnMulN1_32(unsigned long *out, unsigned long const *in, unsigned len, unsigned long k);
unsigned long
lbnMulAdd1_32(unsigned long *out, unsigned long const *in, unsigned len, unsigned long k);
unsigned long
lbnMulSub1_32(unsigned long *out, unsigned long const *in, unsigned len, unsigned long k);
unsigned long
lbnDiv21_32(unsigned long *q, unsigned long nh, unsigned long nl, unsigned long d);
unsigned lbnModQ_32(unsigned long const *n, unsigned len, unsigned d);

#ifdef __cplusplus
}
#endif

/* #define the values to exclude the C versions */
#define lbnSub1_32 lbnSub1_32
#define lbnAdd1_32 lbnAdd1_32
#define lbnMulN1_32 lbnMulN1_32
#define lbnMulAdd1_32 lbnMulAdd1_32
#define lbnMulSub1_32 lbnMulSub1_32
#define lbnDiv21_32 lbnDiv21_32
#define lbnModQ_32 lbnModQ_32
