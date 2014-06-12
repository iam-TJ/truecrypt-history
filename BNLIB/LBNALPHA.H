/*
 * lbnalpha.h - header file that declares the Alpha assembly-language
 * subroutines.  It is intended to be included via the BNINCLUDE
 * mechanism.
 */

#define BN_LITTLE_ENDIAN 1

#ifdef __cplusplus
extern "C" {
#endif

void lbnMulN1_64(unsigned long *out, unsigned long const *in, unsigned len,
	unsigned long k);
#define lbnMulN1_64 lbnMulN1_64

unsigned long lbnMulAdd1_64(unsigned long *out, unsigned long const *in,
	unsigned len, unsigned long k);
#define lbnMulAdd1_64 lbnMulAdd1_64

unsigned long lbnMulSub1_64(unsigned long *out, unsigned long const *in,
	unsigned len, unsigned long k);
#define lbnMulSub1_64 lbnMulSub1_64

#ifdef __cplusplus
}
#endif
