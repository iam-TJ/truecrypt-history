/*
 * The Square block cipher.
 *
 * Algorithm developed by Joan Daemen <Daemen.J@banksys.com> and
 * Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *
 * This public domain implementation by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> and George Barwood <george.barwood@dial.pipex.com>
 * based on software originally written by Vincent Rijmen.
 *
 * Caveat: this code assumes 32-bit words and probably will not work
 * otherwise.
 *
 * Version 2.6 (1997.04.29)
 *
 * =============================================================================
 *
 * Differences from version 2.5 (1997.04.25)
 *
 * - Improved key scheduling setup to enhance hashing performance.  Modules
 *   sqgen.c and sqtest.c have been updated accordingly.  The new scheme
 *   (suggested by Vincent Rijmen) uses tables instead of explicit GF(2^8)
 *   multiplications.  Increase in size of the generated code is very small.
 *
 * - Hashing scheme added.
 *
 * =============================================================================
 *
 * Differences from version 2.4 (1997.04.09):
 *
 * - Changed all initialization functions so that the IV (when applicable)
 *   is separately loaded.
 *
 * - Ciphertext Stealing (CTS) mode added.
 *
 * - Output Feedback (OFB) mode added.
 *
 * - Cipher Block Chaining (CBC) mode added.
 *
 * - Split square.c int several files according to the specific functionality
 *   (basic functions, modes, testing).
 *
 * - Flipped tables according to the endianness of the subjacent platform
 *   for best performance.
 *
 * - Changed "maketabs.c" to "sqgen.c" for compatibility with the Pegwit system.
 *
 * =============================================================================
 *
 * Differences from version 2.3 (1997.04.09):
 *
 * - Defined function squareExpandKey() to enhance performance of both CFB
 *   initialization and hash computation (not yet implemented).
 *
 * - Changed definition of function squareTransform() to accept a single in-out
 *   parameter, and optimized function squareGenerateRoundKeys accordingly.
 *
 * =============================================================================
 *
 * Differences from version 2.2 (1997.03.03):
 *
 * - Cipher feedback (CFB) mode added (heavily based on an old public domain CFB
 *   shell written by Colin Plumb for the IDEA cipher).
 *
 * - Fixed word size problem (64 bits rather than 32) arising on the Alpha.
 *
 * - Reformatted indented sections of compiler directives for use with old,
 *   non-ANSI compliant compilers.
 *
 * Differences from version 2.1 (1997.03.03):
 *
 * - Added optional Microsoft x86 assembler version, which can boost performance
 *   by up to 20% depending on the target machine, and generates smaller code.
 *
 * Differences from version 2.0 (1997.02.11):
 *
 * - Added typecasts to the build-up of out[] in function squareTransform()
 *   to make it portable to 16-bit (MSDOS) systems.
 *
 * - Truncated alogtab[] back to 256 elements and changed the mul() macro
 *   accordingly.  Using an extended table to avoid a division seemed an
 *   unnecessary storage overhead (it could be useful to speed up hash
 *   functions derived from Square, but other optimizations are likely to be
 *   more effective).
 *
 * Differences from version 2.0 (1997.02.11):
 *
 * - Updated definition of Square algorithm (version 1.0 implemented an
 *   embryonic form of Square).
 *
 * ==============================================================================
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <malloc.h>
#define UWORD unsigned short
#define UBYTE unsigned char
#include "square.h"

#ifndef R
#define R 8
#endif /* R */

#if R != 8
#error "This implementation is optimized for (and assumes) exactly 8 rounds"
#endif

#ifndef USUAL_TYPES
#       define USUAL_TYPES
	typedef unsigned char   sbyte;  /*  8 bit */
	typedef unsigned short  sword16;        /* 16 bit */
#       ifdef __alpha
	typedef unsigned int    sword32;        /* 32 bit */
#       else  /* !__alpha */
	typedef unsigned long   sword32;        /* 32 bit */
#       endif /* ?__alpha */
#endif /* ?USUAL_TYPES */


/* platform endianness: */
#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#       if defined(_M_IX86) || defined(_M_I86) || defined(__alpha)
#               define LITTLE_ENDIAN
#       else
#               error "Either LITTLE_ENDIAN or BIG_ENDIAN must be defined"
#       endif
#elif defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN)
#       error "LITTLE_ENDIAN and BIG_ENDIAN must not be simultaneously defined"
#endif /* !LITTLE_ENDIAN && !BIG_ENDIAN */


/* Microsoft C / Intel x86 optimizations: */
#if defined(_MSC_VER) && defined(_M_IX86) 
/* #     define HARDWARE_ROTATIONS */
#       define ASSEMBLER_CORE
#endif /* ?(_MSC_VER && _M_IX86) */

#ifdef HARDWARE_ROTATIONS
#       define SROTL(x, s) (_lrotl ((x), (s)))
#       define ROTR(x, s) (_lrotr ((x), (s)))
#else  /* !HARDWARE_ROTATIONS */
#       define SROTL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#       define ROTR(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
#endif /* ?HARDWARE_ROTATIONS */

#ifdef LITTLE_ENDIAN
#       ifdef MASKED_BYTE_EXTRACTION
#               define GETB0(x) (((x)      ) & 0xffU)
#               define GETB1(x) (((x) >>  8) & 0xffU)
#               define GETB2(x) (((x) >> 16) & 0xffU)
#               define GETB3(x) (((x) >> 24) & 0xffU)
#       else  /* !MASKED_BYTE_EXTRACTION */
#               define GETB0(x) ((sbyte)  ((x)      ))
#               define GETB1(x) ((sbyte)  ((x) >>  8))
#               define GETB2(x) ((sbyte)  ((x) >> 16))
#               define GETB3(x) ((sbyte)  ((x) >> 24))
#       endif /* ?MASKED_BYTE_EXTRACTION */
#       define PUTB0(x) ((sword32) (x)      )
#       define PUTB1(x) ((sword32) (x) <<  8)
#       define PUTB2(x) ((sword32) (x) << 16)
#       define PUTB3(x) ((sword32) (x) << 24)
#       define PSI_ROTL(x, s) ROTR(x, s)
#       define PSI_ROTR(x, s) SROTL(x, s)
#else  /* !LITTLE_ENDIAN */
#       ifdef MASKED_BYTE_EXTRACTION
#               define GETB0(x) (((x) >> 24) & 0xffU)
#               define GETB1(x) (((x) >> 16) & 0xffU)
#               define GETB2(x) (((x) >>  8) & 0xffU)
#               define GETB3(x) (((x)      ) & 0xffU)
#       else  /* !MASKED_BYTE_EXTRACTION */
#               define GETB0(x) ((sbyte)  ((x) >> 24))
#               define GETB1(x) ((sbyte)  ((x) >> 16))
#               define GETB2(x) ((sbyte)  ((x) >>  8))
#               define GETB3(x) ((sbyte)  ((x)      ))
#       endif /* ?MASKED_BYTE_EXTRACTION */
#       define PUTB0(x) ((sword32) (x) << 24)
#       define PUTB1(x) ((sword32) (x) << 16)
#       define PUTB2(x) ((sword32) (x) <<  8)
#       define PUTB3(x) ((sword32) (x)      )
#       define PSI_ROTL(x, s) SROTL(x, s)
#       define PSI_ROTR(x, s) ROTR(x, s)
#endif /* ?LITTLE_ENDIAN */


#include "squareb.h"


#define mul(a, b) ((a && b) ? alogtab[(mtemp = logtab[a] + logtab[b]) >= 255 ? mtemp - 255 : mtemp] : 0)

#define D(p) ((sword32 *)(p))

#define COPY_BLOCK(target, source) \
{ \
	(target)[0] = (source)[0]; \
	(target)[1] = (source)[1]; \
	(target)[2] = (source)[2]; \
	(target)[3] = (source)[3]; \
} /* COPY_BLOCK */


static void squareTransform (sword32 roundKey[4])
{
	roundKey[0] = phi[GETB0 (roundKey[0])] ^
		PSI_ROTR (phi[GETB1 (roundKey[0])],  8) ^
		PSI_ROTR (phi[GETB2 (roundKey[0])], 16) ^
		PSI_ROTR (phi[GETB3 (roundKey[0])], 24);
	roundKey[1] = phi[GETB0 (roundKey[1])] ^
		PSI_ROTR (phi[GETB1 (roundKey[1])],  8) ^
		PSI_ROTR (phi[GETB2 (roundKey[1])], 16) ^
		PSI_ROTR (phi[GETB3 (roundKey[1])], 24);
	roundKey[2] = phi[GETB0 (roundKey[2])] ^
		PSI_ROTR (phi[GETB1 (roundKey[2])],  8) ^
		PSI_ROTR (phi[GETB2 (roundKey[2])], 16) ^
		PSI_ROTR (phi[GETB3 (roundKey[2])], 24);
	roundKey[3] = phi[GETB0 (roundKey[3])] ^
		PSI_ROTR (phi[GETB1 (roundKey[3])],  8) ^
		PSI_ROTR (phi[GETB2 (roundKey[3])], 16) ^
		PSI_ROTR (phi[GETB3 (roundKey[3])], 24);
} /* squareTransform */


void squareGenerateRoundKeys (const squareBlock key,
	squareKeySchedule roundKeys_e, squareKeySchedule roundKeys_d)
{
	int t;

	COPY_BLOCK (roundKeys_e[0], D(key));
	for (t = 1; t < R+1; t++) {
		/* apply the key evolution function: */
		roundKeys_d[R-t][0] = roundKeys_e[t][0] = roundKeys_e[t-1][0] ^ PSI_ROTL (roundKeys_e[t-1][3], 8) ^ offset[t-1];
		roundKeys_d[R-t][1] = roundKeys_e[t][1] = roundKeys_e[t-1][1] ^ roundKeys_e[t][0];
		roundKeys_d[R-t][2] = roundKeys_e[t][2] = roundKeys_e[t-1][2] ^ roundKeys_e[t][1];
		roundKeys_d[R-t][3] = roundKeys_e[t][3] = roundKeys_e[t-1][3] ^ roundKeys_e[t][2];
		/* apply the theta diffusion function: */
		squareTransform (roundKeys_e[t-1]);
	}  
	COPY_BLOCK (roundKeys_d[R], roundKeys_e[0]);
} /* squareGenerateRoundKeys */

void squareExpandKey (const squareBlock key, squareKeySchedule roundKeys_e)
{
	int t;

	COPY_BLOCK (roundKeys_e[0], D(key));
	for (t = 1; t < R+1; t++) {
		/* apply the key evolution function: */
		roundKeys_e[t][0] = roundKeys_e[t-1][0] ^ PSI_ROTL (roundKeys_e[t-1][3], 8) ^ offset[t-1];
		roundKeys_e[t][1] = roundKeys_e[t-1][1] ^ roundKeys_e[t][0];
		roundKeys_e[t][2] = roundKeys_e[t-1][2] ^ roundKeys_e[t][1];
		roundKeys_e[t][3] = roundKeys_e[t-1][3] ^ roundKeys_e[t][2];
		/* apply the theta diffusion function: */
		squareTransform (roundKeys_e[t-1]);
	}  
} /* squareExpandKey */


#ifdef ASSEMBLER_CORE

/* Microsoft x86 version by George Barwood */
/* About 15-20% faster, using less code */
/* Notes:
   Calculate 4 outputs of each round in parallel using esi, edx, ecx, edi
   eax is used to hold the sub-round input
   ebx is used as a byte index register (and also to address text)
   ebp is used to address roundKeys and tables
   5 words of stack are used 
     1 - saved value of ebp
     2 - saved value of roundKeys address
     3,4,5 - round inputs (eax has first input)
   These are destroyed if DESTROY_TEMPORARIES is set
*/

#define INITIAL __asm      \
{                          \
  __asm push ebp  /*1*/    \
  __asm mov ebx, text      \
  __asm mov ebp, roundKeys \
  __asm push ebp  /*2*/    \
  __asm mov eax, [ebp][12] \
  __asm xor eax, [ebx][12] \
  __asm push eax  /*3*/    \
  __asm mov eax, [ebp][8]  \
  __asm xor eax, [ebx][8]  \
  __asm push eax  /*4*/    \
  __asm mov eax, [ebp][4]  \
  __asm xor eax, [ebx][4]  \
  __asm push eax  /*5*/    \
  __asm mov eax, [ebp][0]  \
  __asm xor eax, [ebx][0]  \
  __asm sub ebx, ebx       \
}

#define INIT_ROUND(RN)  __asm      \
{ /* load roundKeys */             \
  __asm mov edi, [ebp][RN*16+0*4]  \
  __asm mov ecx, [ebp][RN*16+1*4]  \
  __asm mov edx, [ebp][RN*16+2*4]  \
  __asm mov esi, [ebp][RN*16+3*4]  \
}

#define SUB_ROUND(TABLE) __asm \
{ /* the real work */          \
  __asm mov ebp,offset TABLE   \
  __asm mov bl,al              \
  __asm xor edi, [ebp][4*ebx]  \
  __asm mov bl,ah              \
  __asm shr eax,16             \
  __asm xor ecx, [ebp][4*ebx]  \
  __asm mov bl,al              \
  __asm shr eax,8              \
  __asm xor edx, [ebp][4*ebx]  \
  __asm xor esi, [ebp][4*eax]  \
}

#define END_ROUND __asm     \
{ /* save round output*/    \
  __asm mov ebp,[esp] /*2*/ \
  __asm push esi      /*3*/ \
  __asm push edx      /*4*/ \
  __asm push ecx      /*5*/ \
  __asm mov eax,edi         \
}

#define ENCRYPT_ROUND(RN) _asm  \
{ /* encryption round */ \
  INIT_ROUND(RN)         \
  SUB_ROUND(Te0)         \
  __asm pop eax  /*5*/   \
  SUB_ROUND(Te1)         \
  __asm pop eax  /*4*/   \
  SUB_ROUND(Te2)         \
  __asm pop eax  /*3*/   \
  SUB_ROUND(Te3)         \
  END_ROUND              \
}

#define DECRYPT_ROUND(RN) _asm  \
{ /* decryption round */ \
  INIT_ROUND(RN)         \
  SUB_ROUND(Td0)         \
  __asm pop eax  /*5*/   \
  SUB_ROUND(Td1)         \
  __asm pop eax  /*4*/   \
  SUB_ROUND(Td2)         \
  __asm pop eax  /*3*/   \
  SUB_ROUND(Td3)         \
  END_ROUND              \
}

#define HALF_FINAL __asm     \
{                            \
  __asm mov bl,al            \
  __asm mov bl, [ebp][ebx]   \
  __asm xor edi, ebx         \
  __asm mov bl,ah            \
  __asm shr eax,16           \
  __asm xor cl, [ebp][ebx]   \
  __asm mov bl,al            \
  __asm xor dl, [ebp][ebx]   \
  __asm mov bl, ah           \
  __asm mov bl, [ebp][ebx]   \
  __asm xor esi, ebx         \
  __asm pop eax              \
  __asm ror edi,8            \
  __asm mov bl,al            \
  __asm mov bl, [ebp][ebx]   \
  __asm xor edi,ebx          \
  __asm ror edi,8            \
  __asm sub bh,bh            \
  __asm mov bl,ah            \
  __asm shr eax,16           \
  __asm xor ch, [ebp][ebx]   \
  __asm ror ecx,16           \
  __asm mov bl,al            \
  __asm xor dh, [ebp][ebx]   \
  __asm ror edx,16           \
  __asm mov bl,ah            \
  __asm ror esi,8            \
  __asm mov bl, [ebp][ebx]   \
  __asm xor esi,ebx          \
  __asm ror esi,8            \
}

#define FINAL(TABLE) _asm  \
{                          \
  INIT_ROUND(8)            \
  mov ebp,offset TABLE     \
  HALF_FINAL      /*5*/    \
  __asm pop eax   /*4*/    \
  HALF_FINAL      /*3*/    \
  __asm pop ebp   /*2*/    \
  __asm pop ebp   /*1*/    \
  __asm mov ebx, text      \
  __asm mov [ebx][4*3],esi \
  __asm mov [ebx][4*2],edx \
  __asm mov [ebx][4*1],ecx \
  __asm mov [ebx][4*0],edi \
}

#define BURN_STACK _asm  \
{                        \
  __asm mov eax, esp     \
  __asm push 0L          \
  __asm push 0L          \
  __asm push 0L          \
  __asm push 0L          \
  __asm push 0L          \
  __asm mov esp, eax     \
}

void squareEncrypt (sword32 text[4], squareKeySchedule roundKeys)
{ 
  INITIAL
  ENCRYPT_ROUND(1)
  ENCRYPT_ROUND(2)
  ENCRYPT_ROUND(3)
  ENCRYPT_ROUND(4)
  ENCRYPT_ROUND(5)
  ENCRYPT_ROUND(6)
  ENCRYPT_ROUND(7)
  FINAL(Se)
#ifdef DESTROY_TEMPORARIES
  BURN_STACK
#endif /* ?DESTROY_TEMPORARIES */
}

void squareDecrypt (sword32 text[4], squareKeySchedule roundKeys)
{ 
  INITIAL
  DECRYPT_ROUND(1)
  DECRYPT_ROUND(2)
  DECRYPT_ROUND(3)
  DECRYPT_ROUND(4)
  DECRYPT_ROUND(5)
  DECRYPT_ROUND(6)
  DECRYPT_ROUND(7)
  FINAL(Sd)
#ifdef DESTROY_TEMPORARIES
  BURN_STACK
#endif /* ?DESTROY_TEMPORARIES */
}

#else /* !ASSEMBLER_CORE */

#define squareRound(text, temp, T0, T1, T2, T3, roundKey) \
{ \
	temp[0] = T0[GETB0 (text[0])] \
			^ T1[GETB0 (text[1])] \
			^ T2[GETB0 (text[2])] \
			^ T3[GETB0 (text[3])] \
			^ roundKey[0]; \
	temp[1] = T0[GETB1 (text[0])] \
			^ T1[GETB1 (text[1])] \
			^ T2[GETB1 (text[2])] \
			^ T3[GETB1 (text[3])] \
			^ roundKey[1]; \
	temp[2] = T0[GETB2 (text[0])] \
			^ T1[GETB2 (text[1])] \
			^ T2[GETB2 (text[2])] \
			^ T3[GETB2 (text[3])] \
			^ roundKey[2]; \
	temp[3] = T0[GETB3 (text[0])] \
			^ T1[GETB3 (text[1])] \
			^ T2[GETB3 (text[2])] \
			^ T3[GETB3 (text[3])] \
			^ roundKey[3]; \
} /* squareRound */


#define squareFinal(text, temp, S, roundKey) \
{ \
	text[0] = PUTB0 (S[GETB0 (temp[0])]) \
			^ PUTB1 (S[GETB0 (temp[1])]) \
			^ PUTB2 (S[GETB0 (temp[2])]) \
			^ PUTB3 (S[GETB0 (temp[3])]) \
			^ roundKey[0]; \
	text[1] = PUTB0 (S[GETB1 (temp[0])]) \
			^ PUTB1 (S[GETB1 (temp[1])]) \
			^ PUTB2 (S[GETB1 (temp[2])]) \
			^ PUTB3 (S[GETB1 (temp[3])]) \
			^ roundKey[1]; \
	text[2] = PUTB0 (S[GETB2 (temp[0])]) \
			^ PUTB1 (S[GETB2 (temp[1])]) \
			^ PUTB2 (S[GETB2 (temp[2])]) \
			^ PUTB3 (S[GETB2 (temp[3])]) \
			^ roundKey[2]; \
	text[3] = PUTB0 (S[GETB3 (temp[0])]) \
			^ PUTB1 (S[GETB3 (temp[1])]) \
			^ PUTB2 (S[GETB3 (temp[2])]) \
			^ PUTB3 (S[GETB3 (temp[3])]) \
			^ roundKey[3]; \
} /* squareFinal */


void squareEncrypt (sword32 text[4], squareKeySchedule roundKeys)
{
	sword32 temp[4];

	/* initial key addition */
	text[0] ^= roundKeys[0][0];
	text[1] ^= roundKeys[0][1];
	text[2] ^= roundKeys[0][2];
	text[3] ^= roundKeys[0][3];

	/* R - 1 full rounds */
	squareRound (text, temp, Te0, Te1, Te2, Te3, roundKeys[1]);
	squareRound (temp, text, Te0, Te1, Te2, Te3, roundKeys[2]);
	squareRound (text, temp, Te0, Te1, Te2, Te3, roundKeys[3]);
	squareRound (temp, text, Te0, Te1, Te2, Te3, roundKeys[4]);
	squareRound (text, temp, Te0, Te1, Te2, Te3, roundKeys[5]);
	squareRound (temp, text, Te0, Te1, Te2, Te3, roundKeys[6]);
	squareRound (text, temp, Te0, Te1, Te2, Te3, roundKeys[7]);

	/* last round (diffusion becomes only transposition) */
	squareFinal (text, temp, Se, roundKeys[R]);

#ifdef DESTROY_TEMPORARIES
	/* destroy sensitive data: */
	temp[0] = temp[1] = temp[2] = temp[3] = 0L;
#endif /* ?DESTROY_TEMPORARIES */
} /* squareEncrypt */


void squareDecrypt (sword32 text[4], squareKeySchedule roundKeys)
{
	sword32 temp[4];

	/* initial key addition */
	text[0] ^= roundKeys[0][0];
	text[1] ^= roundKeys[0][1];
	text[2] ^= roundKeys[0][2];
	text[3] ^= roundKeys[0][3];

	/* R - 1 full rounds */
	squareRound (text, temp, Td0, Td1, Td2, Td3, roundKeys[1]);
	squareRound (temp, text, Td0, Td1, Td2, Td3, roundKeys[2]);
	squareRound (text, temp, Td0, Td1, Td2, Td3, roundKeys[3]);
	squareRound (temp, text, Td0, Td1, Td2, Td3, roundKeys[4]);
	squareRound (text, temp, Td0, Td1, Td2, Td3, roundKeys[5]);
	squareRound (temp, text, Td0, Td1, Td2, Td3, roundKeys[6]);
	squareRound (text, temp, Td0, Td1, Td2, Td3, roundKeys[7]);

	/* last round (diffusion becomes only transposition) */
	squareFinal (text, temp, Sd, roundKeys[R]);

#ifdef DESTROY_TEMPORARIES
	/* destroy sensitive data: */
	temp[0] = temp[1] = temp[2] = temp[3] = 0L;
#endif /* ?DESTROY_TEMPORARIES */
} /* squareDecrypt */

#endif /* ?ASSEMBLER_CORE */

#if 0

static void squarePrint (const sbyte *block, const char *tag)
{
	printf ("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %s\n",
		block[ 0], block[ 1], block[ 2], block[ 3],
		block[ 4], block[ 5], block[ 6], block[ 7],
		block[ 8], block[ 9], block[10], block[11],
		block[12], block[13], block[14], block[15],
		tag);
} /* squarePrint */

#endif

void squareinitialise(char *keyin, void* ks)
{
	squareKeySchedule *ke = ks;
	squareKeySchedule *kd = (void*) ((char*) ks + 144);

	squareBlock key;
	int n=sizeof(squareKeySchedule);

	for (n=0;n<SQUARE_BLOCKSIZE;n++)
		key[n]=keyin[n];

	squareGenerateRoundKeys (key, *ke, *kd);        
}

#if 0

int smain (void)
{
	int i;
	squareBlock key, block;
	squareKeySchedule roundKeys_e;
	squareKeySchedule roundKeys_d;

	printf ("===========================================================================\n\n"
			"Validation data set for Square v1.0\n\n");

	printf ("===========================================================================\n\n"
			"Encryption of the null data block with every key where a single bit is set:\n\n");
	memset (block, 0, SQUARE_BLOCKSIZE);
	squarePrint (block, "plaintext\n");
	for (i = 0; i < 128; i++) {
		memset (key, 0, SQUARE_BLOCKSIZE);
		key[i/8] |= 1 << (7 - i%8); /* set only the i-th bit of the i-th test key */
		squarePrint (key, "key");
		memset (block, 0, SQUARE_BLOCKSIZE);
		squareExpandKey (key, roundKeys_e);
		squareEncrypt ((sword32 *)block, roundKeys_e);
		squarePrint (block, "ciphertext\n\n");
	}

	printf ("===========================================================================\n\n"
			"Encryption of a sample data block with every key where a single bit is set:\n\n");
	memcpy (block, "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0", SQUARE_BLOCKSIZE);

	for (i = 0; i < 128; i++) {
			
		squarePrint (block, "plaintext");
		memset (key, 0, SQUARE_BLOCKSIZE);
		key[i/8] |= 1 << (7 - i%8); /* set only the i-th bit of the i-th test key */
		squarePrint (key, "key");
		memcpy (block, "\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0", SQUARE_BLOCKSIZE);
		
		
		/* squareExpandKey (key, roundKeys_e); */
		squareGenerateRoundKeys (key,roundKeys_e, roundKeys_d);
	
		squareEncrypt ((sword32 *)block, roundKeys_e);
		squarePrint (block, "ciphertext");
		squareDecrypt ((sword32 *)block, roundKeys_d);
	squarePrint (block, "plaintext\n");
	}

	
	printf ("===========================================================================\n\n");

	return 0;
}


#endif
