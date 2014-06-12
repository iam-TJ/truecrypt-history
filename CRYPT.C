#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"

#include "bnlib/bnstub.h"	/* Disable RSA routines for now */

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions".
												- Don Alvarez */

/****************************************************************************
*																			*
*								General Work Routines						*
*																			*
****************************************************************************/

/* To convert from the external CRYPT_CONTEXT cookie which is used to
   reference encryption contexts to the internal CRYPT_INFO structure, we
   subtract an offset from the CRYPT_CONTEXT value to obtain a pointer to
   the CRYPT_INFO struct.  The use of the conversion offset means programs
   outside the library security perimeter will generate a protection
   violation if they try to treat the CRYPT_CONTEXT as a pointer to
   anything unless they go to some lengths to determine the conversion
   value */

int cryptContextConversionOffset;

/* Get an IV value.  It doesn't matter much what it is, as long as it's
   completely different for each call.  We use the first built-in encrypt
   capability we find (actually we just assume it's there to save some time) */

static int getIV( void *iv, int ivLength )
	{
	static BOOLEAN initialised = FALSE;
	static BYTE ivBuffer[ CRYPT_MAX_IVSIZE ];
	CRYPT_CONTEXT cryptContext;
	CRYPT_INFO *cryptInfo;
	CRYPT_INFO_MDCSHS cryptInfoEx;
	int status;

	if( !initialised )
		{
		/* Seed the data with a value which is guaranteed to be different
		   each time (unless the entire program is rerun more than twice a
		   second, which is doubtful) */
		memset( ivBuffer, 0, CRYPT_MAX_IVSIZE );
		time( ( time_t * ) ivBuffer );
		initialised = TRUE;
		}

	/* Use an extended setup call to only perform 2 setup iterations for
	   speed, since we're not concerned about security */
	cryptInfoEx.keySetupIterations = 2;

	/* Shuffle the bits and return them to the user.  Since the encryption
	   will force a call to getIV() again, we cheat a bit by poking around
	   the cryptInfo internals to fool encryptBuffer() into thinking the IV
	   is already set */
	if( ( status = initCryptContextEx( &cryptContext, CRYPT_ALGO_MDCSHS, \
									   CRYPT_MODE_CFB, &cryptInfoEx ) ) != CRYPT_OK || \
		( status = loadCryptContext( cryptContext, ivBuffer, \
									 CRYPT_MAX_IVSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo = CONTEXT_TO_INFO( cryptContext );
	cryptInfo->ivSet = TRUE;		/* Nasty hack to stop recursion */
	if( ( status = encryptBuffer( cryptContext, ivBuffer, \
								  CRYPT_MAX_IVSIZE ) ) != CRYPT_OK || \
		( status = destroyCryptContext( cryptContext ) ) != CRYPT_OK )
		return( status );
	memcpy( iv, ivBuffer, ivLength );

	return( CRYPT_OK );
	}

/* Byte-reverse an array of 16- and 32-bit words to/from network byte order
   to account for processor endianness.  These routines assume the given
   count is a multiple of 16 or 32 bits.  They are safe even for CPU's with
   a word size > 32 bits since on a little-endian CPU the important 32 bits
   are stored first, so that by zeroizing the first 32 bits and oring the
   reversed value back in we don't need to rely on the processor only writing
   32 bits into memory */

void longReverse( LONG *buffer, int count )
	{
#ifdef _BIG_WORDS
	BYTE *bufPtr = ( BYTE * ) buffer, temp;

	count /= 4;		/* sizeof( LONG ) != 4 */
	while( count-- )
		{
  #if 0
		LONG temp;

		/* This code is cursed */
		temp = value = *buffer & 0xFFFFFFFFUL;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		value = ( ( value << 16 ) | ( value >> 16 ) ) ^ temp;
		*buffer ^= value;
		buffer = ( LONG * ) ( ( BYTE * ) buffer + 4 );
  #endif /* 0 */
		/* There's really no nice way to do this - the above code generates
		   misaligned accesses on processors with a word size > 32 bits, so
		   we have to work at the byte level (either that or turn misaligned
		   access warnings off by trapping the signal the access corresponds
		   to.  However a context switch per memory access is probably
		   somewhat slower than the current byte-twiddling mess) */
		temp = bufPtr[ 3 ];
		bufPtr[ 3 ] = bufPtr[ 0 ];
		bufPtr[ 0 ] = temp;
		temp = bufPtr[ 2 ];
		bufPtr[ 2 ] = bufPtr[ 1 ];
		bufPtr[ 1 ] = temp;
		bufPtr += 4;
		}
#else
	LONG value;

	count /= sizeof( LONG );
	while( count-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
#endif /* _BIG_WORDS */
	}

void wordReverse( WORD *buffer, int count )
	{
	WORD value;

	count /= sizeof( WORD );
	while( count-- )
		{
		value = *buffer;
		*buffer++ = ( value << 8 ) | ( value >> 8 );
		}
	}

/* A safe free function which scrubs memory and zeroes the pointer */

void secureFree( void **pointer, int count )
	{
	if( *pointer != NULL )
		{
		/* Scrub the memory, free it, and zero the pointer */
		memset( *pointer, 0, count );
		free( *pointer );
		*pointer = NULL;
		}
	}

/****************************************************************************
*																			*
*						Capability Management Functions						*
*																			*
****************************************************************************/
    
/* The parameters of most encryption algorithms are traditionally specified
   in bytes, so we define a shorter form of the bitsToBytes() macro to allow
   the capability information to be specified in bits */

#define bits(x)	bitsToBytes(x)

/* The functions used to implement the null encryption routines */

int nullSelfTest( void );
int nullInit( CRYPT_INFO *cryptInfo );
int nullInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int nullEnd( CRYPT_INFO *cryptInfo );
int nullInitKey( CRYPT_INFO *cryptInfo );
int nullInitIV( CRYPT_INFO *cryptInfo );
int nullGetData( CRYPT_INFO *cryptInfo, void *buffer );
int nullEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int nullDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MDC/SHS encryption routines */

int mdcshsSelfTest( void );
int mdcshsInit( CRYPT_INFO *cryptInfo );
int mdcshsInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int mdcshsEnd( CRYPT_INFO *cryptInfo );
int mdcshsInitKey( CRYPT_INFO *cryptInfo );
int mdcshsInitIV( CRYPT_INFO *cryptInfo );
int mdcshsEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int mdcshsDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DES encryption routines */

int desSelfTest( void );
int desInit( CRYPT_INFO *cryptInfo );
int desInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int desEnd( CRYPT_INFO *cryptInfo );
int desInitKey( CRYPT_INFO *cryptInfo );
int desEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the triple DES encryption routines */

int des3SelfTest( void );
int des3Init( CRYPT_INFO *cryptInfo );
int des3InitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int des3End( CRYPT_INFO *cryptInfo );
int des3InitKey( CRYPT_INFO *cryptInfo );
int des3EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the IDEA encryption routines */

int ideaSelfTest( void );
int ideaInit( CRYPT_INFO *cryptInfo );
int ideaInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int ideaEnd( CRYPT_INFO *cryptInfo );
int ideaInitKey( CRYPT_INFO *cryptInfo );
int ideaEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC2 encryption routines */

int rc2SelfTest( void );
int rc2Init( CRYPT_INFO *cryptInfo );
int rc2InitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc2End( CRYPT_INFO *cryptInfo );
int rc2InitKey( CRYPT_INFO *cryptInfo );
int rc2EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RC4 encryption routines */

int rc4SelfTest( void );
int rc4Init( CRYPT_INFO *cryptInfo );
int rc4InitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc4End( CRYPT_INFO *cryptInfo );
int rc4InitKey( CRYPT_INFO *cryptInfo );
int rc4Encrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc4Decrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC5 encryption routines */

int rc5SelfTest( void );
int rc5Init( CRYPT_INFO *cryptInfo );
int rc5InitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc5End( CRYPT_INFO *cryptInfo );
int rc5InitKey( CRYPT_INFO *cryptInfo );
int rc5EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SAFER and SAFER_SK encryption
   routines */

int saferSelfTest( void );
int saferInit( CRYPT_INFO *cryptInfo );
int saferInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int saferEnd( CRYPT_INFO *cryptInfo );
int saferInitKey( CRYPT_INFO *cryptInfo );
int saferEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Blowfish and Blowfish_SK encryption
   routines */

int blowfishSelfTest( void );
int blowfishInit( CRYPT_INFO *cryptInfo );
int blowfishInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int blowfishEnd( CRYPT_INFO *cryptInfo );
int blowfishInitKey( CRYPT_INFO *cryptInfo );
int blowfishEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RSA encryption routines */

int rsaSelfTest( void );
int rsaInitKey( CRYPT_INFO *cryptInfo );
int rsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DSA encryption routines */

int dsaSelfTest( void );
int dsaInitKey( CRYPT_INFO *cryptInfo );
int dsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD2 hash routines */

int md2SelfTest( void );
int md2Init( CRYPT_INFO *cryptInfo );
int md2End( CRYPT_INFO *cryptInfo );
int md2GetData( CRYPT_INFO *cryptInfo, void *buffer );
int md2Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD4 hash routines */

int md4SelfTest( void );
int md4Init( CRYPT_INFO *cryptInfo );
int md4End( CRYPT_INFO *cryptInfo );
int md4GetData( CRYPT_INFO *cryptInfo, void *buffer );
int md4Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD5 hash routines */

int md5SelfTest( void );
int md5Init( CRYPT_INFO *cryptInfo );
int md5End( CRYPT_INFO *cryptInfo );
int md5GetData( CRYPT_INFO *cryptInfo, void *buffer );
int md5Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SHA hash routines */

int shaSelfTest( void );
int shaInit( CRYPT_INFO *cryptInfo );
int shaEnd( CRYPT_INFO *cryptInfo );
int shaGetData( CRYPT_INFO *cryptInfo, void *buffer );
int shaHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The encryption library intrinsic capability list */

static CAPABILITY_INFO intrinsicCapabilities[] = {
	/* The no-encryption capability */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, 0, "None", CRYPT_MAX_SPEED,
		0, 0, 0,
		0, 0, 0,
		nullSelfTest, nullInit, nullInitEx, nullEnd, nullInitKey, nullInitIV,
		nullGetData, nullEncrypt, nullDecrypt, CRYPT_ERROR, NULL },

	/* The MDC/SHS capabilities */
	{ CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB, bits( 8 ), "MDC/SHS", CRYPT_ERROR,
		bits( 40 ), bits( 512 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), bits( 64 ), bits( 160 ),
		mdcshsSelfTest, mdcshsInit, mdcshsInitEx, mdcshsEnd,
		mdcshsInitKey, mdcshsInitIV, NULL, mdcshsEncrypt, mdcshsDecrypt,
		CRYPT_ERROR, NULL },

	/* The DES capabilities */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		NULL, desEncryptECB, desDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		NULL, desEncryptCBC, desDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, bits( 8 ), "DES-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		NULL, desEncryptCFB, desDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, bits( 8 ), "DES-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		NULL, desEncryptOFB, desDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_PCBC, bits( 64 ), "DES-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		NULL, desEncryptPCBC, desDecryptPCBC, CRYPT_ERROR, NULL },

	/* The triple DES capabilities */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 168 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		NULL, des3EncryptECB, des3DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 168 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		NULL, des3EncryptCBC, des3DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, bits( 64 ), "3DES-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 168 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		NULL, des3EncryptCFB, des3DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, bits( 64 ), "3DES-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 168 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		NULL, des3EncryptOFB, des3DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_PCBC, bits( 64 ), "3DES-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 168 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		NULL, des3EncryptPCBC, des3DecryptPCBC, CRYPT_ERROR, NULL },

	/* The IDEA capabilities */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, bits( 64 ), "IDEA-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, ideaEncryptECB, ideaDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, bits( 64 ), "IDEA-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, ideaEncryptCBC, ideaDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, bits( 8 ), "IDEA-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, ideaEncryptCFB, ideaDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, bits( 8 ), "IDEA-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, ideaEncryptOFB, ideaDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_PCBC, bits( 64 ), "IDEA-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, ideaEncryptPCBC, ideaDecryptPCBC, CRYPT_ERROR, NULL },

	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB, bits( 64 ), "RC2-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, rc2EncryptECB, rc2DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC, bits( 64 ), "RC2-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, rc2EncryptCBC, rc2DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CFB, bits( 8 ), "RC2-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, rc2EncryptCFB, rc2DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_OFB, bits( 8 ), "RC2-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, rc2EncryptOFB, rc2DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_PCBC, bits( 64 ), "RC2-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, rc2EncryptPCBC, rc2DecryptPCBC, CRYPT_ERROR, NULL },

	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, bits( 8 ), "RC4", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), 256,
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc4SelfTest, rc4Init, rc4InitEx, rc4End, rc4InitKey, NULL,
		NULL, rc4Encrypt, rc4Decrypt, CRYPT_ERROR, NULL },

	/* The RC5 capabilities */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_ECB, bits( 64 ), "RC5-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, rc5EncryptECB, rc5DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC, bits( 64 ), "RC5-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, rc5EncryptCBC, rc5DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CFB, bits( 8 ), "RC5-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, rc5EncryptCFB, rc5DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_OFB, bits( 8 ), "RC5-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, rc5EncryptOFB, rc5DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_PCBC, bits( 64 ), "RC5-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, rc5EncryptPCBC, rc5DecryptPCBC, CRYPT_ERROR, NULL },

	/* The SAFER capabilities */
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_ECB, bits( 64 ), "SAFER-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		NULL, saferEncryptECB, saferDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CBC, bits( 64 ), "SAFER-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		NULL, saferEncryptCBC, saferDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CFB, bits( 8 ), "SAFER-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		NULL, saferEncryptCFB, saferDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_OFB, bits( 8 ), "SAFER-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		NULL, saferEncryptOFB, saferDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_PCBC, bits( 64 ), "SAFER-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		NULL, saferEncryptPCBC, saferDecryptPCBC, CRYPT_ERROR, NULL },

	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB, bits( 64 ), "Blowfish-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		NULL, blowfishEncryptECB, blowfishDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC, bits( 64 ), "Blowfish-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 16 ), bits( 32 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		NULL, blowfishEncryptCBC, blowfishDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB, bits( 8 ), "Blowfish-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 16 ), bits( 32 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		NULL, blowfishEncryptCFB, blowfishDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB, bits( 8 ), "Blowfish-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 16 ), bits( 32 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		NULL, blowfishEncryptOFB, blowfishDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_PCBC, bits( 64 ), "Blowfish-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 16 ), bits( 32 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		NULL, blowfishEncryptPCBC, blowfishDecryptPCBC, CRYPT_ERROR, NULL },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PRIVKEY, bits( 0 ),
		"RSA private-key operation", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rsaSelfTest, NULL, NULL, NULL, rsaInitKey, NULL,
		NULL, rsaEncrypt, rsaDecrypt, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PUBKEY, bits( 0 ),
		"RSA public-key operation", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rsaSelfTest, NULL, NULL, NULL, rsaInitKey, NULL,
		NULL, rsaEncrypt, rsaDecrypt, CRYPT_ERROR, NULL },

#if 0
	/* The DSS capabilities */
	{ CRYPT_ALGO_DSS, CRYPT_MODE_PRIVKEY, bits( 0 ),
		"DSS private-key operation", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		dsaSelfTest, NULL, NULL, NULL, dsaInitKey, NULL,
		NULL, dsaEncrypt, dsaDecrypt, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DSS, CRYPT_MODE_PUBKEY, bits( 0 ),
		"DSS public-key operation", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		dsaSelfTest, NULL, NULL, NULL, dsaInitKey, NULL,
		NULL, dsaEncrypt, dsaDecrypt, CRYPT_ERROR, NULL },

	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, CRYPT_MODE_NONE, bits( 128 ), "MD2", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md2SelfTest, md2Init, NULL, md2End,
		NULL, NULL, md2GetData, md2Hash, md2Hash,
		CRYPT_ERROR, NULL },
#endif

	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, CRYPT_MODE_NONE, bits( 128 ), "MD4", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md4SelfTest, md4Init, NULL, md4End,
		NULL, NULL, md4GetData, md4Hash, md4Hash,
		CRYPT_ERROR, NULL },

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, CRYPT_MODE_NONE, bits( 128 ), "MD5", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md5SelfTest, md5Init, NULL, md5End,
		NULL, NULL, md5GetData, md5Hash, md5Hash,
		CRYPT_ERROR, NULL },

	/* The SHA capabilities */
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, bits( 160 ), "SHA", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		shaSelfTest, shaInit, NULL, shaEnd,
		NULL, NULL, shaGetData, shaHash, shaHash,
		CRYPT_ERROR, NULL },

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, CRYPT_ERROR, "", 0,
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, CRYPT_ERROR, NULL }
	};

/* The list of crypt library capability records.  Even if initCapabilities()
   is never called we still have a minimum non-encryption method available */

static CAPABILITY_INFO *capabilityListHead = intrinsicCapabilities;
static CAPABILITY_INFO *capabilityListTail = intrinsicCapabilities;
static CAPABILITY_INFO *intrinsicCapabilityListEnd = NULL;

/* Free the capability list */

static void freeCapabilityList( void )
	{
	CAPABILITY_INFO *capabilityListPtr = intrinsicCapabilityListEnd;
	void *capabilityToFree;

	/* Mark the list as being empty */
	intrinsicCapabilityListEnd = NULL;

	/* Free the capability record list list */
	while( capabilityListPtr != NULL )
		{
		capabilityToFree = capabilityListPtr;
		capabilityListPtr = capabilityListPtr->next;
		secureFree( &capabilityToFree, sizeof( CAPABILITY_INFO ) );
		}
	}

/* Initialise the intrinsic encryption library capability list */

static int initCapabilities( void )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_ALGO cryptAlgo = CRYPT_ERROR;
	int i;

	/* Add the built-in encryption capabilities */
	for( i = 0; intrinsicCapabilities[ i + 1 ].blockSize != CRYPT_ERROR; i++ )
		intrinsicCapabilities[ i ].next = &intrinsicCapabilities[ i + 1 ];

	/* Perform the self-test for each encryption algorithm */
	for( capabilityInfoPtr = capabilityListHead;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		{
		CAPABILITY_INFO *capabilitySelfTestPtr;
		int status;

		/* If we've already encountered this algorithm, don't try the
		   self-test again */
		if( capabilityInfoPtr->cryptAlgo == cryptAlgo )
			continue;
		cryptAlgo = capabilityInfoPtr->cryptAlgo;

		/* If it's a PKC, there is a large amount of extra code wrapped
		   around the basic encryption functions, so we need to call the
		   high-level interface routines directly (this is very naughty, but
		   saves duplicating large amounts of code in the high-level and test
		   routines).  In order for the self-test code to work, we need to
		   set the self-test status to indicate that the test has already
		   been performed successfully.  The real self-test status is then
		   set on return from the self-test function */
		if( capabilityInfoPtr->cryptMode == CRYPT_MODE_PRIVKEY || \
			capabilityInfoPtr->cryptMode == CRYPT_MODE_PUBKEY )
			capabilityInfoPtr->selfTestStatus = CRYPT_OK;

		/* Perform the self-test for this algorithm type */
		status = capabilityInfoPtr->selfTestFunction();

		/* Set the test status for each capability using this algorithm */
		for( capabilitySelfTestPtr = capabilityInfoPtr;
			 capabilitySelfTestPtr != NULL;
			 capabilitySelfTestPtr = capabilitySelfTestPtr->next )
			if( capabilitySelfTestPtr->cryptAlgo == capabilityInfoPtr->cryptAlgo )
				capabilitySelfTestPtr->selfTestStatus = status;
		}

	return( CRYPT_OK );
	}

/* Add a capability record to the library */

static int addCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
						  int blockSize, char *name, int speed, \
						  int minKeySize, int keySize, int maxKeySize )
	{
	CAPABILITY_INFO *newElement;

	/* Check the passed-in parameters */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( blockSize < 0 )
		return( CRYPT_BADPARM3 );
	if( name == NULL )
		return( CRYPT_BADPARM4 );
	if( ( speed != CRYPT_ERROR && speed < 0 ) || speed > CRYPT_MAX_SPEED )
		return( CRYPT_BADPARM5 );
	if( minKeySize < 0 )
		return( CRYPT_BADPARM6 );
	if( keySize < minKeySize )
		return( CRYPT_BADPARM7 );
	if( maxKeySize < keySize )
		return( CRYPT_BADPARM8 );

	/* Allocate memory for the new capability and its associated message */
	if( ( newElement = ( CAPABILITY_INFO * ) malloc( sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( CAPABILITY_INFO ) );
	if( ( newElement->name = ( char * ) malloc( strlen( name ) + 1 ) ) == NULL )
		{
		free( newElement );
		return( CRYPT_NOMEM );
		}

	/* Copy the information across */
	newElement->cryptAlgo = cryptAlgo;
	newElement->cryptMode = cryptMode;
	newElement->blockSize = blockSize;
	strcpy( newElement->name, name );
	newElement->minKeySize = minKeySize;
	newElement->keySize = keySize;
	newElement->maxKeySize = maxKeySize;
	newElement->next = NULL;

	/* Link it into the list */
	if( capabilityListHead == NULL )
		capabilityListHead = newElement;
	else
		capabilityListTail->next = newElement;
	capabilityListTail = newElement;

	return( CRYPT_OK );
	}

/* Find the capability record for a given encryption algorithm */

static CAPABILITY_INFO *findCapabilityInfo( CRYPT_ALGO cryptAlgo, \
											CRYPT_MODE cryptMode )
	{
	CAPABILITY_INFO *capabilityInfoPtr;

	/* Try and find information on the required algorithm */
	for( capabilityInfoPtr = capabilityListHead;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		if( capabilityInfoPtr->cryptAlgo == cryptAlgo &&
			( capabilityInfoPtr->cryptMode == cryptMode ||
			  cryptMode == CRYPT_MODE_NONE ) )
			return( capabilityInfoPtr );

	/* Nothing available */
	return( NULL );
	}

/****************************************************************************
*																			*
*				Memory Management Functions for Encryption Contexts			*
*																			*
****************************************************************************/

/* The linked list of encryption contexts */

static CRYPT_INFO *cryptInfoListHead = NULL, *cryptInfoListTail;

/* Create an encryption context and add it to the list */

static CRYPT_INFO CPTR createCryptContext( void )
	{
	CRYPT_INFO *newElement;

	/* Allocate memory for the new encryption context */
	if( ( newElement = ( CRYPT_INFO * ) malloc( sizeof( CRYPT_INFO ) ) ) == NULL )
		return( NULL );
	memset( newElement, 0, sizeof( CRYPT_INFO ) );

	/* Link it into the list */
	if( cryptInfoListHead == NULL )
		cryptInfoListHead = newElement;
	else
		{
		cryptInfoListTail->next = newElement;
		newElement->prev = cryptInfoListTail;
		}
	cryptInfoListTail = newElement;

	return( newElement );
	}

/* Delete an encryption context from the list */

static void deleteCryptContext( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO *cryptInfoPrevPtr = cryptInfo->prev, *cryptInfoNextPtr = cryptInfo->next;

	/* Remove the encryption context from the list of contexts */
	if( cryptInfo == cryptInfoListHead )
		{
		/* Special case for first encryption context */
		cryptInfoListHead = cryptInfoNextPtr;
		if( cryptInfoNextPtr != NULL )
			cryptInfoNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		cryptInfoPrevPtr->next = cryptInfoNextPtr;
		if( cryptInfoNextPtr != NULL )
			cryptInfoNextPtr->prev = cryptInfoPrevPtr;
		}

	/* If this was the last element, move the tail pointer back */
	if( cryptInfoListTail == cryptInfo )
		cryptInfoListTail = cryptInfoPrevPtr;

	/* Clear all data in the encryption context and free the memory */
	secureFree( ( void ** ) &cryptInfo, sizeof( CRYPT_INFO ) );
	}

/* Delete all encryption contexts */

static int deleteAllCryptContexts( void )
	{
	CRYPT_INFO *cryptInfoListPtr = cryptInfoListHead;

	/* Mark the list as being empty */
	cryptInfoListHead = cryptInfoListTail = NULL;

	/* If there are no remaining allocated encryption contexts, return now */
	if( cryptInfoListPtr == NULL )
		return( CRYPT_OK );

	/* Free any remaining encryption contexts */
	while( cryptInfoListPtr != NULL )
		{
		CRYPT_INFO *cryptInfoToFree = cryptInfoListPtr;

		cryptInfoListPtr = cryptInfoListPtr->next;
		secureFree( ( void ** ) &cryptInfoToFree, sizeof( CRYPT_INFO ) );
		}

	/* If there were encryption contexts still allocated we warn the user
	   about it */
	return( CRYPT_ORPHAN );
	}

/****************************************************************************
*																			*
*							Capability Query Functions						*
*																			*
****************************************************************************/

/* Determine whether a given encryption mode is available */

CRET queryModeAvailability( const CRYPT_ALGO cryptAlgo, \
							const CRYPT_MODE cryptMode )
	{
	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );

	/* Make sure the library has been initalised */
	if( capabilityListHead == NULL )
		return( CRYPT_NOTINITED );

	/* See if we have any information on this encryption algo/mode */
	if( findCapabilityInfo( cryptAlgo, cryptMode ) == NULL )
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );

	return( CRYPT_OK );
	}

CRET queryAlgoAvailability( const CRYPT_ALGO cryptAlgo )
	{
	return( queryModeAvailability( cryptAlgo, CRYPT_MODE_NONE ) );
	}

/* Get information on a given encrytion algorithm */

CRET queryAlgoModeInformation( const CRYPT_ALGO cryptAlgo, \
							   const CRYPT_MODE cryptMode, \
							   CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CAPABILITY_INFO *capabilityInfo;

	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptQueryInfo == NULL )
		return( CRYPT_BADPARM3 );

	/* Make sure the library has been initalised */
	if( capabilityListHead == NULL )
		return( CRYPT_NOTINITED );

	/* Clear the fields in the query structure */
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );

	/* Find the information record on this algorithm */
	if( ( capabilityInfo = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		{
		cryptQueryInfo->algoName = "";
		cryptQueryInfo->blockSize = CRYPT_ERROR;
		cryptQueryInfo->minKeySize = CRYPT_ERROR;
		cryptQueryInfo->keySize = CRYPT_ERROR;
		cryptQueryInfo->maxKeySize = CRYPT_ERROR;
		cryptQueryInfo->minIVsize = CRYPT_ERROR;
		cryptQueryInfo->ivSize = CRYPT_ERROR;
		cryptQueryInfo->maxIVsize = CRYPT_ERROR;
		cryptQueryInfo->speed = CRYPT_ERROR;
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );
		}

	/* Return the appropriate information */
	cryptQueryInfo->cryptAlgo = cryptAlgo;
	cryptQueryInfo->cryptMode = cryptMode;
	cryptQueryInfo->algoName = capabilityInfo->name;
	cryptQueryInfo->blockSize = capabilityInfo->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfo->minKeySize;
	cryptQueryInfo->keySize = capabilityInfo->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfo->maxKeySize;
	cryptQueryInfo->minIVsize = capabilityInfo->minIVsize;
	cryptQueryInfo->ivSize = capabilityInfo->ivSize;
	cryptQueryInfo->maxIVsize = capabilityInfo->maxIVsize;
	cryptQueryInfo->speed = capabilityInfo->speed;
	return( CRYPT_OK );
	}

/* Get information on the algorithm used by a given encryption context */

CRET queryContextInformation( const CRYPT_CONTEXT cryptContext, \
							  CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->capabilityInfo == NULL )
		return( CRYPT_NOTINITED );

	/* Fill in the basic information */
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	if( ( status = queryAlgoModeInformation( capabilityInfoPtr->cryptAlgo,
						capabilityInfoPtr->cryptMode, cryptQueryInfo ) ) != CRYPT_OK )
		return( status );

	/* If it's a hash function, copy in the current state */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_NONE )
		{
		if( ( status = capabilityInfoPtr->getDataFunction( cryptInfoPtr,
								cryptQueryInfo->hashValue ) ) != CRYPT_OK )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Initialise and shut down the encryption library */

CRET initLibrary( void )
	{
	/* Set up the conversion offset used to translate CRYPT_CONTEXT cookies
	   into CRYPT_INFO structures.  This doesn't have to be secure, just a
	   random value that isn't too easy to guess and which generates some
	   form of error if the the CRYPT_CONTEXT it is added to is treated as a
	   pointer (the forced odd address guarantees this for many
	   architectures) */
	cryptContextConversionOffset = ( int ) time( NULL ) | 1;

	/* Initialise the BigNum library */
	bnInit();

	return( initCapabilities() );
	}

CRET endLibrary( void )
	{
	int status;

	status = deleteAllCryptContexts();
	freeCapabilityList();

	return( status );
	}

/****************************************************************************
*																			*
*					Encryption Context Management Functions					*
*																			*
****************************************************************************/

/* A magic value to detect whether an encryption context has been
   initialised yet */

#define CRYPT_MAGIC		0xC0EDBABEUL

/* Initialise and perform an extended initialisation of an encryption
   context.  These two functions are almost identical except for a slightly
   different function call in the middle.  For this reason we create two
   extra functions xInitial() and xFinal() which contain common code and call
   these before and after the function call in the middle.  Passing a
   function pointer to a common function from init()/initEx() isn't possible
   since the function call is of a different type for the two routines */

static int initContextInitial( CRYPT_INFO **cryptInfoPtr,
							   CAPABILITY_INFO *capabilityInfoPtr )
	{
	CRYPT_INFO *cryptInfoPtrPtr;

	/* Make sure the algorithm self-test went OK */
	if( capabilityInfoPtr->selfTestStatus != CRYPT_OK )
		return( CRYPT_SELFTEST );

	/* We're through the intialization phase, now we can create the
	   encryption context */
	if( ( *cryptInfoPtr = createCryptContext() ) == NULL )
		return( CRYPT_NOMEM );
	cryptInfoPtrPtr = *cryptInfoPtr;
	cryptInfoPtrPtr->capabilityInfo = capabilityInfoPtr;
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_PUBKEY || \
		capabilityInfoPtr->cryptMode == CRYPT_MODE_PRIVKEY )
		{
		cryptInfoPtrPtr->isPKCcontext = TRUE;
		cryptInfoPtrPtr->keySizeBits = 0;
		cryptInfoPtrPtr->ivSet = TRUE;	/* No IV for PKC's */

		/* Initialise the BigNum information */
		bnBegin( &cryptInfoPtrPtr->pkcParam1 );
		bnBegin( &cryptInfoPtrPtr->pkcParam2 );
		bnBegin( &cryptInfoPtrPtr->pkcParam3 );
		bnBegin( &cryptInfoPtrPtr->pkcParam4 );
		bnBegin( &cryptInfoPtrPtr->pkcParam5 );
		bnBegin( &cryptInfoPtrPtr->pkcParam6 );
		bnBegin( &cryptInfoPtrPtr->pkcParam7 );
		bnBegin( &cryptInfoPtrPtr->pkcParam8 );
		}

	return( CRYPT_OK );
	}

static int initContextFinal( CRYPT_INFO *cryptInfoPtr )
	{
	CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;

	/* If we don't need a key and IV, record them as being set */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_NONE )
		{
		cryptInfoPtr->keySet = TRUE;
		cryptInfoPtr->ivSet = TRUE;
		}

	/* Set up the IV information to the default values.  This can be
	   overridden later if required */
	cryptInfoPtr->ivLength = capabilityInfoPtr->ivSize;

	/* Set the check value.  Note that we set it after the capability info
	   has been set, so that a check on this value will also tell us whether
	   the capability info is present */
	cryptInfoPtr->checkValue = CRYPT_MAGIC;

	return( CRYPT_OK );
	}

CRET initCryptContext( CRYPT_CONTEXT CPTR cryptContext, \
					   const CRYPT_ALGO cryptAlgo, const CRYPT_MODE cryptMode )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM3 );

	/* Set up the pointer to the capability information */
	if( ( capabilityInfoPtr = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		return( ( queryAlgoAvailability( cryptAlgo ) ) ? \
				CRYPT_NOMODE : CRYPT_NOALGO );

	/* Perform the initial setup */
	if( ( status = initContextInitial( &cryptInfoPtr, capabilityInfoPtr ) ) != CRYPT_OK )
		return( status );

	/* Perform any algorithm-specific initialization */
	if( capabilityInfoPtr->initFunction != NULL )
		{
		int status;

		status = capabilityInfoPtr->initFunction( cryptInfoPtr );
		if( isStatusError( status ) )
			{
			deleteCryptContext( cryptInfoPtr );
			return( status );
			}
		}

	/* Perform the final setup */
	if( ( status = initContextFinal( cryptInfoPtr ) ) != CRYPT_OK )
		return( status );

	/* Convert the encryption information pointer to an encryption context
	   and return it to the user */
	*cryptContext = INFO_TO_CONTEXT( cryptInfoPtr );

	return( CRYPT_OK );
	}

CRET initCryptContextEx( CRYPT_CONTEXT CPTR cryptContext, \
						 const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode, \
						 const void *cryptInfoEx )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM3 );
	if( cryptInfoEx == NULL )
		return( CRYPT_BADPARM4 );

	/* Set up the pointer to the capability information */
	if( ( capabilityInfoPtr = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		return( ( queryAlgoAvailability( cryptAlgo ) ) ? \
				CRYPT_NOMODE : CRYPT_NOALGO );

	/* Perform the initial setup */
	if( ( status = initContextInitial( &cryptInfoPtr, capabilityInfoPtr ) ) != CRYPT_OK )
		return( status );

	/* Perform any algorithm-specific initialization */
	if( capabilityInfoPtr->initExFunction != NULL )
		{
		int status;

		status = capabilityInfoPtr->initExFunction( cryptInfoPtr, cryptInfoEx );
		if( isStatusError( status ) )
			{
			deleteCryptContext( cryptInfoPtr );
			return( status );
			}
		}

	/* Perform the final setup */
	if( ( status = initContextFinal( cryptInfoPtr ) ) != CRYPT_OK )
		return( status );

	/* Convert the encryption information pointer to an encryption context
	   and return it to the user */
	*cryptContext = INFO_TO_CONTEXT( cryptInfoPtr );

	return( CRYPT_OK );
	}

/* Destroy an encryption context */

CRET destroyCryptContext( CRYPT_CONTEXT cryptContext )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC ||
		cryptInfoPtr->capabilityInfo == NULL )
		return( CRYPT_NOTINITED );

	/* Perform any algorithm-specific shutdown */
	if( cryptInfoPtr->capabilityInfo->endFunction != NULL )
		{
		int status;

		status = cryptInfoPtr->capabilityInfo->endFunction( cryptInfoPtr );
		if( isStatusError( status ) )
			return( status );
		}

	/* If it's a PKC crypt context, free the BigNum information */
	if( cryptInfoPtr->isPKCcontext )
		{
		bnEnd( &cryptInfoPtr->pkcParam1 );
		bnEnd( &cryptInfoPtr->pkcParam2 );
		bnEnd( &cryptInfoPtr->pkcParam3 );
		bnEnd( &cryptInfoPtr->pkcParam4 );
		bnEnd( &cryptInfoPtr->pkcParam5 );
		bnEnd( &cryptInfoPtr->pkcParam6 );
		bnEnd( &cryptInfoPtr->pkcParam7 );
		bnEnd( &cryptInfoPtr->pkcParam8 );
		}

	/* Delete the encryption context */
	deleteCryptContext( cryptInfoPtr );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Keying Functions							*
*																			*
****************************************************************************/

/* Load a user key into an encryption context */

CRET loadCryptContext( CRYPT_CONTEXT cryptContext, const void CPTR userKey,
					   const int userKeyLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( userKey == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( !cryptInfoPtr->isPKCcontext &&
		( userKeyLength < cryptInfoPtr->capabilityInfo->minKeySize ||
		  userKeyLength > cryptInfoPtr->capabilityInfo->maxKeySize ) )
		return( CRYPT_BADPARM3 );
	if( cryptInfoPtr->capabilityInfo->initKeyFunction == NULL )
		return( CRYPT_NOALGO );

	/* If it's a hash function, the load key operation is meaningless */
	if( cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE )
		return( CRYPT_NOTAVAIL );

	/* Load either PKC keying information or a conventional key */
	if( cryptInfoPtr->isPKCcontext )
		{
		/* Call the algorithm-specific function to load the key components */
		cryptInfoPtr->keyComponentPtr = ( void CPTR ) userKey;
		cryptInfoPtr->keyComponentsLittleEndian = \
			( ( ( CRYPT_PKCINFO_RSA * ) userKey )->endianness == CRYPT_COMPONENTS_LITTLENDIAN );
		if( ( status = cryptInfoPtr->capabilityInfo->initKeyFunction( cryptInfoPtr ) ) != CRYPT_OK )
			return( status );
		}
	else
		{
		/* Load the user encryption key into the encryption context */
		memcpy( cryptInfoPtr->userKey, userKey, userKeyLength );
		cryptInfoPtr->userKeyLength = userKeyLength;

		/* Remember that we need to set an IV before we encrypt anything */
		if( needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
			cryptInfoPtr->ivSet = FALSE;
		else
			/* We don't need an IV, record it as being set */
			cryptInfoPtr->ivSet = TRUE;

		/* Call the encryption routine for this algorithm/mode */
		if( ( status = cryptInfoPtr->capabilityInfo->initKeyFunction( cryptInfoPtr ) ) != CRYPT_OK )
			return( status );
		}

	/* Record the fact that the key has been initialized */
	cryptInfoPtr->keySet = TRUE;

	return( CRYPT_OK );
	}

/* Generate a session key in an encryption context */

CRET generateCryptContext( CRYPT_CONTEXT cryptContext, const int userKeyLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	BYTE sessionKey[ CRYPT_MAX_KEYSIZE ];
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* If it's a hash function or PKC, the session key generate operation is
	   meaningless */
	if( cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE || \
		cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );

	/* Generate a session key and load it into the encryption context */
	memset( sessionKey, '*', userKeyLength );
	status = loadCryptContext( cryptContext, sessionKey, userKeyLength );
	memset( sessionKey, 0, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/****************************************************************************
*																			*
*							IV Handling Functions							*
*																			*
****************************************************************************/

/* Load an IV into an encryption context */

CRET loadIV( CRYPT_CONTEXT cryptContext, const void CPTR iv, const int ivLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( ivLength < cryptInfoPtr->capabilityInfo->minIVsize ||
		ivLength > cryptInfoPtr->capabilityInfo->maxIVsize )
		return( CRYPT_BADPARM3 );

	/* If it's a PKC crypt context or an mode which doesn't use an IV, the
	   load IV operation is meaningless */
	if( cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );
	if( !needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		return( CRYPT_NOTAVAIL );

	/* Set the IV length and check whether we'll be using a user-supplied
	   IV */
	cryptInfoPtr->ivLength = ivLength;
	cryptInfoPtr->ivCount = 0;
	if( iv != NULL )
		{
		/* Load the IV of the required length.  If the required IV size is
		   less than the maximum possible IV size, we pad it with zeroes */
		memset( cryptInfoPtr->iv, 0, CRYPT_MAX_IVSIZE );
		memcpy( cryptInfoPtr->iv, iv, cryptInfoPtr->ivLength );
		memcpy( cryptInfoPtr->currentIV, cryptInfoPtr->iv, CRYPT_MAX_IVSIZE );
		cryptInfoPtr->ivSet = TRUE;
		}
	if( cryptInfoPtr->capabilityInfo->initIVFunction != NULL )
		{
		int status;

		status = cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr );
		if( isStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Retrieve an IV from an encryption context */

CRET retrieveIV( CRYPT_CONTEXT cryptContext, void CPTR iv )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( iv == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* If it's a PKC crypt context or an mode which doesn't use an IV, the
	   load IV operation is meaningless */
	if( cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );
	if( !needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		return( CRYPT_NOTAVAIL );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Copy the IV data of the required length to the output buffer */
	memcpy( iv, cryptInfoPtr->iv, cryptInfoPtr->ivLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Routines						*
*																			*
****************************************************************************/

/* Encrypt a block of memory */

CRET encryptBuffer( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
					const int length )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( length < 0 )
		return( CRYPT_BADPARM3 );
	if( !cryptInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfoPtr->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* If there's no IV set, generate one ourselves */
	if( !cryptInfoPtr->ivSet )
		{
		BYTE iv[ CRYPT_MAX_IVSIZE ];
		int status;

		if( ( status = getIV( iv, cryptInfoPtr->ivLength ) ) != CRYPT_OK || \
			( status = loadIV( cryptContext, iv, cryptInfoPtr->ivLength ) ) != CRYPT_OK )
			return( status );
		}

	/* Call the encryption routine for this algorithm/mode */
	return( cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr, buffer, length ) );
	}

/* Decrypt a block of memory */

CRET decryptBuffer( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
					const int length )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( length < 0 )
		return( CRYPT_BADPARM3 );
	if( !cryptInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfoPtr->capabilityInfo->decryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Call the decryption routine for this algorithm/mode */
	return( cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr, buffer, length ) );
	}

/****************************************************************************
*																			*
*						Dynamic Library Update Support						*
*																			*
****************************************************************************/

/* Add a new encryption capability to the library.  This routine is quite
   powerful, but what a kludge! */

CRET addCryptCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
						 int blockSize, char *name, int speed, \
						 int minKeySize, int keySize, int maxKeySize )
	{
	int status;

	/* Add the basic capability information */
	status = addCapability( cryptAlgo, cryptMode, blockSize, name,
							speed, minKeySize, keySize, maxKeySize );
	if( isStatusError( status ) )
		return( status );

	/* Add the handlers */
/* Not implemented yet */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !defined( __WIN32__ )

/* Whether LibMain() has been called before */

static BOOLEAN libMainCalled = FALSE;
static HWND hInst;

/* The main function for the DLL */

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{
	/* Rot bilong kargo */
	if( wHeapSize > 0 )
		UnlockData( 0 );	/* Allow heap to move */

	/* If we've been called before, return with an error message */
	if( libMainCalled )
		return( FALSE );
	libMainCalled = TRUE;

	/* Initialise the library */
	if( initLibrary() != CRYPT_OK )
		return( FALSE );

	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

/* Shut down the DLL */

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	/* Shut down the encryption library if necessary */
	endLibrary();
	
	return( TRUE );
	}

#elif defined( __WINDOWS__ ) && defined( __WIN32__ )

/* Whether LibMain() has been called before */

static BOOLEAN libMainCalled = FALSE;
static HWND hInst;

int LibMain( HANDLE hInstance, ULONG ulReasonCalled, LPVOID lpReserved )
	{
	/* If we've been called before, return with an error message */
	if( libMainCalled )
		return( FALSE );
	libMainCalled = TRUE;

	/* Initialise the library */
	if( initLibrary() != CRYPT_OK )
		return( FALSE );

	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	/* Shut down the encryption library if necessary */
	endLibrary();
	
	return( TRUE );
	}
#endif /* __WINDOWS__ && !__WIN32__ */
