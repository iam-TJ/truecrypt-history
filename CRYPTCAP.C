/****************************************************************************
*																			*
*					cryptlib Capability Management Routines					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"

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
int nullGetKeysize( CRYPT_INFO *cryptInfo );
int nullGetData( CRYPT_INFO *cryptInfo, void *buffer );
int nullEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int nullDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DES encryption routines */

int desSelfTest( void );
int desInit( CRYPT_INFO *cryptInfo );
int desInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int desEnd( CRYPT_INFO *cryptInfo );
int desInitKey( CRYPT_INFO *cryptInfo );
int desGetKeysize( CRYPT_INFO *cryptInfo );
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
int des3GetKeysize( CRYPT_INFO *cryptInfo );
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

/* The functions used to implement the MDC/SHS encryption routines */

int mdcshsSelfTest( void );
int mdcshsInit( CRYPT_INFO *cryptInfo );
int mdcshsInitEx( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int mdcshsEnd( CRYPT_INFO *cryptInfo );
int mdcshsInitKey( CRYPT_INFO *cryptInfo );
int mdcshsInitIV( CRYPT_INFO *cryptInfo );
int mdcshsEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int mdcshsDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

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
int saferGetKeysize( CRYPT_INFO *cryptInfo );
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
int blowfishGetKeysize( CRYPT_INFO *cryptInfo );
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

/* The functions used to implement the Diffie-Hellman key exchange routines */

int dhSelfTest( void );
int dhInitKey( CRYPT_INFO *cryptInfo );
int dhEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dhDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

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

/* The functions used to implement the RIPEMD-160 hash routines */

int ripemd160SelfTest( void );
int ripemd160Init( CRYPT_INFO *cryptInfo );
int ripemd160End( CRYPT_INFO *cryptInfo );
int ripemd160GetData( CRYPT_INFO *cryptInfo, void *buffer );
int ripemd160Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SHA hash routines */

int shaSelfTest( void );
int shaInit( CRYPT_INFO *cryptInfo );
int shaEnd( CRYPT_INFO *cryptInfo );
int shaGetData( CRYPT_INFO *cryptInfo, void *buffer );
int shaHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The encryption library intrinsic capability list */

static CAPABILITY_INFO intrinsicCapabilities[] = {
	/* The no-encryption capability */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, 0, "None", "None", CRYPT_MAX_SPEED,
		0, 0, 0,
		0, 0, 0,
		nullSelfTest, nullInit, nullInitEx, nullEnd, nullInitKey, nullInitIV,
		nullGetKeysize, nullGetData, nullEncrypt, nullDecrypt, CRYPT_ERROR, NULL },

	/* The DES capabilities */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desGetKeysize, NULL, desEncryptECB, desDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desGetKeysize, NULL, desEncryptCBC, desDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, bits( 8 ), "DES", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desGetKeysize, NULL, desEncryptCFB, desDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, bits( 8 ), "DES", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desGetKeysize, NULL, desEncryptOFB, desDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_PCBC, bits( 64 ), "DES", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desGetKeysize, NULL, desEncryptPCBC, desDecryptPCBC, CRYPT_ERROR, NULL },

	/* The triple DES capabilities */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 192 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3GetKeysize, NULL, des3EncryptECB, des3DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 192 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3GetKeysize, NULL, des3EncryptCBC, des3DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, bits( 64 ), "3DES", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 192 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3GetKeysize, NULL, des3EncryptCFB, des3DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, bits( 64 ), "3DES", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 192 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3GetKeysize, NULL, des3EncryptOFB, des3DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_PCBC, bits( 64 ), "3DES", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 192 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3GetKeysize, NULL, des3EncryptPCBC, des3DecryptPCBC, CRYPT_ERROR, NULL },

	/* The IDEA capabilities */
#ifndef NO_PATENT
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, bits( 64 ), "IDEA", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, NULL, ideaEncryptECB, ideaDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, bits( 64 ), "IDEA", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, NULL, ideaEncryptCBC, ideaDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, bits( 8 ), "IDEA", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, NULL, ideaEncryptCFB, ideaDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, bits( 8 ), "IDEA", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, NULL, ideaEncryptOFB, ideaDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_PCBC, bits( 64 ), "IDEA", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		NULL, NULL, ideaEncryptPCBC, ideaDecryptPCBC, CRYPT_ERROR, NULL },
#endif /* NO_PATENT */

	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB, bits( 64 ), "RC2", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, NULL, rc2EncryptECB, rc2DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC, bits( 64 ), "RC2", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, NULL, rc2EncryptCBC, rc2DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CFB, bits( 8 ), "RC2", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, NULL, rc2EncryptCFB, rc2DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_OFB, bits( 8 ), "RC2", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, NULL, rc2EncryptOFB, rc2DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_PCBC, bits( 64 ), "RC2", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc2SelfTest, rc2Init, rc2InitEx, rc2End, rc2InitKey, NULL,
		NULL, NULL, rc2EncryptPCBC, rc2DecryptPCBC, CRYPT_ERROR, NULL },

	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, bits( 8 ), "RC4", "Stream", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), 256,
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc4SelfTest, rc4Init, rc4InitEx, rc4End, rc4InitKey, NULL,
		NULL, NULL, rc4Encrypt, rc4Decrypt, CRYPT_ERROR, NULL },

	/* The RC5 capabilities */
#ifndef NO_PATENT
	{ CRYPT_ALGO_RC5, CRYPT_MODE_ECB, bits( 64 ), "RC5", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, NULL, rc5EncryptECB, rc5DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC, bits( 64 ), "RC5", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, NULL, rc5EncryptCBC, rc5DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CFB, bits( 8 ), "RC5", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, NULL, rc5EncryptCFB, rc5DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_OFB, bits( 8 ), "RC5", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, NULL, rc5EncryptOFB, rc5DecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_PCBC, bits( 64 ), "RC5", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		rc5SelfTest, rc5Init, rc5InitEx, rc5End, rc5InitKey, NULL,
		NULL, NULL, rc5EncryptPCBC, rc5DecryptPCBC, CRYPT_ERROR, NULL },
#endif /* NO_PATENT */

	/* The MDC/SHS capabilities */
	{ CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB, bits( 8 ), "MDC/SHS", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 512 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), bits( 64 ), CRYPT_MAX_IVSIZE,
		mdcshsSelfTest, mdcshsInit, mdcshsInitEx, mdcshsEnd,
		mdcshsInitKey, mdcshsInitIV, NULL, NULL, mdcshsEncrypt, mdcshsDecrypt,
		CRYPT_ERROR, NULL },

	/* The SAFER capabilities */
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_ECB, bits( 64 ), "SAFER", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		saferGetKeysize, NULL, saferEncryptECB, saferDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CBC, bits( 64 ), "SAFER", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		saferGetKeysize, NULL, saferEncryptCBC, saferDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CFB, bits( 8 ), "SAFER", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		saferGetKeysize, NULL, saferEncryptCFB, saferDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_OFB, bits( 8 ), "SAFER", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		saferGetKeysize, NULL, saferEncryptOFB, saferDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_PCBC, bits( 64 ), "SAFER", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		saferSelfTest, saferInit, saferInitEx, saferEnd, saferInitKey, NULL,
		saferGetKeysize, NULL, saferEncryptPCBC, saferDecryptPCBC, CRYPT_ERROR, NULL },

	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB, bits( 64 ), "Blowfish", "ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		blowfishGetKeysize, NULL, blowfishEncryptECB, blowfishDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC, bits( 64 ), "Blowfish", "CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		blowfishGetKeysize, NULL, blowfishEncryptCBC, blowfishDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB, bits( 8 ), "Blowfish", "CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		blowfishGetKeysize, NULL, blowfishEncryptCFB, blowfishDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB, bits( 8 ), "Blowfish", "OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		blowfishGetKeysize, NULL, blowfishEncryptOFB, blowfishDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_PCBC, bits( 64 ), "Blowfish", "PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 32 ), CRYPT_MAX_IVSIZE, CRYPT_MAX_IVSIZE,
		blowfishSelfTest, blowfishInit, blowfishInitEx, blowfishEnd, blowfishInitKey, NULL,
		blowfishGetKeysize, NULL, blowfishEncryptPCBC, blowfishDecryptPCBC, CRYPT_ERROR, NULL },

	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, CRYPT_MODE_NONE, bits( 128 ), "MD2",
		"Hash algorithm", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md2SelfTest, md2Init, NULL, md2End,
		NULL, NULL, NULL, md2GetData, md2Hash, md2Hash,
		CRYPT_ERROR, NULL },

	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, CRYPT_MODE_NONE, bits( 128 ), "MD4",
		"Hash algorithm", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md4SelfTest, md4Init, NULL, md4End,
		NULL, NULL, NULL, md4GetData, md4Hash, md4Hash,
		CRYPT_ERROR, NULL },

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, CRYPT_MODE_NONE, bits( 128 ), "MD5",
		"Hash algorithm", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		md5SelfTest, md5Init, NULL, md5End,
		NULL, NULL, NULL, md5GetData, md5Hash, md5Hash,
		CRYPT_ERROR, NULL },

	/* The RIPEMD-160 capabilities */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_MODE_NONE, bits( 160 ),
		"RIPEMD-160", "Hash algorithm", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		ripemd160SelfTest, ripemd160Init, NULL, ripemd160End,
		NULL, NULL, NULL, ripemd160GetData, ripemd160Hash, ripemd160Hash,
		CRYPT_ERROR, NULL },

	/* The SHA capabilities */
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, bits( 160 ), "SHA",
    	"Hash algorithm", CRYPT_ERROR,
		bits( 0 ), bits( 0 ), bits( 0 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		shaSelfTest, shaInit, NULL, shaEnd,
		NULL, NULL, NULL, shaGetData, shaHash, shaHash,
		CRYPT_ERROR, NULL },

	/* The Diffie-Hellman capabilities */
	{ CRYPT_ALGO_DH, CRYPT_MODE_PKC, bits( 0 ), "Diffie-Hellman",
		"Key exchange algorithm", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		dhSelfTest, NULL, NULL, NULL, dhInitKey, NULL,
		NULL, NULL, dhEncrypt, dhDecrypt, CRYPT_ERROR, NULL },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PKC, bits( 0 ), "RSA",
		"Public-key algorithm", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rsaSelfTest, NULL, NULL, NULL, rsaInitKey, NULL,
		NULL, NULL, rsaEncrypt, rsaDecrypt, CRYPT_ERROR, NULL },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, CRYPT_MODE_PKC, bits( 0 ), "DSA",
		"Public-key algorithm", CRYPT_ERROR,
		bits( 512 ), bits( 1024 ), bits( 4096 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		dsaSelfTest, NULL, NULL, NULL, dsaInitKey, NULL,
		NULL, NULL, dsaEncrypt, dsaDecrypt, CRYPT_ERROR, NULL },

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, CRYPT_ERROR, "", "", 0,
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, CRYPT_ERROR, NULL }
	};

/* The list of crypt library capability records.  Even if initCapabilities()
   is never called we still have a minimum non-encryption method available */

static CAPABILITY_INFO *capabilityListHead = NULL;
static CAPABILITY_INFO *capabilityListTail = intrinsicCapabilities;
static CAPABILITY_INFO *intrinsicCapabilityListEnd = NULL;

/* Query whether the capability list has been initialised */

BOOLEAN queryCapabilitiesInited( void )
	{
	return( ( capabilityListHead != NULL ) ? TRUE : FALSE );
	}

/* Free the capability list */

void freeCapabilityList( void )
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
		cleanFree( &capabilityToFree, sizeof( CAPABILITY_INFO ) );
		}
	}

/* Initialise the intrinsic encryption library capability list */

int initCapabilities( void )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_ALGO cryptAlgo = CRYPT_ERROR;
	int i;

	/* Add the built-in encryption capabilities */
	for( i = 0; intrinsicCapabilities[ i + 1 ].blockSize != CRYPT_ERROR; i++ )
		intrinsicCapabilities[ i ].next = &intrinsicCapabilities[ i + 1 ];
	capabilityListHead = intrinsicCapabilities;
	capabilityListTail = &intrinsicCapabilities[ i ];

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

#if 0

/* Add a capability record to the library */

int addCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, int blockSize,
				   char *algoName, char *modeName, int speed, int minKeySize,
				   int keySize, int maxKeySize )
	{
	CAPABILITY_INFO *newElement;

	/* Check the passed-in parameters */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( blockSize < 0 )
		return( CRYPT_BADPARM3 );
	if( algoName == NULL )
		return( CRYPT_BADPARM4 );
	if( modeName == NULL )
		return( CRYPT_BADPARM5 );
	if( ( speed != CRYPT_ERROR && speed < 0 ) || speed > CRYPT_MAX_SPEED )
		return( CRYPT_BADPARM6 );
	if( minKeySize < 0 )
		return( CRYPT_BADPARM7 );
	if( keySize < minKeySize )
		return( CRYPT_BADPARM8 );
	if( maxKeySize < keySize )
		return( CRYPT_BADPARM9 );

	/* Allocate memory for the new capability and its associated message */
	if( ( newElement = ( CAPABILITY_INFO * ) malloc( sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( CAPABILITY_INFO ) );
	if( ( newElement->algoName = ( char * ) malloc( strlen( algoName ) + 1 ) ) == NULL )
		{
		free( newElement );
		return( CRYPT_NOMEM );
		}
	if( ( newElement->modeName = ( char * ) malloc( strlen( modeName ) + 1 ) ) == NULL )
		{
		free( newElement->algoName );
		free( newElement );
		return( CRYPT_NOMEM );
		}

	/* Copy the information across */
	newElement->cryptAlgo = cryptAlgo;
	newElement->cryptMode = cryptMode;
	newElement->blockSize = blockSize;
	strcpy( newElement->algoName, algoName );
	strcpy( newElement->modeName, modeName );
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
#endif /* 0 */

/* Find the capability record for a given encryption algorithm */

CAPABILITY_INFO *findCapabilityInfo( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
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
