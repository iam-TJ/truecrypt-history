/****************************************************************************
*																			*
*						cryptlib DES Encryption Routines					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "des.h"
#else
  #include "libdes/des.h"
#endif /* Compiler-specific includes */

/* The DES block size */

#define DES_BLOCKSIZE			8

/* A structure to hold the keyscheduled DES keys */

typedef struct {
	Key_schedule desKey;			/* The DES key */
	BOOLEAN isDESX;					/* Whether it's DES or DESX */
	} DES_KEY;

/* The size of the keyscheduled DES key */

#define DES_EXPANDED_KEYSIZE	sizeof( DES_KEY )

/****************************************************************************
*																			*
*							DES Self-test Routines							*
*																			*
****************************************************************************/

#include "testdes.h"

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 500-20, 1980.  We need to perform the tests at a very low
   level since the encryption library hasn't been intialized yet */

static int desTestLoop( DES_TEST *testData, int iterations, int operation )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key[ DES_EXPANDED_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );
		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key ) );
		des_ecb_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						 *( ( Key_schedule * ) key ), operation );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

int desSelfTest( void )
	{
	UNUSED( testIPname );
	UNUSED( testVPname );
	UNUSED( testKPname );
	UNUSED( testRSname );
	UNUSED( testDPname );
	UNUSED( testSBname );

#if defined( __WIN16__ ) && defined( _MSC_VER )
	/* Bypass 16-bit Visual C bug */
	des_check_key = FALSE;
#endif /* __WIN16__ && _MSC_VER */

	/* Check the DES test vectors */
	if( ( desTestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testRS, sizeof( testRS ) / sizeof( DES_TEST ),
					   DES_DECRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) )
		return( CRYPT_SELFTEST );

	/* Turn on checking for key parity errors and weak keys.  Note that we
	   have do this after the self-test since the self-test uses weak keys */
	des_check_key = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int desInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_DES *cryptInfoExPtr = ( CRYPT_INFO_DES * ) cryptInfoEx;
	int status;

	/* Allocate memory for the keyscheduled key */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( status = secureMalloc( &cryptInfo->key, DES_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr->isDESX == CRYPT_USE_DEFAULT )
		{
		cryptInfo->privateUseDefaults = TRUE;
		setDESinfo( cryptInfo, FALSE );
		}
	else
		setDESinfo( cryptInfo, ( BOOLEAN ) cryptInfoExPtr->isDESX );
	cryptInfo->keyLength = DES_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int desInit( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_DES cryptInfoEx;

	/* Use standard 2-key EDE triple DES */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_DES ) );
	cryptInfoEx.isDESX = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( desInitEx( cryptInfo, &cryptInfoEx ) );
	}

int desEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int desEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int desEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	BYTE temp[ DES_BLOCKSIZE ];
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, DES_BLOCKSIZE );

		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_DECRYPT );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int desEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];
		memcpy( cryptInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 desKey->desKey, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	BYTE temp[ DES_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];
		memcpy( cryptInfo->currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 desKey->desKey, DES_ENCRYPT );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int desEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 desKey->desKey, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 desKey->desKey, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in PCBC mode.  We have to carry along the previous
   block's plaintext as well as the IV so we store it after the IV in the
   buffer allocated for IV storage.  Initially the plaintextChain value will
   be null as the IV buffer is zeroed on init, so we don't need to worry
   about the special case of the first ciphertext block */

int desEncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + DES_BLOCKSIZE;
	BYTE temp[ DES_BLOCKSIZE ];
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Remember the previous block's plaintext and copy the current
		   plaintext for chaining in the next iteration */
		memcpy( temp, plaintextChain, DES_BLOCKSIZE );
		memcpy( plaintextChain, buffer, DES_BLOCKSIZE );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ temp[ i ];

		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + DES_BLOCKSIZE;
	BYTE temp[ DES_BLOCKSIZE ];
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, DES_BLOCKSIZE );

		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 desKey->desKey, DES_DECRYPT );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ plaintextChain[ i ];

		/* Shift the ciphertext into the IV and copy the current plaintext
		   for chaining in the next iteration */
		memcpy( cryptInfo->currentIV, temp, DES_BLOCKSIZE );
		memcpy( plaintextChain, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES Key Management Routines						*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

BOOLEAN getDESinfo( const CRYPT_INFO *cryptInfo )
	{
	return( ( ( DES_KEY * ) cryptInfo->key )->isDESX );
	}

void setDESinfo( CRYPT_INFO *cryptInfo, const BOOLEAN isDESX )
	{
	( ( DES_KEY * ) cryptInfo->key )->isDESX = isDESX;
	}

int desGetKeysize( CRYPT_INFO *cryptInfo )
	{
	return( ( ( ( DES_KEY * ) cryptInfo->key )->isDESX ) ? \
			bitsToBytes( 64 + 64 + 64 ) : bitsToBytes( 64 ) );
	}

/* Key schedule a DES key */

int desInitKey( CRYPT_INFO *cryptInfo )
	{
	DES_KEY *desKey = ( DES_KEY * ) cryptInfo->key;

	/* If it's a long key, make sure we're using DESX */
	if( cryptInfo->userKeyLength > bitsToBytes( 64 ) && !desKey->isDESX )
		return( CRYPT_BADPARM3 );

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong (which never occurs since we force the correct parity) or -2
	   if a weak key is used */
	des_set_odd_parity( ( C_Block * ) cryptInfo->userKey );
	if( key_sched( ( C_Block * ) cryptInfo->userKey,
				   *( ( Key_schedule * ) cryptInfo->key ) ) )
		return( CRYPT_BADPARM );
	if( desKey->isDESX )
		{
		/* DESX isn't implemented yet - need test vectors before using it */
		return( CRYPT_ERROR );	/*!!!!!!!!!!!!!!!!*/
		}

	return( CRYPT_OK );
	}
