#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "libdes/des.h"

/* The DES block size */

#define DES_BLOCKSIZE	8

/* A structure to hold the keyscheduled DES keys */

typedef struct {
	BOOLEAN isThreeKey;				/* Whether two or three-key triple DES */
	Key_schedule desKey1;			/* The first DES key */
	Key_schedule desKey2;			/* The second DES key */
	Key_schedule desKey3;			/* The third DES key */
	} DES3_KEY;

/* The size of the keyscheduled DES and 3DES keys */

#define DES_KEYSIZE		sizeof( Key_schedule )
#define DES3_KEYSIZE	sizeof( DES3_KEY )

/****************************************************************************
*																			*
*								3DES Self-test Routines						*
*																			*
****************************************************************************/

/* Are there any 3DES test vectors?  Presumably X9F1 will eventually
   publish some... */

int des3SelfTest( void )
	{
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int des3InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_3DES *cryptInfoExPtr = ( CRYPT_INFO_3DES * ) cryptInfoEx;

	/* Allocate memory for the keyscheduled keys */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( DES3_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, DES3_KEYSIZE );
	if( cryptInfoExPtr->isThreeKey != CRYPT_USE_DEFAULT )
		( ( DES3_KEY * ) cryptInfo->key )->isThreeKey = cryptInfoExPtr->isThreeKey;
	cryptInfo->keyLength = DES3_KEYSIZE;

	return( CRYPT_OK );
	}

int des3Init( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_3DES cryptInfoEx;

	/* Use use standard 2-key EDE triple DES */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_3DES ) );
	cryptInfoEx.isThreeKey = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( des3InitEx( cryptInfo, &cryptInfoEx ) );
	}

int des3End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							3DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int des3EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int des3DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int des3EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int des3DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int des3EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int des3DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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
	memset( temp, 0, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int des3EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

/* Decrypt data in OFB mode */

int des3DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

int des3EncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int des3DecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

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
	memset( temp, 0, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							3DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule two DES keys */

int des3InitKey( CRYPT_INFO *cryptInfo )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong, -2 if a weak key is used */
	if( key_sched( ( des_cblock * ) cryptInfo->userKey, des3Key->desKey1 ) )
		return( CRYPT_BADPARM );
	if( key_sched( ( des_cblock * ) ( cryptInfo->userKey + bitsToBytes( 56 ) ),
				   des3Key->desKey2 ) )
		return( CRYPT_BADPARM );
	if( des3Key->isThreeKey )
		{
		if( key_sched( ( des_cblock * ) ( cryptInfo->userKey + bitsToBytes( 112 ) ),
					   des3Key->desKey3 ) )
			return( CRYPT_BADPARM );
		}
	else
		if( key_sched( ( des_cblock * ) cryptInfo->userKey, des3Key->desKey3 ) )
			return( CRYPT_BADPARM );

	return( CRYPT_OK );
	}
