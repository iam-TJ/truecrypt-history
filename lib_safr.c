#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "safer/safer.h"

/* The SAFER key and block size */

#define SAFER_KEYSIZE	SAFER_KEY_LEN
#define SAFER_BLOCKSIZE	SAFER_BLOCK_LEN

#define SAFER_KEY		safer_key_t

/* The size of the expanded SAFER keys */

#define SAFER_EXPANDED_KEYSIZE		sizeof( SAFER_KEY )

/****************************************************************************
*																			*
*							SAFER Self-test Routines						*
*																			*
****************************************************************************/

#include "testsafr.h"

/* Test the SAFER-SK code against the test vectors from the ETH reference
   implementation */

int saferSelfTest( void )
	{
	BYTE temp[ SAFER_BLOCKSIZE ];
	SAFER_KEY key;
	int i;

	Safer_Init_Module();
	for( i = 0; i < sizeof( testSafer ) / sizeof( SAFER_TEST ); i++ )
		{
		memcpy( temp, testSafer[ i ].plaintext, SAFER_BLOCKSIZE );
		if( testSafer[ i ].rounds == SAFER_K64_DEFAULT_NOF_ROUNDS )
			Safer_Expand_Userkey( testSafer[ i ].key, \
								  testSafer[ i ].key, \
								  testSafer[ i ].rounds, TRUE, key );
		else
			Safer_Expand_Userkey( testSafer[ i ].key, \
								  testSafer[ i ].key + bitsToBytes( 64 ), \
								  testSafer[ i ].rounds, TRUE, key );
		Safer_Encrypt_Block( temp, key, temp );
		if( memcmp( testSafer[ i ].ciphertext, temp, SAFER_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int saferInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_SAFER *cryptInfoExPtr = ( CRYPT_INFO_SAFER * ) cryptInfoEx;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need.  We don't process
	   cryptInfoExPtr->rounds at this point since we set things up when we
	   perform the saferInitKey() function, as the number of rounds is key-
	   dependant */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( SAFER_EXPANDED_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, SAFER_EXPANDED_KEYSIZE );
	if( ( cryptInfo->privateData = malloc( sizeof( CRYPT_INFO_SAFER ) ) ) == NULL )
		{
		free( cryptInfo->key );
		cryptInfo->key = NULL;
		return( CRYPT_NOMEM );
		}
	if( cryptInfoExPtr->useSaferSK == CRYPT_USE_DEFAULT )
		cryptInfoExPtr->useSaferSK = FALSE;
	memcpy( cryptInfo->privateData, cryptInfoEx, sizeof( CRYPT_INFO_SAFER ) );
	cryptInfo->keyLength = SAFER_EXPANDED_KEYSIZE;

	/* Set up the SAFER data tables if necessary */
	Safer_Init_Module();

	return( CRYPT_OK );
	}

int saferInit( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_SAFER cryptInfoEx;

	/* Use the default number of rounds and the non-enhanced SAFER */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_MDCSHS ) );
	cryptInfoEx.rounds = CRYPT_USE_DEFAULT;
	cryptInfoEx.useSaferSK = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( saferInitEx( cryptInfo, &cryptInfoEx ) );
	}

int saferEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );
	secureFree( &cryptInfo->privateData, sizeof( CRYPT_INFO_SAFER ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SAFER En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int saferEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		Safer_Encrypt_Block( buffer, *saferKey, buffer );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		Safer_Decrypt_Block( buffer, *saferKey, buffer );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int saferEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		Safer_Encrypt_Block( buffer, *saferKey, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	BYTE temp[ SAFER_BLOCKSIZE ];
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, SAFER_BLOCKSIZE );

		/* Decrypt a block of data */
		Safer_Decrypt_Block( buffer, *saferKey, buffer );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int saferEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		Safer_Encrypt_Block( cryptInfo->currentIV, *saferKey, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int saferDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	BYTE temp[ SAFER_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		Safer_Encrypt_Block( cryptInfo->currentIV, *saferKey, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % SAFER_BLOCKSIZE );

	/* Clear the temporary buffer */
	memset( temp, 0, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int saferEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		Safer_Encrypt_Block( cryptInfo->currentIV, *saferKey, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int saferDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		Safer_Encrypt_Block( cryptInfo->currentIV, *saferKey, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SAFER Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule a SAFER key */

int saferInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_SAFER *cryptInfoEx = ( CRYPT_INFO_SAFER * ) cryptInfo->privateData;
	SAFER_KEY *saferKey = ( SAFER_KEY * ) cryptInfo->key;
	BOOLEAN shortKey = cryptInfo->userKeyLength <= bitsToBytes( 64 );

	/* If the number of rounds has been preset, use this value */
	if( cryptInfoEx->rounds != CRYPT_USE_DEFAULT )
		cryptInfoEx->currentRounds = cryptInfoEx->rounds;
	else
		/* Determine the number of rounds to use based on the key size */
		if( cryptInfoEx->useSaferSK )
			cryptInfoEx->currentRounds = ( shortKey ) ? \
				 SAFER_SK64_DEFAULT_NOF_ROUNDS : SAFER_SK128_DEFAULT_NOF_ROUNDS;
		else
			cryptInfoEx->currentRounds = ( shortKey ) ? \
				 SAFER_K64_DEFAULT_NOF_ROUNDS : SAFER_K128_DEFAULT_NOF_ROUNDS;

	/* Generate an expanded SAFER key */
	if( shortKey )
		Safer_Expand_Userkey( cryptInfo->userKey, \
							  cryptInfo->userKey, cryptInfoEx->currentRounds, \
							  cryptInfoEx->useSaferSK, *saferKey );
	else
		Safer_Expand_Userkey( cryptInfo->userKey, \
							  cryptInfo->userKey + bitsToBytes( 64 ), \
							  cryptInfoEx->currentRounds, \
							  cryptInfoEx->useSaferSK, *saferKey );

	return( CRYPT_OK );
	}
