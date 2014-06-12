#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "blowfish/blowfish.h"

/* The size of the expanded Blowfish keys */

#define BLOWFISH_EXPANDED_KEYSIZE		sizeof( BLOWFISH_KEY )

/****************************************************************************
*																			*
*							Blowfish Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Blowfish code against Bruce Schneiers test vectors */

int blowfishSelfTest( void )
	{
	BYTE *plain1 = ( BYTE * ) "BLOWFISH";
	BYTE *key1 = ( BYTE * ) "abcdefghijklmnopqrstuvwxyz";
	BYTE *cipher1 = ( BYTE * ) "\x32\x4E\xD0\xFE\xF4\x13\xA2\x03";
	BYTE *plain2 = ( BYTE * ) "\xFE\xDC\xBA\x98\x76\x54\x32\x10";
	BYTE *key2 = ( BYTE * ) "Who is John Galt?";
	BYTE *cipher2 = ( BYTE * ) "\xCC\x91\x73\x2B\x80\x22\xF6\x84";
	BLOWFISH_KEY bfKey;
	BYTE buffer[ 8 ];

	memcpy( buffer, plain1, 8 );
	if( blowfishKeyInit( &bfKey, key1, strlen( ( char * ) key1 ) ) != CRYPT_OK )
		return( CRYPT_ERROR );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher1, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain1, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain2, 8 );
	if( blowfishKeyInit( &bfKey, key2, strlen( ( char * ) key2 ) ) != CRYPT_OK )
		return( CRYPT_ERROR );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher2, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain2, 8 ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int blowfishInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_BLOWFISH *cryptInfoExPtr = ( CRYPT_INFO_BLOWFISH * ) cryptInfoEx;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need.  We don't process
	   cryptInfoExPtr->rounds at this point since we set things up when we
	   perform the blowfishInitKey() function, as the number of rounds is key-
	   dependant */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( BLOWFISH_EXPANDED_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, BLOWFISH_EXPANDED_KEYSIZE );
	if( ( cryptInfo->privateData = malloc( sizeof( CRYPT_INFO_BLOWFISH ) ) ) == NULL )
		{
		free( cryptInfo->key );
		cryptInfo->key = NULL;
		return( CRYPT_NOMEM );
		}
	cryptInfo->privateDataLength = sizeof( CRYPT_INFO_BLOWFISH );
	if( cryptInfoExPtr->useBlowfishSK == CRYPT_USE_DEFAULT )
		cryptInfoExPtr->useBlowfishSK = FALSE;
	memcpy( cryptInfo->privateData, cryptInfoEx, sizeof( CRYPT_INFO_BLOWFISH ) );
	cryptInfo->keyLength = BLOWFISH_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int blowfishInit( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_BLOWFISH cryptInfoEx;

	/* Use the default number of rounds and the non-enhanced Blowfish */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_BLOWFISH ) );
	cryptInfoEx.keySetupIterations = CRYPT_USE_DEFAULT;
	cryptInfoEx.useBlowfishSK = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( blowfishInitEx( cryptInfo, &cryptInfoEx ) );
	}

int blowfishEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );
	secureFree( &cryptInfo->privateData, cryptInfo->privateDataLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Blowfish En/Decryption Routines					*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int blowfishEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		blowfishEncrypt( blowfishKey, buffer );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int blowfishDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		blowfishDecrypt( blowfishKey, buffer );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int blowfishEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < BLOWFISH_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		blowfishEncrypt( blowfishKey, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, BLOWFISH_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int blowfishDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	BYTE temp[ BLOWFISH_BLOCKSIZE ];
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, BLOWFISH_BLOCKSIZE );

		/* Decrypt a block of data */
		blowfishDecrypt( blowfishKey, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < BLOWFISH_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, BLOWFISH_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int blowfishEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BLOWFISH_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > BLOWFISH_BLOCKSIZE ) ? BLOWFISH_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		blowfishEncrypt( blowfishKey, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int blowfishDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	BYTE temp[ BLOWFISH_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BLOWFISH_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > BLOWFISH_BLOCKSIZE ) ? BLOWFISH_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		blowfishEncrypt( blowfishKey, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % BLOWFISH_BLOCKSIZE );

	/* Clear the temporary buffer */
	memset( temp, 0, BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int blowfishEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BLOWFISH_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > BLOWFISH_BLOCKSIZE ) ? BLOWFISH_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		blowfishEncrypt( blowfishKey, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int blowfishDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BLOWFISH_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > BLOWFISH_BLOCKSIZE ) ? BLOWFISH_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		blowfishEncrypt( blowfishKey, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in PCBC mode.  We have to carry along the previous
   block's plaintext as well as the IV so we store it after the IV in the
   buffer allocated for IV storage.  Initially the plaintextChain value will
   be null as the IV buffer is zeroed on init, so we don't need to worry
   about the special case of the first ciphertext block */

int blowfishEncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + BLOWFISH_BLOCKSIZE;
	BYTE temp[ BLOWFISH_BLOCKSIZE ];
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Remember the previous block's plaintext and copy the current
		   plaintext for chaining in the next iteration */
		memcpy( temp, plaintextChain, BLOWFISH_BLOCKSIZE );
		memcpy( plaintextChain, buffer, BLOWFISH_BLOCKSIZE );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < BLOWFISH_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ temp[ i ];

		/* Encrypt a block of data */
		blowfishEncrypt( blowfishKey, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, BLOWFISH_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}

int blowfishDecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + BLOWFISH_BLOCKSIZE;
	BYTE temp[ BLOWFISH_BLOCKSIZE ];
	int blockCount = noBytes / BLOWFISH_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % BLOWFISH_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, BLOWFISH_BLOCKSIZE );

		/* Decrypt a block of data */
		blowfishDecrypt( blowfishKey, buffer );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < BLOWFISH_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ plaintextChain[ i ];

		/* Shift the ciphertext into the IV and copy the current plaintext
		   for chaining in the next iteration */
		memcpy( cryptInfo->currentIV, temp, BLOWFISH_BLOCKSIZE );
		memcpy( plaintextChain, buffer, BLOWFISH_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += BLOWFISH_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}


/****************************************************************************
*																			*
*							Blowfish Key Management Routines				*
*																			*
****************************************************************************/

/* Key schedule a Blowfish key */

int blowfishInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_BLOWFISH *cryptInfoEx = ( CRYPT_INFO_BLOWFISH * ) cryptInfo->privateData;
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	BOOLEAN shortKey = cryptInfo->userKeyLength <= bitsToBytes( 448 );
	int keySetupIterations = BLOWFISH_KEYSETUP_ITERATIONS;

	/* If the number of rounds has been preset, use this value */
	if( cryptInfoEx->keySetupIterations != CRYPT_USE_DEFAULT )
		keySetupIterations = cryptInfoEx->keySetupIterations;

	/* Set up the key for Blowfish or Blowfish-SK */
	if( cryptInfoEx->useBlowfishSK || !shortKey )
		return( blowfishKeyInitSK( blowfishKey, cryptInfo->userKey,
								   cryptInfo->userKeyLength,
								   keySetupIterations ) );
	else
		return( blowfishKeyInit( blowfishKey, cryptInfo->userKey,
								 cryptInfo->userKeyLength ) );
	}
