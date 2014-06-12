/****************************************************************************
*																			*
*						cryptlib Safer Encryption Routines					*
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
  #include "safer.h"
#else
  #include "safer/safer.h"
#endif /* Compiler-specific includes */

/* The size of the expanded SAFER keys */

#define SAFER_EXPANDED_KEYSIZE		SAFER_KEYLEN

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
	BYTE key[ SAFER_KEYLEN ];
	int i;

	for( i = 0; i < sizeof( testSafer ) / sizeof( SAFER_TEST ); i++ )
		{
		memcpy( temp, testSafer[ i ].plaintext, SAFER_BLOCKSIZE );
		if( testSafer[ i ].rounds == SAFER_K64_ROUNDS )
			/* We always do a 128-bit key schedule internally so if we're
			   using a 64-bit key we mirror the first 64 bits into the second
			   64 bits */
			memcpy( testSafer[ i ].key + bitsToBytes( 64 ),
					testSafer[ i ].key, bitsToBytes( 64 ) );
		saferExpandKey( key, testSafer[ i ].key, testSafer[ i ].rounds, TRUE );
		saferEncryptBlock( temp, key );
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
	int status;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need.  We don't process
	   cryptInfoExPtr->rounds at this point since we set things up when we
	   perform the saferInitKey() function, as the number of rounds is key-
	   dependant */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( status = secureMalloc( &cryptInfo->key, SAFER_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr->rounds == CRYPT_USE_DEFAULT && \
		cryptInfoExPtr->useSaferSK == CRYPT_USE_DEFAULT )
		cryptInfo->privateUseDefaults = TRUE;
	if( ( status = secureMalloc( &cryptInfo->privateData, sizeof( CRYPT_INFO_SAFER ) ) ) != CRYPT_OK )
		{
		secureFree( &cryptInfo->key );
		return( status );
		}
	if( cryptInfoExPtr->useSaferSK == CRYPT_USE_DEFAULT )
		setSaferInfo( cryptInfo, FALSE, cryptInfoExPtr->rounds );
	else
		setSaferInfo( cryptInfo, ( BOOLEAN ) cryptInfoExPtr->useSaferSK,
					  cryptInfoExPtr->rounds );
	cryptInfo->keyLength = SAFER_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int saferInit( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_SAFER cryptInfoEx;

	/* Use the default number of rounds and the non-enhanced SAFER */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_SAFER ) );
	cryptInfoEx.rounds = CRYPT_USE_DEFAULT;
	cryptInfoEx.useSaferSK = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( saferInitEx( cryptInfo, &cryptInfoEx ) );
	}

int saferEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key );
	secureFree( &cryptInfo->privateData );

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
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		saferEncryptBlock( buffer, saferKey );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		saferDecryptBlock( buffer, saferKey );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int saferEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		saferEncryptBlock( buffer, saferKey );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
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
		saferDecryptBlock( buffer, saferKey );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int saferEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
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
		saferEncryptBlock( cryptInfo->currentIV, saferKey );

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
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
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
		saferEncryptBlock( cryptInfo->currentIV, saferKey );

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
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int saferEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
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
		saferEncryptBlock( cryptInfo->currentIV, saferKey );

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
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
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
		saferEncryptBlock( cryptInfo->currentIV, saferKey );

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

/* Encrypt/decrypt data in PCBC mode.  We have to carry along the previous
   block's plaintext as well as the IV so we store it after the IV in the
   buffer allocated for IV storage.  Initially the plaintextChain value will
   be null as the IV buffer is zeroed on init, so we don't need to worry
   about the special case of the first ciphertext block */

int saferEncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + SAFER_BLOCKSIZE;
	BYTE temp[ SAFER_BLOCKSIZE ];
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % SAFER_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Remember the previous block's plaintext and copy the current
		   plaintext for chaining in the next iteration */
		memcpy( temp, plaintextChain, SAFER_BLOCKSIZE );
		memcpy( plaintextChain, buffer, SAFER_BLOCKSIZE );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ temp[ i ];

		/* Encrypt a block of data */
		saferEncryptBlock( buffer, saferKey );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

int saferDecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + SAFER_BLOCKSIZE;
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
		saferDecryptBlock( buffer, saferKey );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ plaintextChain[ i ];

		/* Shift the ciphertext into the IV and copy the current plaintext
		   for chaining in the next iteration */
		memcpy( cryptInfo->currentIV, temp, SAFER_BLOCKSIZE );
		memcpy( plaintextChain, buffer, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}


/****************************************************************************
*																			*
*							SAFER Key Management Routines					*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int getSaferInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useSaferSK )
	{
	CRYPT_INFO_SAFER *cryptInfoEx = ( CRYPT_INFO_SAFER * ) cryptInfo->privateData;

	*useSaferSK = ( BOOLEAN ) cryptInfoEx->useSaferSK;
	return( cryptInfoEx->rounds );
	}

void setSaferInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useSaferSK,
				   const int rounds )
	{
	CRYPT_INFO_SAFER *cryptInfoEx = ( CRYPT_INFO_SAFER * ) cryptInfo->privateData;

	cryptInfoEx->useSaferSK = ( int ) useSaferSK;
	cryptInfoEx->rounds = rounds;
	}

int saferGetKeysize( CRYPT_INFO *cryptInfo )
	{
	/* This is tricky, since we dynamically adjust the key type to 64 or 128
	   bits depending on how much keying data we've been passed by the user,
	   but we can't tell in advance how much this will be.  We get around
	   this by taking advantage of the fact that when the library queries the
	   key size for an encryption context with no key loaded, it always wants
	   to know the maximum amount of data it can use for a key, so we just
	   return the maximum value */
	if( cryptInfo->userKeyLength == 0 )
		return( bitsToBytes( 128 ) );

	/* If the key has already been set up, just return the type of key we're
	   using */
	return( ( cryptInfo->userKeyLength <= bitsToBytes( 64 ) ) ? \
			bitsToBytes( 64 ) : bitsToBytes( 128 ) );
	}

/* Key schedule a SAFER key */

int saferInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_SAFER *cryptInfoEx = ( CRYPT_INFO_SAFER * ) cryptInfo->privateData;
	BYTE *saferKey = ( BYTE * ) cryptInfo->key;
	BOOLEAN shortKey = cryptInfo->userKeyLength <= bitsToBytes( 64 );
	int currentRounds;

	/* If the number of rounds has been preset, use this value */
	if( cryptInfoEx->rounds != CRYPT_USE_DEFAULT )
		currentRounds = cryptInfoEx->rounds;
	else
		/* Determine the number of rounds to use based on the key size */
		if( cryptInfoEx->useSaferSK )
			currentRounds = ( shortKey ) ? SAFER_SK64_ROUNDS : SAFER_SK128_ROUNDS;
		else
			currentRounds = ( shortKey ) ? SAFER_K64_ROUNDS : SAFER_K128_ROUNDS;

	/* Generate an expanded SAFER key */
	if( shortKey )
		/* We always do a 128-bit key schedule internally so if we're using a
		   64-bit key we mirror the first 64 bits into the second 64 bits */
		memcpy( cryptInfo->userKey + bitsToBytes( 64 ), cryptInfo->userKey,
				bitsToBytes( 64 ) );
	saferExpandKey(	saferKey, cryptInfo->userKey, currentRounds,
					cryptInfoEx->useSaferSK );

	return( CRYPT_OK );
	}
