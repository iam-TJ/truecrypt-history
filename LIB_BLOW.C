/****************************************************************************
*																			*
*					  cryptlib Blowfish Encryption Routines					*
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
  #include "blowfish.h"
#else
  #include "blowfish/blowfish.h"
#endif /* Compiler-specific includes */

/* The size of the expanded Blowfish keys */

#define BLOWFISH_EXPANDED_KEYSIZE		sizeof( BLOWFISH_KEY )

/****************************************************************************
*																			*
*							Blowfish Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Blowfish code against Bruce Schneiers test vectors (1 & 2) and
   Mike Morgans test vector (3) */

int blowfishSelfTest( void )
	{
	BYTE *plain1 = ( BYTE * ) "BLOWFISH";
	BYTE *key1 = ( BYTE * ) "abcdefghijklmnopqrstuvwxyz";
	BYTE cipher1[] = { 0x32, 0x4E, 0xD0, 0xFE, 0xF4, 0x13, 0xA2, 0x03 };
	BYTE plain2[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE *key2 = ( BYTE * ) "Who is John Galt?";
	BYTE cipher2[] = { 0xCC, 0x91, 0x73, 0x2B, 0x80, 0x22, 0xF6, 0x84 };
	BYTE plain3[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE key3[] = { 0x41, 0x79, 0x6E, 0xA0, 0x52, 0x61, 0x6E, 0xE4 };
	BYTE cipher3[] = { 0xE1, 0x13, 0xF4, 0x10, 0x2C, 0xFC, 0xCE, 0x43 };
	BYTE *plain4 = ( BYTE * ) "BLOWFISH";
	BYTE *key4 = ( BYTE * ) "Blowfish-SK test key";
	BYTE cipher4[] = { 0xB4, 0xA0, 0xDC, 0x81, 0xE1, 0x3E, 0xAF, 0x4F };

	BLOWFISH_KEY bfKey;
	BYTE buffer[ 8 ];

	/* Test the Blowfish implementation */
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
	memcpy( buffer, plain3, 8 );
	if( blowfishKeyInit( &bfKey, key3, 8 ) != CRYPT_OK )
		return( CRYPT_ERROR );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher3, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain3, 8 ) )
		return( CRYPT_ERROR );

	/* Test the Blowfish-SK implementation */
	memcpy( buffer, plain4, 8 );
	if( blowfishKeyInitSK( &bfKey, key4, strlen( ( char * ) key4 ), 10 ) != CRYPT_OK )
		return( CRYPT_ERROR );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher4, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain4, 8 ) )
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
	int status;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need.  We don't process
	   cryptInfoExPtr->rounds at this point since we set things up when we
	   perform the blowfishInitKey() function, as the number of rounds is key-
	   dependant */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( status = secureMalloc( &cryptInfo->key, BLOWFISH_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr->keySetupIterations == CRYPT_USE_DEFAULT && \
		cryptInfoExPtr->useBlowfishSK == CRYPT_USE_DEFAULT )
		cryptInfo->privateUseDefaults = TRUE;
	if( ( status = secureMalloc( &cryptInfo->privateData, sizeof( CRYPT_INFO_BLOWFISH ) ) ) != CRYPT_OK )
		{
		secureFree( &cryptInfo->key );
		return( status );
		}
	if( cryptInfoExPtr->useBlowfishSK == CRYPT_USE_DEFAULT )
		setBlowfishInfo( cryptInfo, FALSE,
						 cryptInfoExPtr->keySetupIterations );
	else
		setBlowfishInfo( cryptInfo, ( BOOLEAN ) cryptInfoExPtr->useBlowfishSK,
						 cryptInfoExPtr->keySetupIterations );
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
	secureFree( &cryptInfo->key );
	secureFree( &cryptInfo->privateData );

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
	zeroise( temp, BLOWFISH_BLOCKSIZE );

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
	zeroise( temp, BLOWFISH_BLOCKSIZE );

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
	zeroise( temp, BLOWFISH_BLOCKSIZE );

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
	zeroise( temp, BLOWFISH_BLOCKSIZE );

	return( CRYPT_OK );
	}


/****************************************************************************
*																			*
*							Blowfish Key Management Routines				*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int getBlowfishInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useBlowfishSK )
	{
	CRYPT_INFO_BLOWFISH *cryptInfoEx = ( CRYPT_INFO_BLOWFISH * ) cryptInfo->privateData;

	*useBlowfishSK = cryptInfoEx->useBlowfishSK;
	return( cryptInfoEx->keySetupIterations );
	}

void setBlowfishInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useBlowfishSK,
					  const int keySetupIterations )
	{
	CRYPT_INFO_BLOWFISH *cryptInfoEx = ( CRYPT_INFO_BLOWFISH * ) cryptInfo->privateData;

	cryptInfoEx->useBlowfishSK = useBlowfishSK;
	cryptInfoEx->keySetupIterations = keySetupIterations;
	}

int blowfishGetKeysize( CRYPT_INFO *cryptInfo )
	{
	/* This is tricky, since we dynamically adjust the key type to 448 or
	   CRYPT_MAX_KEYSIZE bits depending on how much keying data we've been
	   passed by the user, but we can't tell in advance how much this will
	   be.  We get around this by taking advantage of the fact that when the
	   library queries the key size for an encryption context with no key
	   loaded, it always wants to know the maximum amount of data it can use
	   for a key, so we just return the maximum value */
	if( cryptInfo->userKeyLength == 0 )
		return( CRYPT_MAX_KEYSIZE );

	/* If the key has already been set up, just return the size of the key
	   we're using */
	return( cryptInfo->userKeyLength );
	}

/* Key schedule a Blowfish key */

int blowfishInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_BLOWFISH *cryptInfoEx = ( CRYPT_INFO_BLOWFISH * ) cryptInfo->privateData;
	BLOWFISH_KEY *blowfishKey = ( BLOWFISH_KEY * ) cryptInfo->key;
	int keySetupIterations = BLOWFISH_KEYSETUP_ITERATIONS;

	/* If it's a long key, make sure we're using Blowfish-SK */
	if( cryptInfo->userKeyLength > bitsToBytes( 448 ) && \
		!cryptInfoEx->useBlowfishSK )
		return( CRYPT_BADPARM3 );

	/* If the number of rounds has been preset, use this value */
	if( cryptInfoEx->keySetupIterations != CRYPT_USE_DEFAULT )
		keySetupIterations = cryptInfoEx->keySetupIterations;

	/* Set up the key for Blowfish or Blowfish-SK */
	if( cryptInfoEx->useBlowfishSK )
		return( blowfishKeyInitSK( blowfishKey, cryptInfo->userKey,
								   cryptInfo->userKeyLength,
								   keySetupIterations ) );
	else
		return( blowfishKeyInit( blowfishKey, cryptInfo->userKey,
								 cryptInfo->userKeyLength ) );
	}
