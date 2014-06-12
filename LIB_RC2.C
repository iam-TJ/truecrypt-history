#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "rc2/rc2.h"

/****************************************************************************
*																			*
*								RC2 Self-test Routines						*
*																			*
****************************************************************************/

/* RC2 test vectors from RC2 specification */

static struct RC2_TEST {
	BYTE key[ 16 ];
	BYTE plainText[ 8 ];
	BYTE cipherText[ 8 ];
	} testRC2[] = {
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7 } },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74 } },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	  { 0x13, 0xDB, 0x35, 0x17, 0xD3, 0x21, 0x86, 0x9E } },
	{ { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31 } }
	};

/* Test the RC2 code against the RC2 test vectors */

int rc2SelfTest( void )
	{
	BYTE temp[ RC2_BLOCKSIZE ];
	RC2_KEY key;
	int i;

	for( i = 0; i < sizeof( testRC2 ) / sizeof( struct RC2_TEST ); i++ )
		{
		memcpy( temp, testRC2[ i ].plainText, RC2_BLOCKSIZE );
			rc2keyInit( &key, testRC2[ i ].key, 16 );
		rc2encrypt( &key, temp );
		if( memcmp( testRC2[ i ].cipherText, temp, RC2_BLOCKSIZE ) )
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

int rc2InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	UNUSED( cryptInfoEx );

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need */
	if( cryptInfo->key != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( sizeof( RC2_KEY ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, sizeof( RC2_KEY ) );
	cryptInfo->keyLength = sizeof( RC2_KEY );

	return( CRYPT_OK );
	}

int rc2Init( CRYPT_INFO *cryptInfo )
	{
	/* Just pass through to the extended setup routine */
	return( rc2InitEx( cryptInfo, NULL ) );
	}

int rc2End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC2 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int rc2EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		rc2encrypt( rc2Key, buffer );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc2DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		rc2decrypt( rc2Key, buffer );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int rc2EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		rc2encrypt( rc2Key, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc2DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	BYTE temp[ RC2_BLOCKSIZE ];
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, RC2_BLOCKSIZE );

		/* Decrypt a block of data */
		rc2decrypt( rc2Key, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int rc2EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int rc2DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	BYTE temp[ RC2_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->currentIV );

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
	cryptInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

	/* Clear the temporary buffer */
	memset( temp, 0, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int rc2EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int rc2DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in PCBC mode.  We have to carry along the previous
   block's plaintext as well as the IV so we store it after the IV in the
   buffer allocated for IV storage.  Initially the plaintextChain value will
   be null as the IV buffer is zeroed on init, so we don't need to worry
   about the special case of the first ciphertext block */

int rc2EncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + RC2_BLOCKSIZE;
	BYTE temp[ RC2_BLOCKSIZE ];
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Remember the previous block's plaintext and copy the current
		   plaintext for chaining in the next iteration */
		memcpy( temp, plaintextChain, RC2_BLOCKSIZE );
		memcpy( plaintextChain, buffer, RC2_BLOCKSIZE );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ temp[ i ];

		/* Encrypt a block of data */
		rc2encrypt( rc2Key, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

int rc2DecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;
	BYTE *plaintextChain = cryptInfo->currentIV + RC2_BLOCKSIZE;
	BYTE temp[ RC2_BLOCKSIZE ];
	int blockCount = noBytes / RC2_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % RC2_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, RC2_BLOCKSIZE );

		/* Decrypt a block of data */
		rc2decrypt( rc2Key, buffer );

		/* XOR the buffer contents with the IV and previous plaintext */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ] ^ plaintextChain[ i ];

		/* Shift the ciphertext into the IV and copy the current plaintext
		   for chaining in the next iteration */
		memcpy( cryptInfo->currentIV, temp, RC2_BLOCKSIZE );
		memcpy( plaintextChain, buffer, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	memset( temp, 0, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}


/****************************************************************************
*																			*
*							RC2 Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule an RC2 key */

int rc2InitKey( CRYPT_INFO *cryptInfo )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->key;

	rc2keyInit( rc2Key, cryptInfo->userKey, cryptInfo->userKeyLength );
	return( CRYPT_OK );
	}
