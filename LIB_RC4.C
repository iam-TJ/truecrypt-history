/****************************************************************************
*																			*
*						cryptlib RC4 Encryption Routines					*
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
  #include "rc4.h"
#else
  #include "rc/rc4.h"
#endif /* Compiler-specific includes */

/* The size of the expanded IDEA keys */

#define RC4_EXPANDED_KEYSIZE	sizeof( RC4KEY )

/****************************************************************************
*																			*
*								RC4 Self-test Routines						*
*																			*
****************************************************************************/

#include "testrc4.h"

/* Test the RC4 code against the test vectors from the BSAFE2 implementation */

static int rc4Test( BYTE *key, int keySize,
					BYTE *plaintext, BYTE *ciphertext, int length )
	{
	BYTE temp[ 512 ];
	RC4KEY rc4key;

	memcpy( temp, plaintext, length );
	rc4ExpandKey( &rc4key, key, keySize );
	rc4Crypt( &rc4key, temp, length );
	if( memcmp( ciphertext, temp, length ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}


int rc4SelfTest( void )
	{
	/* The testing gets somewhat messy here because of the variable-length
	   arrays, which isn't normally a problem with the fixed-length keys
	   and data used in the block ciphers */
	if( rc4Test( testRC4key1, sizeof( testRC4key1 ), testRC4plaintext1,
				 testRC4ciphertext1, sizeof( testRC4plaintext1 ) ) != CRYPT_OK ||
		rc4Test( testRC4key2, sizeof( testRC4key2 ), testRC4plaintext2,
				 testRC4ciphertext2, sizeof( testRC4plaintext2 ) ) != CRYPT_OK ||
		rc4Test( testRC4key3, sizeof( testRC4key3 ), testRC4plaintext3,
				 testRC4ciphertext3, sizeof( testRC4plaintext3 ) ) != CRYPT_OK ||
		rc4Test( testRC4key4, sizeof( testRC4key4 ), testRC4plaintext4,
				 testRC4ciphertext4, sizeof( testRC4plaintext4 ) ) != CRYPT_OK ||
		rc4Test( testRC4key5, sizeof( testRC4key5 ), testRC4plaintext5,
				 testRC4ciphertext5, sizeof( testRC4plaintext5 ) ) != CRYPT_OK )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int rc4InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	int status;

	UNUSED( cryptInfoEx );

	/* Allocate memory for the expanded key */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( status = secureMalloc( &cryptInfo->key, RC4_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->keyLength = RC4_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int rc4Init( CRYPT_INFO *cryptInfo )
	{
	/* Just pass the call through to the extended setup routine */
	return( rc4InitEx( cryptInfo, NULL ) );
	}

int rc4End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC4 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data.  Since RC4 is a stream cipher, encryption and
   decryption are one and the same */

int rc4Encrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	rc4Crypt( ( RC4KEY * ) cryptInfo->key, buffer, noBytes );

	return( CRYPT_OK );
	}

int rc4Decrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	rc4Crypt( ( RC4KEY * ) cryptInfo->key, buffer, noBytes );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC4 Key Management Routines						*
*																			*
****************************************************************************/

/* Create an expanded RC4 key */

int rc4InitKey( CRYPT_INFO *cryptInfo )
	{
	rc4ExpandKey( ( RC4KEY * ) cryptInfo->key, cryptInfo->userKey,
				  cryptInfo->userKeyLength );

	return( CRYPT_OK );
	}
