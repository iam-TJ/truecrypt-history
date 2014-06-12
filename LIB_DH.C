/****************************************************************************
*																			*
*					cryptlib Diffie-Hellman Key Exchange Routines			*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/****************************************************************************
*																			*
*						Predefined DH p and g Parameters					*
*																			*
****************************************************************************/

#include "testdh.h"

/* The structure for storing the primes */

typedef struct {
	int baseLen; BYTE base[ 1 ];
	int primeLen; BYTE *prime;
	} DH_PUBLIC_VALUES;

static DH_PUBLIC_VALUES dhPublicValues[] = {
	{ 1, { 0x02 }, 512, prime512 },
	{ 1, { 0x02 }, 768, prime768 },
	{ 1, { 0x02 }, 1024, prime1024 },
	{ 1, { 0x02 }, 1280, prime1280 },
	{ 1, { 0x02 }, 1536, prime1536 },
	{ 1, { 0x02 }, 2048, prime2048 },
	{ 1, { 0x02 }, 3072, prime3072 },
	{ 1, { 0x02 }, 4096, prime4096 },
	{ 0, { 0 }, 0, NULL }
	};

/****************************************************************************
*																			*
*						Diffie-Hellman Self-test Routines					*
*																			*
****************************************************************************/

/* Test the Diffie-Hellman implementation using a sample key exchange.
   Because a lot of the high-level encryption routines don't exist yet, we
   cheat a bit and set up a dummy encryption context with just enough
   information for the following code to work */

int dhInitKey( CRYPT_INFO *cryptInfo );
int dhEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int dhDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int dhSelfTest( void )
	{
	CRYPT_INFO cryptInfo1, cryptInfo2;
	CRYPT_PKCINFO_DH *dhKey;
	CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_DH, CRYPT_MODE_PKC, 0,
									   NULL, NULL, CRYPT_ERROR, 64, 128, 512,
									   0, 0, 0, NULL, NULL, NULL, NULL, NULL,
									   NULL, NULL, NULL, NULL, NULL,
									   CRYPT_ERROR, NULL };
	BYTE buffer1[ 64 ], buffer2[ 64 ];
	int status = CRYPT_OK;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DH * ) malloc( sizeof( CRYPT_PKCINFO_DH ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the BigNum information and components */
	cryptInitComponents( dhKey, 512, CRYPT_UNUSED );
	memset( &cryptInfo1, 0, sizeof( CRYPT_INFO ) );
	bnBegin( &cryptInfo1.pkcParam1 );
	bnBegin( &cryptInfo1.pkcParam2 );
	bnBegin( &cryptInfo1.pkcParam3 );
	cryptInfo1.keyComponentPtr = dhKey;
	cryptInfo1.capabilityInfo = &capabilityInfo;
	memset( &cryptInfo2, 0, sizeof( CRYPT_INFO ) );
	bnBegin( &cryptInfo2.pkcParam1 );
	bnBegin( &cryptInfo2.pkcParam2 );
	bnBegin( &cryptInfo2.pkcParam3 );
	cryptInfo2.keyComponentPtr = dhKey;
	cryptInfo2.capabilityInfo = &capabilityInfo;

	/* Perform the test key exchange on a block of data */
	memset( buffer1, 0, 64 );
	memcpy( buffer1, "abcde", 5 );
	memset( buffer2, 0, 64 );
	memcpy( buffer2, "efghi", 5 );
	if( dhInitKey( &cryptInfo1 ) != CRYPT_OK ||
		dhInitKey( &cryptInfo2 ) != CRYPT_OK ||
		dhEncrypt( &cryptInfo1, buffer1, CRYPT_USE_DEFAULT ) != CRYPT_OK ||
		dhEncrypt( &cryptInfo2, buffer2, CRYPT_USE_DEFAULT ) != CRYPT_OK ||
		dhDecrypt( &cryptInfo1, buffer2, CRYPT_USE_DEFAULT ) != CRYPT_OK ||
		dhDecrypt( &cryptInfo2, buffer1, CRYPT_USE_DEFAULT ) != CRYPT_OK ||
		memcmp( buffer1, buffer2, 64 ) )
		status = CRYPT_SELFTEST;

	/* Clean up */
	cryptDestroyComponents( dhKey );
	bnEnd( &cryptInfo1.pkcParam1 );
	bnEnd( &cryptInfo1.pkcParam2 );
	bnEnd( &cryptInfo1.pkcParam3 );
	zeroise( &cryptInfo1, sizeof( CRYPT_INFO ) );
	bnEnd( &cryptInfo2.pkcParam1 );
	bnEnd( &cryptInfo2.pkcParam2 );
	bnEnd( &cryptInfo2.pkcParam3 );
	zeroise( &cryptInfo2, sizeof( CRYPT_INFO ) );
	free( dhKey );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the DH routines */

/****************************************************************************
*																			*
*						Diffie-Hellman Key Exchange Routines				*
*																			*
****************************************************************************/

/* Perform phase 1 of Diffie-Hellman */

int dhEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM y;
	int length = bitsToBytes( cryptInfo->keySizeBits ), status = 0;

	/* The length of the encrypted data is determined by the PKC key size */
	UNUSED( noBytes );

	/* Move the public data from the buffer into a bignum making sure it
	   obeys the constraint 0 < x < p-1, perform phase 1 of DH, and move the
	   resulting public value back into the buffer.  Note that it would be
	   slightly more efficient to call bnTwoExpMod() in place of bnExpMod(),
	   but there's a chance the caller may want to use a base other than two,
	   and bnExpMod() calls bnTwoExpMod() anyway if the base == 2 */
	bnBegin( &y );
	bnInsertBigBytes( &cryptInfo->dhParam_x, buffer, 0, length );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */
	CK( bnMod( &cryptInfo->dhParam_x, &cryptInfo->dhParam_x,
			   &cryptInfo->dhParam_p ) );
	CK( bnSubQ( &cryptInfo->dhParam_x, 1 ) );
	CK( bnExpMod( &y, &cryptInfo->dhParam_g, &cryptInfo->dhParam_x,
				  &cryptInfo->dhParam_p ) );
	bnExtractBigBytes( &y, buffer, 0, length );
	bnEnd( &y );

	return( ( status == -1 ) ? CRYPT_PKCCRYPT : CRYPT_OK );
	}

/* Perform phase 2 of Diffie-Hellman */

int dhDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM y, z;
	int length = bitsToBytes( cryptInfo->keySizeBits ), status = CRYPT_OK;

	/* The length of the data is determined by the DH key size */
	UNUSED( noBytes );

	/* Move the public data from the buffer into a bignum, perform phase 2
	   of DH, and move the resulting secret value back into the buffer */
	bnBegin( &y );
	bnBegin( &z );
	bnInsertBigBytes( &y, buffer, 0, length );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */
	if( bnExpMod( &z, &y, &cryptInfo->dhParam_x, &cryptInfo->dhParam_p ) != 0 )
		status = CRYPT_PKCCRYPT;
	bnExtractBigBytes( &z, buffer, 0, length );
	bnEnd( &z );
	bnEnd( &y );

	return( status );
	}

/****************************************************************************
*																			*
*						Diffie-Hellman Key Management Routines				*
*																			*
****************************************************************************/

/* Load DH public key components into an encryption context */

int dhInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_PKCINFO_DH *dhKey = ( CRYPT_PKCINFO_DH * ) cryptInfo->keyComponentPtr;
	int status = CRYPT_OK;

	/* Make sure the last parameter is correct.  Sinc the DH parameters are
	   somewhat different from those used for normal PKC's, this is a useful
	   test to make sure the caller hasn't confused things */
	if( dhKey->isPublicKey != CRYPT_UNUSED )
		return( CRYPT_BADPARM3 );

	/* Allocate storage for the external-format key components */
	if( ( status = secureMalloc( &cryptInfo->pkcInfo,
								 sizeof( CRYPT_PKCINFO_DH ) ) ) != CRYPT_OK )
		return( status );

	/* If a key size is given, use the default public values */
	if( dhKey->endianness > CRYPT_COMPONENTS_LITTLENDIAN )
		{
		CRYPT_PKCINFO_DH *externalDHkey = cryptInfo->pkcInfo;
		int index, size = dhKey->endianness;

		/* Determine which parameters to use */
		for( index = 0; dhPublicValues[ index ].primeLen && \
			 dhPublicValues[ index ].primeLen != size; index++ );
		if( !dhPublicValues[ index ].primeLen )
			return( CRYPT_BADPARM2 );

		/* Load them into the external-format component storage */
		cryptInitComponents( externalDHkey, CRYPT_COMPONENTS_BIGENDIAN,
							 CRYPT_UNUSED );
		cryptSetComponent( externalDHkey->p, dhPublicValues[ index ].prime, size );
		cryptSetComponent( externalDHkey->g, dhPublicValues[ index ].base, 1 );

		/* Load them into the internal-format component storage and generate
		   a key ID for them */
		bnInsertBigBytes( &cryptInfo->dhParam_p, dhPublicValues[ index ].prime,
						  0, bitsToBytes( size ) );
		bnInsertBigBytes( &cryptInfo->dhParam_g, dhPublicValues[ index ].base,
						  0, 1 );
		cryptInfo->keySizeBits = size;

		return( generateKeyID( CRYPT_ALGO_DH, cryptInfo->keyID, \
							   &cryptInfo->keyIDlength, dhKey ) );
		}

	/* Load the key components into the external-format component storage */
	memcpy( cryptInfo->pkcInfo, dhKey, sizeof( CRYPT_PKCINFO_DH ) );

	/* Load the key component from the external representation into the
	   internal BigNums */
	cryptInfo->keyComponentsLittleEndian = dhKey->endianness;
	if( cryptInfo->keyComponentsLittleEndian )
		{
		bnInsertLittleBytes( &cryptInfo->dhParam_p, dhKey->p, 0,
							 bitsToBytes( dhKey->pLen ) );
		bnInsertLittleBytes( &cryptInfo->dhParam_g, dhKey->g, 0,
							 bitsToBytes( dhKey->gLen ) );
		}
	else
		{
		bnInsertBigBytes( &cryptInfo->dhParam_p, dhKey->p, 0,
						  bitsToBytes( dhKey->pLen ) );
		bnInsertBigBytes( &cryptInfo->dhParam_g, dhKey->g, 0,
						  bitsToBytes( dhKey->gLen ) );
		}

	/* Make sure the necessary key parameters have been initialised */
	if( !bnCmpQ( &cryptInfo->dhParam_p, 0 ) || \
		!bnCmpQ( &cryptInfo->dhParam_g, 0 ) )
		status = CRYPT_BADPARM2;

	/* Set the nominal keysize in bits */
	cryptInfo->keySizeBits = dhKey->pLen;

	/* Finally, generate a key ID for this key */
	if( cryptStatusOK( status ) )
		status = generateKeyID( CRYPT_ALGO_DH, cryptInfo->keyID, \
								&cryptInfo->keyIDlength, dhKey );

	return( status );
	}
