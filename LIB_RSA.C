/****************************************************************************
*																			*
*						cryptlib RSA Encryption Routines					*
*						Copyright Peter Gutmann 1993-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/****************************************************************************
*																			*
*							RSA Self-test Routines							*
*																			*
****************************************************************************/

/* Test the RSA implementation using a sample key.  Because a lot of the
   high-level encryption routines don't exist yet, we cheat a bit and set
   up a dummy encryption context with just enough information for the
   following code to work */

typedef struct {
	int nLen; BYTE n[ 64 ];
	int eLen; BYTE e[ 1 ];
	int dLen; BYTE d[ 64 ];
	int pLen; BYTE p[ 32 ];
	int qLen; BYTE q[ 32 ];
	int uLen; BYTE u[ 32 ];
	int e1Len; BYTE e1[ 32 ];
	int e2Len; BYTE e2[ 32 ];
	} RSA_PRIVKEY;

static RSA_PRIVKEY rsaTestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A, 
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F, 
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20, 
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54, 
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2, 
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x68, 0x45, 0x00, 0x64, 0x32, 0x9D, 0x09, 0x6E, 
	  0x0A, 0xD3, 0xF3, 0x8A, 0xFE, 0x15, 0x8C, 0x79,
	  0xAD, 0x84, 0x35, 0x05, 0x19, 0x2C, 0x19, 0x51,
	  0xAB, 0x83, 0xC7, 0xE8, 0x5C, 0xAC, 0xAD, 0x7A },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B, 
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B, 
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

int rsaInitKey( CRYPT_INFO *cryptInfo );
int rsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int rsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int rsaSelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	CRYPT_PKCINFO_RSA *rsaKey;
	CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_RSA, CRYPT_MODE_PKC, 0,
									   NULL, NULL, CRYPT_ERROR, 64, 128, 512,
									   0, 0, 0, NULL, NULL, NULL, NULL, NULL,
									   NULL, NULL, NULL, NULL, NULL,
									   CRYPT_ERROR, NULL };
	BYTE buffer[ 64 ];
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the BigNum information and components */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	bnBegin( &cryptInfo.pkcParam1 );
	bnBegin( &cryptInfo.pkcParam2 );
	bnBegin( &cryptInfo.pkcParam3 );
	bnBegin( &cryptInfo.pkcParam4 );
	bnBegin( &cryptInfo.pkcParam5 );
	bnBegin( &cryptInfo.pkcParam6 );
	bnBegin( &cryptInfo.pkcParam7 );
	bnBegin( &cryptInfo.pkcParam8 );
	cryptInfo.keyComponentsLittleEndian = FALSE;
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsaTestKey.n, rsaTestKey.nLen );
	cryptSetComponent( rsaKey->e, rsaTestKey.e, rsaTestKey.eLen );
	cryptSetComponent( rsaKey->d, rsaTestKey.d, rsaTestKey.dLen );
	cryptSetComponent( rsaKey->p, rsaTestKey.p, rsaTestKey.pLen );
	cryptSetComponent( rsaKey->q, rsaTestKey.q, rsaTestKey.qLen );
	cryptSetComponent( rsaKey->u, rsaTestKey.u, rsaTestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsaTestKey.e1, rsaTestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsaTestKey.e2, rsaTestKey.e2Len );
	cryptInfo.keyComponentPtr = rsaKey;
	cryptInfo.capabilityInfo = &capabilityInfo;

	/* Perform the test en/decryption of a block of data */
	memset( buffer, 0, 64 );
	memcpy( buffer, "abcde", 5 );
	rsaInitKey( &cryptInfo );
	if( ( status = rsaEncrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT ) ) == CRYPT_OK )
		status = rsaDecrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT );
	if( status != CRYPT_OK || memcmp( buffer, "abcde", 5 ) )
		status = CRYPT_SELFTEST;

	/* Clean up */
	cryptDestroyComponents( rsaKey );
	bnEnd( &cryptInfo.pkcParam1 );
	bnEnd( &cryptInfo.pkcParam2 );
	bnEnd( &cryptInfo.pkcParam3 );
	bnEnd( &cryptInfo.pkcParam4 );
	bnEnd( &cryptInfo.pkcParam5 );
	bnEnd( &cryptInfo.pkcParam6 );
	bnEnd( &cryptInfo.pkcParam7 );
	bnEnd( &cryptInfo.pkcParam8 );
	zeroise( &cryptInfo, sizeof( CRYPT_INFO ) );
	free( rsaKey );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the RSA routines */

/****************************************************************************
*																			*
*							RSA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt a single block of data  */

int rsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM n;
	int length = bitsToBytes( cryptInfo->keySizeBits ), status = CRYPT_OK;

	/* The length of the encrypted data is determined by the PKC key size */
	UNUSED( noBytes );

	/* Move the data from the buffer into a bignum, perform the modexp,
	   and move the result back into the buffer */
	bnBegin( &n );
	bnInsertBigBytes( &n, buffer, 0, length );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */
	if( bnExpMod( &n, &n, &cryptInfo->rsaParam_e, &cryptInfo->rsaParam_n ) != 0 )
		status = CRYPT_PKCCRYPT;
	bnExtractBigBytes( &n, buffer, 0, length );
	bnEnd( &n );

	return( status );
	}

/* Use the Chinese Remainder Theorem shortcut for RSA decryption.
   M is the output plaintext message, C is the input ciphertext message,
   d is the secret decryption exponent, p and q are the prime factors of n,
   u is the multiplicative inverse of q, mod p.  n, the common modulus, is not
   used because of the Chinese Remainder Theorem shortcut */

int rsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM *p = &cryptInfo->rsaParam_p, *q = &cryptInfo->rsaParam_q;
	BIGNUM *u = &cryptInfo->rsaParam_u, *e1 = &cryptInfo->rsaParam_exponent1;
	BIGNUM *e2 = &cryptInfo->rsaParam_exponent2;
	BIGNUM data, p2, q2, temp1, temp2;
	int length = bitsToBytes( cryptInfo->keySizeBits ), status = 0;

	/* The length of the encrypted data is determined by the PKC key size */
	UNUSED( noBytes );

	/* Initialise the bignums */
	bnBegin( &p2 );
	bnBegin( &q2 );
	bnBegin( &temp1 );
	bnBegin( &temp2 );
	bnBegin( &data );
	bnInsertBigBytes( &data, buffer, 0, length );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */

	/* Make sure that p < q */
	if( bnCmp( p, q ) >= 0 )
		bnSwap( p, q );

	/* Rather than decrypting by computing modexp with full mod n precision,
	   compute a shorter modexp with mod p precision:

	   p2 = ( ( C mod p ) ** exponent1 ) mod p */
	CK( bnCopy( &temp1, p ) );
	CK( bnMod( &temp1, &data, p ) );	/* temp1 = C mod p  */
	CK( bnExpMod( &p2, &temp1, e1, p ) );

	/* Then compute a short modexp with mod q precision:

	   q2 = ( ( C mod q ) ** exponent2 ) mod q */
	CK( bnCopy( &temp1, q ) );
	CK( bnMod( &temp1, &data, q ) );	/* temp1 = C mod q  */
	CK( bnExpMod( &q2, &temp1, e2, q ) );

	/* Now use the multiplicative inverse u to combine the two halves, saving
	   a lot of time by avoiding a full mod n exponentiation.  At key
	   generation time, u was computed with the secret key as the
	   multiplicative inverse of p, mod q such that ( p * u ) mod q = 1,
	   assuming p < q */
	if( !bnCmp( &p2, &q2 ) )
		/* Only happens if C < p */
		CK( bnCopy( &data, &p2 ) );
	else
		{
		/* q2 = q2 - p2; if q2 < 0 then q2 = q2 + q */
		if( bnSub( &q2, &p2 ) == 1 )
			{
			/* Since bnlib doesn't work with negative numbers, we need to
			   perform a reverse subtract on q to obtain the intended result.
			   This rarely happens, so we perform a few extra steps here
			   rather than checking if q2 would go negative before the
			   subtract */
			CK( bnCopy( &temp1, q ) );
			CK( bnSub( &temp1, &q2 ) );
			CK( bnCopy( &q2, &temp1 ) );
			}

		/* M = ( ( ( q2 * u ) mod q ) * p ) + p2 */
		CK( bnMul( &temp1, &q2, u ) );		/* temp1 = q2 * u  */
		CK( bnMod( &temp2, &temp1, q ) );	/* temp2 = temp1 mod q */
		CK( bnMul( &temp1, p, &temp2 ) );	/* temp1 = p * temp2 */
		CK( bnAdd( &temp1, &p2 ) );			/* temp1 = temp1 + p2 */
		CK( bnCopy( &data, &temp1 ) );		/* M = temp1 */
		}

	/* Copy the result to the output buffer and destroy sensitive data */
	bnExtractBigBytes( &data, buffer, 0, length );
	bnEnd( &p2 );
	bnEnd( &q2 );
	bnEnd( &temp1 );
	bnEnd( &temp2 );
	bnEnd( &data );

	return( ( status == -1 ) ? CRYPT_PKCCRYPT : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RSA Key Management Routines						*
*																			*
****************************************************************************/

/* Load RSA public/private key components into an encryption context */

int rsaInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) cryptInfo->keyComponentPtr;
	int status = CRYPT_OK;

	/* Allocate storage for the external-format key components */
	if( ( status = secureMalloc( &cryptInfo->pkcInfo,
								 sizeof( CRYPT_PKCINFO_RSA ) ) ) != CRYPT_OK )
		return( status );

	/* Load the key component from the external representation into the
	   internal BigNums */
	cryptInfo->keyComponentsLittleEndian = rsaKey->endianness;
	cryptInfo->isPublicKey = rsaKey->isPublicKey;
	if( cryptInfo->keyComponentsLittleEndian )
		{
		bnInsertLittleBytes( &cryptInfo->rsaParam_n, rsaKey->n, 0,
							 bitsToBytes( rsaKey->nLen ) );
		bnInsertLittleBytes( &cryptInfo->rsaParam_e, rsaKey->e, 0,
							 bitsToBytes( rsaKey->eLen ) );
		if( !rsaKey->isPublicKey )
			{
			bnInsertLittleBytes( &cryptInfo->rsaParam_d, rsaKey->d, 0,
								 bitsToBytes( rsaKey->dLen ) );
			bnInsertLittleBytes( &cryptInfo->rsaParam_p, rsaKey->p, 0,
								 bitsToBytes( rsaKey->pLen ) );
			bnInsertLittleBytes( &cryptInfo->rsaParam_q, rsaKey->q, 0,
								 bitsToBytes( rsaKey->qLen ) );
			bnInsertLittleBytes( &cryptInfo->rsaParam_u, rsaKey->u, 0,
								 bitsToBytes( rsaKey->uLen ) );
			bnInsertLittleBytes( &cryptInfo->rsaParam_exponent1,
								 rsaKey->e1, 0, bitsToBytes( rsaKey->e1Len ) );
			bnInsertLittleBytes( &cryptInfo->rsaParam_exponent2,
								 rsaKey->e2, 0, bitsToBytes( rsaKey->e2Len ) );
			}
		}
	else
		{
		bnInsertBigBytes( &cryptInfo->rsaParam_n, rsaKey->n, 0,
						  bitsToBytes( rsaKey->nLen ) );
		bnInsertBigBytes( &cryptInfo->rsaParam_e, rsaKey->e, 0,
						  bitsToBytes( rsaKey->eLen ) );
		if( !rsaKey->isPublicKey )
			{
			bnInsertBigBytes( &cryptInfo->rsaParam_d, rsaKey->d, 0,
							  bitsToBytes( rsaKey->dLen ) );
			bnInsertBigBytes( &cryptInfo->rsaParam_p, rsaKey->p, 0,
							  bitsToBytes( rsaKey->pLen ) );
			bnInsertBigBytes( &cryptInfo->rsaParam_q, rsaKey->q, 0,
							  bitsToBytes( rsaKey->qLen ) );
			bnInsertBigBytes( &cryptInfo->rsaParam_u, rsaKey->u, 0,
							  bitsToBytes( rsaKey->uLen ) );
			bnInsertBigBytes( &cryptInfo->rsaParam_exponent1,
							  rsaKey->e1, 0, bitsToBytes( rsaKey->e1Len ) );
			bnInsertBigBytes( &cryptInfo->rsaParam_exponent2,
							  rsaKey->e2, 0, bitsToBytes( rsaKey->e2Len ) );
			}
		}

	/* Load the key components into the external-format component storage */
	memcpy( cryptInfo->pkcInfo, rsaKey, sizeof( CRYPT_PKCINFO_RSA ) );

	/* Make sure the necessary key parameters have been initialised */
	if( !bnCmpQ( &cryptInfo->rsaParam_n, 0 ) || \
		!bnCmpQ( &cryptInfo->rsaParam_e, 0 ) )
		status = CRYPT_BADPARM2;
	if( !rsaKey->isPublicKey )
		if( !bnCmpQ( &cryptInfo->rsaParam_d, 0 ) || \
			!bnCmpQ( &cryptInfo->rsaParam_p, 0 ) || \
			!bnCmpQ( &cryptInfo->rsaParam_q, 0 ) || \
			!bnCmpQ( &cryptInfo->rsaParam_u, 0 ) )
		status = CRYPT_BADPARM2;

	/* If we're not using PKCS keys which have exponent1 = d mod ( p - 1 )
	   and exponent2 = d mod ( q - 1 ) precalculated, evaluate them now */
	if( !rsaKey->isPublicKey && !bnCmpQ( &cryptInfo->rsaParam_exponent1, 0 ) )
		{
		BIGNUM *d = &cryptInfo->rsaParam_d, tmp;
		CRYPT_PKCINFO_RSA *externalRSAkey = cryptInfo->pkcInfo;

		bnBegin( &tmp );
		CK( bnCopy( &tmp, &cryptInfo->rsaParam_p ) );
		CK( bnSubQ( &tmp, 1 ) );			/* tmp = p - 1 */
		CK( bnMod( &cryptInfo->rsaParam_exponent1, d, &tmp ) );
											/* exponent1 = d mod ( p - 1 ) ) */
		CK( bnCopy( &tmp, &cryptInfo->rsaParam_q ) );
		CK( bnSubQ( &tmp, 1 ) );			/* tmp = q - 1 */
		CK( bnMod( &cryptInfo->rsaParam_exponent2, d, &tmp ) );
											/* exponent1 = d mod ( q - 1 ) ) */
		bnEnd( &tmp );

		/* Check that everything went OK */
		status = ( status == -1 ) ? CRYPT_BADPARM2 : CRYPT_OK;

		/* Since these two fields weren't present in the external-format
		   form from which the key components were loaded, we need to insert
		   them back into the the local copy of the external-format data */
		if( cryptInfo->keyComponentsLittleEndian )
			{
			bnExtractLittleBytes( &cryptInfo->rsaParam_exponent1,
								  externalRSAkey->e1, 0,
								  bnBits( &cryptInfo->rsaParam_exponent1 ) );
			bnExtractLittleBytes( &cryptInfo->rsaParam_exponent2,
            					  externalRSAkey->e2, 0,
								  bnBits( &cryptInfo->rsaParam_exponent2 ) );
			}
		else
			{
			bnExtractBigBytes( &cryptInfo->rsaParam_exponent1,
            				   externalRSAkey->e1, 0,
							   bnBits( &cryptInfo->rsaParam_exponent1 ) );
			bnExtractBigBytes( &cryptInfo->rsaParam_exponent2,
							   externalRSAkey->e2, 0,
							   bnBits( &cryptInfo->rsaParam_exponent2 ) );
			}
		}

	/* Set the nominal keysize in bits */
	cryptInfo->keySizeBits = rsaKey->nLen;

	/* Finally, generate a key ID for this key */
	if( cryptStatusOK( status ) )
		status = generateKeyID( CRYPT_ALGO_RSA, cryptInfo->keyID, \
								&cryptInfo->keyIDlength, rsaKey );

	return( status );
	}
