/****************************************************************************
*																			*
*						cryptlib DSA Encryption Routines					*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/****************************************************************************
*																			*
*							DSA Self-test Routines							*
*																			*
****************************************************************************/

/* Test the DSA implementation using the sample key from FIPS 186.  Because a
   lot of the high-level encryption routines don't exist yet, we cheat a bit
   and set up a dummy encryption context with just enough information for the
   following code to work */

typedef struct {
	int pLen; BYTE p[ 64 ];
	int qLen; BYTE q[ 20 ];
	int gLen; BYTE g[ 64 ];
	int xLen; BYTE x[ 20 ];
	int yLen; BYTE y[ 64 ];
	} DSA_PRIVKEY;

static DSA_PRIVKEY dsaTestKey = {
	/* p */
	512,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	160,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	512,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* x */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* y */
	512,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

#if 0
k =	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF

kinv =
	0x0D, 0x51, 0x67, 0x29, 0x82, 0x02, 0xE4, 0x9B,
	0x41, 0x16, 0xAC, 0x10, 0x4F, 0xC3, 0xF4, 0x15,
	0xAE, 0x52, 0xF9, 0x17

SHA(M) =
	0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
	0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
	0x9C, 0xD0, 0xD8, 0x9D

r =	0x8B, 0xAC, 0x1A, 0xB6, 0x64, 0x10, 0x43, 0x5C,
	0xB7, 0x18, 0x1F, 0x95, 0xB1, 0x6A, 0xB9, 0x7C,
	0x92, 0xB3, 0x41, 0xC0

s =	0x41, 0xE2, 0x34, 0x5F, 0x1F, 0x56, 0xDF, 0x24,
	0x58, 0xF4, 0x26, 0xD1, 0x55, 0xB4, 0xBA, 0x2D,
	0xB6, 0xDC, 0xD8, 0xC8

w =	0x9D, 0xF4, 0xEC, 0xE5, 0x82, 0x6B, 0xE9, 0x5F,
	0xED, 0x40, 0x6D, 0x41, 0xB4, 0x3E, 0xDC, 0x0B,
	0x1C, 0x18, 0x84, 0x1B

u1 =
	0xBF, 0x65, 0x5B, 0xD0, 0x46, 0xF0, 0xB3, 0x5E,
	0xC7, 0x91, 0xB0, 0x04, 0x80, 0x4A, 0xFC, 0xBB,
	0x8E, 0xF7, 0xD6, 0x9D

u2 =
	0x82, 0x1A, 0x92, 0x63, 0x12, 0xE9, 0x7A, 0xDE,
	0xAB, 0xCC, 0x8D, 0x08, 0x2B, 0x52, 0x78, 0x97,
	0x8A, 0x2D, 0xF4, 0xB0

gu1 moD p =
	0x51, 0xB1, 0xBF, 0x86, 0x78, 0x88, 0xE5, 0xF3,
	0xAF, 0x6F, 0xB4, 0x76, 0x9D, 0xD0, 0x16, 0xBC,
	0xFE, 0x66, 0x7A, 0x65, 0xAA, 0xFC, 0x27, 0x53,
	0x90, 0x63, 0xBD, 0x3D, 0x2B, 0x13, 0x8B, 0x4C,
	0xE0, 0x2C, 0xC0, 0xC0, 0x2E, 0xC6, 0x2B, 0xB6,
	0x73, 0x06, 0xC6, 0x3E, 0x4D, 0xB9, 0x5B, 0xBF,
	0x6F, 0x96, 0x66, 0x2A, 0x19, 0x87, 0xA2, 0x1B,
	0xE4, 0xEC, 0x10, 0x71, 0x01, 0x0B, 0x60, 0x69

yu2 moD p =
	0x8B, 0x51, 0x00, 0x71, 0x29, 0x57, 0xE9, 0x50,
	0x50, 0xD6, 0xB8, 0xFD, 0x37, 0x6A, 0x66, 0x8E,
	0x4B, 0x0D, 0x63, 0x3C, 0x1E, 0x46, 0xE6, 0x65,
	0x5C, 0x61, 0x1A, 0x72, 0xE2, 0xB2, 0x84, 0x83,
	0xBE, 0x52, 0xC7, 0x4D, 0x4B, 0x30, 0xDE, 0x61,
	0xA6, 0x68, 0x96, 0x6E, 0xDC, 0x30, 0x7A, 0x67,
	0xC1, 0x94, 0x41, 0xF4, 0x22, 0xBF, 0x3C, 0x34,
	0x08, 0xAE, 0xBA, 0x1F, 0x0A, 0x4D, 0xBE, 0xC7

v =	0x8B, 0xAC, 0x1A, 0xB6, 0x64, 0x10, 0x43, 0x5C,
	0xB7, 0x18, 0x1F, 0x95, 0xB1, 0x6A, 0xB9, 0x7C,
	0x92, 0xB3, 0x41, 0xC0
#endif

int dsaInitKey( CRYPT_INFO *cryptInfo );
int dsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int dsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int dsaSelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	CRYPT_PKCINFO_DSA *dsaKey;
	CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_DSA, CRYPT_MODE_PKC, 0,
									   NULL, NULL, CRYPT_ERROR, 64, 128, 512,
									   0, 0, 0, NULL, NULL, NULL, NULL, NULL,
									   NULL, NULL, NULL, NULL, NULL,
									   CRYPT_ERROR, NULL };
	BYTE buffer[ 64 ];
	int status;

	/* Allocate room for the public-key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DSA * ) malloc( sizeof( CRYPT_PKCINFO_DSA ) ) ) == NULL )
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
	cryptInitComponents( dsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( dsaKey->p, dsaTestKey.p, dsaTestKey.pLen );
	cryptSetComponent( dsaKey->q, dsaTestKey.q, dsaTestKey.qLen );
	cryptSetComponent( dsaKey->g, dsaTestKey.g, dsaTestKey.gLen );
	cryptSetComponent( dsaKey->x, dsaTestKey.x, dsaTestKey.xLen );
	cryptSetComponent( dsaKey->y, dsaTestKey.y, dsaTestKey.yLen );
	cryptInfo.keyComponentPtr = dsaKey;
	cryptInfo.capabilityInfo = &capabilityInfo;

	/* Perform the test en/decryption of a block of data */
	memset( buffer, 0, 64 );
	memcpy( buffer, "abcde", 5 );
	dsaInitKey( &cryptInfo );
#if 0	/* Make sure noone uses us for now */
	if( ( status = dsaEncrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT ) ) == CRYPT_OK )
		status = dsaDecrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT );
	if( status != CRYPT_OK || memcmp( buffer, "abcde", 5 ) )
#endif /* 0 */
		status = CRYPT_SELFTEST;

	/* Clean up */
	cryptDestroyComponents( dsaKey );
	bnEnd( &cryptInfo.pkcParam1 );
	bnEnd( &cryptInfo.pkcParam2 );
	bnEnd( &cryptInfo.pkcParam3 );
	bnEnd( &cryptInfo.pkcParam4 );
	bnEnd( &cryptInfo.pkcParam5 );
	bnEnd( &cryptInfo.pkcParam6 );
	bnEnd( &cryptInfo.pkcParam7 );
	bnEnd( &cryptInfo.pkcParam8 );
	zeroise( &cryptInfo, sizeof( CRYPT_INFO ) );
	free( dsaKey );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the DSA routines */

/****************************************************************************
*																			*
*							DSA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt (sign) a single block of data  */

int dsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM *p = &cryptInfo->dsaParam_p, *q = &cryptInfo->dsaParam_q;
	BIGNUM *g = &cryptInfo->dsaParam_g, *x = &cryptInfo->dsaParam_x;
	BIGNUM hash, k, r, s, temp;
	BYTE kBuffer[ CRYPT_MAX_PKCSIZE ];
	int length = bitsToBytes( cryptInfo->keySizeBits ), i, status = CRYPT_OK;

	/* The length of the encrypted data is determined by the PKC key size */
	UNUSED( noBytes );

	/* Initialise the bignums */
	bnBegin( &hash );
	bnBegin( &k );
	bnBegin( &r );
	bnBegin( &s );
	bnBegin( &temp );

	/* Generate the secret random value k */
	for( i = 0; i < length; i++ )
		kBuffer[ i ] = getRandomByte();
	kBuffer[ 0 ] |= 0x80;	/* Make the random value as big as possible */
	bnInsertBigBytes( &k, kBuffer, 0, length );
	bnMod( &k, &k, q );		/* Reduce k to the correct range */
	zeroise( kBuffer, length );

	/* Move the data from the buffer into a bignum */
	bnInsertBigBytes( &hash, buffer, 0, length );

	/* r = ( g ^ k mod p ) mod q */
	CK( bnExpMod( &r, g, &k, p ) );
	CK( bnMod( &r, &r, q ) );

	/* s = k^-1 * ( hash + x * r ) mod q */
	CK( bnInv( &temp, &k, q ) );		/* temp = k^-1 */
	CK( bnMul( &s, x, &r ) );			/* s = x * r */
	CK( bnMod( &s, &s, q ) );			/* s = s mod q */
	CK( bnAdd( &s, &hash ) );			/* s = s + hash */
	if( bnCmp( &s, q ) > 0 )			/* if s > q */
		CK( bnSub( &s, q ) );			/*	 s = s - q */
	CK( bnMul( &s, &s, &temp ) );		/* s = s * k^-1 */
	CK( bnMod( &s, &s, q ) );			/* s = s mod q */

	/* Copy the result to the output buffer and destroy sensitive data */
	bnExtractBigBytes( &r, buffer, 0, length );
	bnBegin( &temp );
	bnBegin( &s );
	bnBegin( &r );
	bnBegin( &k );
	bnBegin( &hash );

	return( ( status == -1 ) ? CRYPT_PKCCRYPT : CRYPT_OK );
	}

/* Decryption (signature check) a single block of data */

int dsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BIGNUM *p = &cryptInfo->dsaParam_p, *q = &cryptInfo->dsaParam_q;
	BIGNUM *g = &cryptInfo->dsaParam_g, *y = &cryptInfo->dsaParam_y;
	BIGNUM r, s, w, u1, u2;
	int length = bitsToBytes( cryptInfo->keySizeBits ), status = 0;

	/* The length of the encrypted data is determined by the PKC key size */
	UNUSED( noBytes );

	/* Initialise the bignums */
	bnBegin( &r );
	bnBegin( &s );
	bnBegin( &w );
	bnBegin( &u1 );
	bnBegin( &u2 );
	bnInsertBigBytes( &r, buffer, 0, length );

	/* w = s^-1 mod q */
	CK( bnInv( &w, &s, q ) );

	/* u1 = ( hash * w ) mod q
	CK( bnMul( &u1, hash, &w ) );
	CK( bnMod(&u1, &u1, q ) );

	/* u2 = ( r * w ) mod q */
	CK( bnMul( &u2, &r, &w ) );
	CK( bnMod( &u2, &u2, q ) );

	/* v = ( ( ( g^u1 ) * ( y^u2 ) ) mod p ) mod q */
	CK( bnDoubleExpMod( &w, g, &u1, y, &u2, p ) );
	CK( bnMod( &w, &w, q ) );

	/* if( !bnCmp( r, &w ) ) => sig = OK */

	/* Copy the result to the output buffer and destroy sensitive data */
	bnExtractBigBytes( &w, buffer, 0, length );
	bnBegin( &u2 );
	bnBegin( &u1 );
	bnBegin( &w );
	bnBegin( &s );
	bnBegin( &r );

	return( ( status == -1 ) ? CRYPT_PKCCRYPT : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DSA Key Management Routines						*
*																			*
****************************************************************************/

/* Load DSA public/private key components into an encryption context */

int dsaInitKey( CRYPT_INFO *cryptInfo )
	{
	CRYPT_PKCINFO_DSA *dsaKey = ( CRYPT_PKCINFO_DSA * ) cryptInfo->keyComponentPtr;
	int status = CRYPT_OK;

	/* Allocate storage for the external-format key components */
	if( ( status = secureMalloc( &cryptInfo->pkcInfo,
								 sizeof( CRYPT_PKCINFO_DSA ) ) ) != CRYPT_OK )
		return( status );

	/* Load the key component from the external representation into the
	   internal BigNums */
	cryptInfo->keyComponentsLittleEndian = dsaKey->endianness;
	cryptInfo->isPublicKey = dsaKey->isPublicKey;
	if( cryptInfo->keyComponentsLittleEndian )
		{
		bnInsertLittleBytes( &cryptInfo->dsaParam_p, dsaKey->p, 0,
							 bitsToBytes( dsaKey->pLen ) );
		bnInsertLittleBytes( &cryptInfo->dsaParam_q, dsaKey->q, 0,
							 bitsToBytes( dsaKey->qLen ) );
		bnInsertLittleBytes( &cryptInfo->dsaParam_g, dsaKey->g, 0,
							 bitsToBytes( dsaKey->gLen ) );
		bnInsertLittleBytes( &cryptInfo->dsaParam_x, dsaKey->x, 0,
							 bitsToBytes( dsaKey->xLen ) );
		if( !dsaKey->isPublicKey )
			bnInsertLittleBytes( &cryptInfo->dsaParam_y, dsaKey->y, 0,
								 bitsToBytes( dsaKey->yLen ) );
		}
	else
		{
		bnInsertBigBytes( &cryptInfo->dsaParam_p, dsaKey->p, 0,
						  bitsToBytes( dsaKey->pLen ) );
		bnInsertBigBytes( &cryptInfo->dsaParam_q, dsaKey->q, 0,
						  bitsToBytes( dsaKey->qLen ) );
		bnInsertBigBytes( &cryptInfo->dsaParam_g, dsaKey->g, 0,
						  bitsToBytes( dsaKey->gLen ) );
		bnInsertBigBytes( &cryptInfo->dsaParam_x, dsaKey->x, 0,
						  bitsToBytes( dsaKey->xLen ) );
		if( !dsaKey->isPublicKey )
			bnInsertBigBytes( &cryptInfo->dsaParam_y, dsaKey->y, 0,
							  bitsToBytes( dsaKey->yLen ) );
		}

	/* Load the key components into the external-format component storage */
	memcpy( cryptInfo->pkcInfo, dsaKey, sizeof( CRYPT_PKCINFO_DSA ) );

	/* Make sure the necessary key parameters have been initialised */
	if( !bnCmpQ( &cryptInfo->dsaParam_p, 0 ) || \
		!bnCmpQ( &cryptInfo->dsaParam_q, 0 ) || \
		!bnCmpQ( &cryptInfo->dsaParam_g, 0 ) || \
		!bnCmpQ( &cryptInfo->dsaParam_x, 0 ) )
		status = CRYPT_BADPARM2;
	if( !dsaKey->isPublicKey )
		if( !bnCmpQ( &cryptInfo->dsaParam_y, 0 ) )
		status = CRYPT_BADPARM2;

	/* Set the nominal keysize in bits */
	cryptInfo->keySizeBits = dsaKey->pLen;

	/* Finally, generate a key ID for this key */
	if( cryptStatusOK( status ) )
		status = generateKeyID( CRYPT_ALGO_DSA, cryptInfo->keyID, \
								&cryptInfo->keyIDlength, dsaKey );

	return( status );
	}
