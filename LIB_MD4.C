#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "md4/md4.h"

/****************************************************************************
*																			*
*								MD4 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD4 output against the test vectors given in RFC 1320 */

static LONG md4TestResults[][ 4 ] = {
	{ 0xE0CFD631L, 0x31E96AD1L, 0xD7593CB7L, 0xC089C0E0L },
	{ 0xB32CE5BDL, 0x463EE31DL, 0xFB055E24L, 0x24FBD6DBL },
	{ 0x7A0148A4L, 0x52D821AFL, 0xE80AC15FL, 0x9D72A67AL },
	{ 0x810A13D9L, 0xE89F5464L, 0x06488718L, 0x4B01C7E1L },
	{ 0x301C9ED7L, 0xCDBBA58AL, 0x63EDA8EEL, 0xA92D41DFL },
	{ 0x82853F04L, 0x35DB41F2L, 0xE127E61CL, 0xE4F0E753L },
	{ 0xDC4D3BE3L, 0x19F2389CL, 0x167B3E9CL, 0x3605CC4FL }
	};

static int compareMD4results( MD4_INFO *md4Info, int md4TestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 4; i++ )
		if( md4Info->digest[ i ] != md4TestResults[ md4TestLevel ][ i ] )
			return( CRYPT_SELFTEST );
	return( CRYPT_OK );
	}

int md4SelfTest( void )
	{
	MD4_INFO md4Info;

	/* Test MD4 against values given in FIPS 180 */
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "", 0 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 0 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "a", 1 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 1 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "abc", 3 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 2 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "message digest", 14 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 3 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "abcdefghijklmnopqrstuvwxyz", 26 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 4 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 5 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 6 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int md4Init( CRYPT_INFO *cryptInfo )
	{
	/* Allocate memory for the MD4 context within the encryption context */
	if( cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->privateData = malloc( sizeof( MD4_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	cryptInfo->privateDataLength = sizeof( MD4_INFO );
	md4Initial( ( MD4_INFO * ) cryptInfo->privateData );

	return( CRYPT_OK );
	}

int md4End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->privateData, cryptInfo->privateDataLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MD4 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD4 */

int md4Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MD4_INFO *md4Info = ( MD4_INFO * ) cryptInfo->privateData;

	/* If we've already called md4Final(), we can't continue */
	if( md4Info->done )
		return( CRYPT_COMPLETE );

	if( !noBytes )
		md4Final( md4Info );
	else
		md4Update( md4Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Retrieve the hash value */

int md4GetData( CRYPT_INFO *cryptInfo, BYTE *buffer )
	{
	MD4_INFO *md4Info = ( MD4_INFO * ) cryptInfo->privateData;
	int i;

	/* Extract the digest into the memory buffer */
	for( i = 0; i < 4; i++ )
		{
		mputLong( buffer, md4Info->digest[ i ] );
		}

	return( ( md4Info->done ) ? CRYPT_OK : CRYPT_INCOMPLETE );
	}
