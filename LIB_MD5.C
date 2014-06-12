#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "md5/md5.h"

/****************************************************************************
*																			*
*								MD5 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD5 output against the test vectors given in RFC 1320 */

static LONG md5TestResults[][ 4 ] = {
	{ 0xD98C1DD4L, 0x04B2008FL, 0x980980E9L, 0x7E42F8ECL },
	{ 0xB975C10CL, 0xA8B6F1C0L, 0xE299C331L, 0x61267769L },
	{ 0x98500190L, 0xB04FD23CL, 0x7D3F96D6L, 0x727FE128L },
	{ 0x7D696BF9L, 0x8D93B77CL, 0x312F5A52L, 0xD061F1AAL },
	{ 0xD7D3FCC3L, 0x00E49261L, 0x6C49FB7DL, 0x3BE167CAL },
	{ 0x98AB74D1L, 0xF5D977D2L, 0x2C1C61A5L, 0x9F9D419FL },
	{ 0xA2F4ED57L, 0x55C9E32BL, 0x2EDA49ACL, 0x7AB60721L }
	};

static int compareMD5results( MD5_INFO *md5Info, int md5TestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 4; i++ )
		if( md5Info->digest[ i ] != md5TestResults[ md5TestLevel ][ i ] )
			return( CRYPT_SELFTEST );
	return( CRYPT_OK );
	}

int md5SelfTest( void )
	{
	MD5_INFO md5Info;

	/* Test MD5 against values given in FIPS 180 */
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "", 0 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 0 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "a", 1 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 1 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "abc", 3 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 2 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "message digest", 14 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 3 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "abcdefghijklmnopqrstuvwxyz", 26 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 4 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 5 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 6 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int md5Init( CRYPT_INFO *cryptInfo )
	{
	/* Allocate memory for the MD5 context within the encryption context */
	if( cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->privateData = malloc( sizeof( MD5_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	cryptInfo->privateDataLength = sizeof( MD5_INFO );
	md5Initial( ( MD5_INFO * ) cryptInfo->privateData );

	return( CRYPT_OK );
	}

int md5End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->privateData, cryptInfo->privateDataLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MD5 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD5 */

int md5Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MD5_INFO *md5Info = ( MD5_INFO * ) cryptInfo->privateData;

	/* If we've already called md5Final(), we can't continue */
	if( md5Info->done )
		return( CRYPT_COMPLETE );

	if( !noBytes )
		md5Final( md5Info );
	else
		md5Update( md5Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Retrieve the hash value */

int md5GetData( CRYPT_INFO *cryptInfo, BYTE *buffer )
	{
	MD5_INFO *md5Info = ( MD5_INFO * ) cryptInfo->privateData;
	int i;

	/* Extract the digest into the memory buffer */
	for( i = 0; i < 4; i++ )
		{
		mputLong( buffer, md5Info->digest[ i ] );
		}

	return( ( md5Info->done ) ? CRYPT_OK : CRYPT_INCOMPLETE );
	}
