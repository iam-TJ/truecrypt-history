#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "sha/shs.h"

/****************************************************************************
*																			*
*								SHA Self-test Routines						*
*																			*
****************************************************************************/

/* Test the SHA output against the test vectors given in FIPS 180 */

static LONG shaTestResults[][ 5 ] = {
	{ 0x0164B8A9L, 0x14CD2A5EL, 0x74C4F7FFL, 0x082C4D97L, 0xF1EDF880L },
	{ 0xD2516EE1L, 0xACFA5BAFL, 0x33DFC1C4L, 0x71E43844L, 0x9EF134C8L },
	{ 0x3232AFFAL, 0x48628A26L, 0x653B5AAAL, 0x44541FD9L, 0x0D690603L }
	};

static int compareSHSresults( SHS_INFO *shsInfo, int shsTestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 5; i++ )
		if( shsInfo->digest[ i ] != shaTestResults[ shsTestLevel ][ i ] )
			return( CRYPT_SELFTEST );
	return( CRYPT_OK );
	}

int shaSelfTest( void )
	{
	SHS_INFO shsInfo;

	/* Test SHA against values given in FIPS 180 */
	shsInit( &shsInfo );
	shsUpdate( &shsInfo, ( BYTE * ) "abc", 3 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 0 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	shsInit( &shsInfo );
	shsUpdate( &shsInfo, ( BYTE * ) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 1 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
#if 0
	/* We skip the third test since this takes several seconds to execute,
	   which leads to an unacceptable delay in the library startup time */
	shsInit( &shsInfo );
	for( i = 0; i < 15625; i++ )
		shsUpdate( &shsInfo, ( BYTE * ) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 2 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
#endif /* 0 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int shaInit( CRYPT_INFO *cryptInfo )
	{
	/* Allocate memory for the SHA context within the encryption context */
	if( cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->privateData = malloc( sizeof( SHS_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	cryptInfo->privateDataLength = sizeof( SHS_INFO );
	shsInit( ( SHS_INFO * ) cryptInfo->privateData );

	return( CRYPT_OK );
	}

int shaEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->privateData, cryptInfo->privateDataLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using SHA */

int shaHash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SHS_INFO *shaInfo = ( SHS_INFO * ) cryptInfo->privateData;

	/* If we've already called shaFinal(), we can't continue */
	if( shaInfo->done )
		return( CRYPT_COMPLETE );

	if( !noBytes )
		shsFinal( shaInfo );
	else
		shsUpdate( shaInfo, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Retrieve the hash value */

int shaGetData( CRYPT_INFO *cryptInfo, BYTE *buffer )
	{
	SHS_INFO *shaInfo = ( SHS_INFO * ) cryptInfo->privateData;
	int i;

	/* Extract the digest into the memory buffer */
	for( i = 0; i < 4; i++ )
		{
		mputLong( buffer, shaInfo->digest[ i ] );
		}

	return( ( shaInfo->done ) ? CRYPT_OK : CRYPT_INCOMPLETE );
	}
