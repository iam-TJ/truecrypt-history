/****************************************************************************
*																			*
*						cryptlib Null Encryption Routines					*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <string.h>
#include "crypt.h"

/****************************************************************************
*																			*
*							Null En/Decryption Routines						*
*																			*
****************************************************************************/

int nullSelfTest( void )
	{
	return( CRYPT_OK );
	}

int nullInit( CRYPT_INFO *cryptInfo )
	{
	UNUSED( cryptInfo );

	return( CRYPT_OK );
	}

int nullInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	UNUSED( cryptInfoEx );

	return( nullInit( cryptInfo ) );
	}

int nullEnd( CRYPT_INFO *cryptInfo )
	{
	UNUSED( cryptInfo );

	return( CRYPT_OK );
	}

int nullInitKey( CRYPT_INFO *cryptInfo )
	{
	UNUSED( cryptInfo );

	return( CRYPT_OK );
	}

int nullInitIV( CRYPT_INFO *cryptInfo )
	{
	UNUSED( cryptInfo );

	return( CRYPT_OK );
	}

int nullGetKeysize( CRYPT_INFO *cryptInfo )
	{
	UNUSED( cryptInfo );

	return( CRYPT_OK );
	}

int nullGetData( CRYPT_INFO *cryptInfo, void *buffer )
	{
	UNUSED( cryptInfo );
	UNUSED( buffer );

	return( CRYPT_OK );
	}

int nullEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	UNUSED( cryptInfo );
	UNUSED( buffer );
	UNUSED( length );

	return( CRYPT_OK );
	}

int nullDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	UNUSED( cryptInfo );
	UNUSED( buffer );
	UNUSED( length );

	return( CRYPT_OK );
	}

void nullHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					 int length, const HASH_STATE hashState )
	{
	UNUSED( hashInfo );
	UNUSED( inBuffer );
	UNUSED( length );

	if( hashState == HASH_ALL || hashState == HASH_END )
		memset( outBuffer, 0, CRYPT_MAX_HASHSIZE );
	}
