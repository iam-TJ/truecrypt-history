/****************************************************************************
*																			*
*						cryptlib MDC/SHS Encryption Routines				*
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
  #include "sha.h"
#else
  #include "hash/sha.h"
#endif /* Compiler-specific includes */

/* The default key setup iteration count.  This gives roughly 0.5s delay on
   a 10K dhrystone machine */

#define MDCSHS_DEFAULT_ITERATIONS	200

/* The size of an MDCSHS key.  If we're running on a machine with a > 32
   bit wordsize, we need to store the key as an array of words rather than
   an array of bytes which is cast to an array of words */

#ifdef _BIG_WORDS
  #define MDCSHS_KEY_WORDS		( SHA_DATASIZE / 4 )
  #define MDCSHS_KEYSIZE		( MDCSHS_KEY_WORDS * sizeof( LONG ) )
#else
  #define MDCSHS_KEYSIZE		SHA_DATASIZE
#endif /* _BIG_WORDS */

/****************************************************************************
*																			*
*							MDC/SHS Self-test Routines						*
*																			*
****************************************************************************/

/* Test the SHA output against the test vectors given in FIPS 180 */

static LONG shaTestResults[][ SHA_DIGESTSIZE / 4 ] = {
	{ 0x0164B8A9L, 0x14CD2A5EL, 0x74C4F7FFL, 0x082C4D97L, 0xF1EDF880L },
	{ 0xD2516EE1L, 0xACFA5BAFL, 0x33DFC1C4L, 0x71E43844L, 0x9EF134C8L },
	{ 0x3232AFFAL, 0x48628A26L, 0x653B5AAAL, 0x44541FD9L, 0x0D690603L }
	};

static int compareSHSresults( SHA_INFO *shaInfo, int shaTestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < SHA_DIGESTSIZE / 4; i++ )
		if( shaInfo->digest[ i ] != shaTestResults[ shaTestLevel ][ i ] )
			return( CRYPT_SELFTEST );
	return( CRYPT_OK );
	}

int mdcshsSelfTest( void )
	{
	SHA_INFO shaInfo;

	/* Test SHA against values given in FIPS 180 */
	shaInitial( &shaInfo );
	shaUpdate( &shaInfo, ( BYTE * ) "abc", 3 );
	shaFinal( &shaInfo );
	if( compareSHSresults( &shaInfo, 0 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
	shaInitial( &shaInfo );
	shaUpdate( &shaInfo, ( BYTE * ) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	shaFinal( &shaInfo );
	if( compareSHSresults( &shaInfo, 1 ) != CRYPT_OK )
		return( CRYPT_SELFTEST );
#if 0
	/* We skip the third test since this takes several seconds to execute,
	   which leads to an unacceptable delay in the library startup time */
	shaInitial( &shaInfo );
	for( i = 0; i < 15625; i++ )
		shaUpdate( &shaInfo, ( BYTE * ) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64 );
	shaFinal( &shaInfo );
	if( compareSHSresults( &shaInfo, 2 ) != CRYPT_OK )
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

int mdcshsInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_MDCSHS *cryptInfoExPtr = ( CRYPT_INFO_MDCSHS * ) cryptInfoEx;
	int status;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( status = secureMalloc( &cryptInfo->key, MDCSHS_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr->keySetupIterations == CRYPT_USE_DEFAULT )
		cryptInfo->privateUseDefaults = TRUE;
	if( ( status = secureMalloc( &cryptInfo->privateData, sizeof( CRYPT_INFO_MDCSHS ) ) ) != CRYPT_OK )
		{
		secureFree( &cryptInfo->key );
		return( status );
		}
	if( cryptInfoExPtr->keySetupIterations == CRYPT_USE_DEFAULT )
		setMDCSHSinfo( cryptInfo, MDCSHS_DEFAULT_ITERATIONS );
	else
		setMDCSHSinfo( cryptInfo, cryptInfoExPtr->keySetupIterations );
	cryptInfo->keyLength = MDCSHS_KEYSIZE;

	return( CRYPT_OK );
	}

int mdcshsInit( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO_MDCSHS cryptInfoEx;

	/* Use the default number of setup iterations */
	memset( &cryptInfoEx, 0, sizeof( CRYPT_INFO_MDCSHS ) );
	cryptInfoEx.keySetupIterations = CRYPT_USE_DEFAULT;

	/* Pass through to the extended setup routine */
	return( mdcshsInitEx( cryptInfo, &cryptInfoEx ) );
	}

int mdcshsEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key );
	secureFree( &cryptInfo->privateData );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						MDC/SHS En/Decryption Routines						*
*																			*
****************************************************************************/

/* The SHS transformation.  What we're doing here isn't totally correct since
   we're forcing the IV to big-endian, transforming it, and returning it to
   the local endianness, rather than changing the data to the local
   endianness and back as we should.  However doing it correctly isn't really
   possible since we can only endianness-swap 4 bytes at a time which
   precludes swapping the data.  The use of the temp variable when the IV is
   copied back in the _BIG_WORDS case is to eliminate multiple memory
   accesses when the four bytes are extracted from ivLong[ n ], since many
   compilers won't risk optimising the loads due to possible aliasing
   problems.  We declare the necessary ivLong array as part of the actual
   encryption function to save it having to be instantiated for every use
   of shsTransform() */

#ifdef _BIG_WORDS
  #define shaTransform(cI)  { \
							LONG temp; \
							BYTE *ivPtr; \
							ivPtr = ( BYTE * ) cI->currentIV; \
							for( i = 0; i < SHA_DIGESTSIZE / 4; i++ ) \
								{ \
								ivLong[ i ] = mgetBLong( ivPtr ); \
								} \
							SHATransform( ivLong, cI->key ); \
							ivPtr = ( BYTE * ) cI->currentIV; \
							for( i = 0; i < SHA_DIGESTSIZE / 4; i++ ) \
								{ \
								temp = ivLong[ i ]; \
								mputBLong( ivPtr, temp ); \
								} \
							}
#else
  #define shaTransform(cI)	bigToLittleLong( ( LONG * ) cI->currentIV, SHA_DIGESTSIZE ); \
							SHATransform( ( LONG * ) cI->currentIV, ( LONG * ) cI->key ); \
							bigToLittleLong( ( LONG * ) cI->currentIV, SHA_DIGESTSIZE );
#endif /* _BIG_WORDS */

void SHATransform( LONG *digest, LONG *data );

/* Encrypt data in CFB mode */

int mdcshsEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ivCount;
#ifdef _BIG_WORDS
	LONG ivLong[ SHA_DIGESTSIZE / 4 ];
#endif /* _BIG_WORDS */

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SHA_DIGESTSIZE - ivCount;
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
		ivCount = ( noBytes > SHA_DIGESTSIZE ) ? SHA_DIGESTSIZE : noBytes;

		/* Encrypt the IV */
		shaTransform( cryptInfo );

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
	cryptInfo->ivCount = ( ivCount % SHA_DIGESTSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int mdcshsDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ SHA_DIGESTSIZE ];
	int i, ivCount = cryptInfo->ivCount;
#ifdef _BIG_WORDS
	LONG ivLong[ SHA_DIGESTSIZE / 4 ];
#endif /* _BIG_WORDS */

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SHA_DIGESTSIZE - ivCount;
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
		ivCount = ( noBytes > SHA_DIGESTSIZE ) ? SHA_DIGESTSIZE : noBytes;

		/* Encrypt the IV */
		shaTransform( cryptInfo );

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
	cryptInfo->ivCount = ( ivCount % SHA_DIGESTSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, SHA_DIGESTSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						MDC/SHS Key Management Routines						*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int getMDCSHSinfo( const CRYPT_INFO *cryptInfo )
	{
	return( ( ( CRYPT_INFO_MDCSHS * ) cryptInfo->privateData )->keySetupIterations );
	}

void setMDCSHSinfo( CRYPT_INFO *cryptInfo, const int keySetupIterations )
	{
	( ( CRYPT_INFO_MDCSHS * ) cryptInfo->privateData )->keySetupIterations = keySetupIterations;
	}

/* The size of the key buffer.  Note that increasing this value will result
   in a significant increase in the setup time, so it will be necessary to
   make a corresponding decrease in the iteration count */

#define KEYBUFFER_SIZE		256

/* Initialise an MDC/SHS key.  This is done by repeatedly encrypting the
   user key as follows:

	IV <- 0
	key <- 0
	repeat
		encrypt userkey with key
		key <- userkey

   The IV is updated transparently as part of the encryption process */

int mdcshsInitKey( CRYPT_INFO *cryptInfo )
	{
	BYTE keyData[ KEYBUFFER_SIZE ];
	int keySetupIterations = ( ( CRYPT_INFO_MDCSHS * ) cryptInfo->privateData )->keySetupIterations;
	int count;

	/* Copy the key information into the key data buffer.  We silently
	   truncate the key length to the size of the buffer, but this usually
	   is some hundreds of bytes so it shouldn't be a problem.
	   We also correct the endianness of the keyData at this point.  From
	   here on all data is in the local endianness format so there is no need
	   for further corrections */
	memset( keyData, 0, KEYBUFFER_SIZE );
	keyData[ 0 ] = ( BYTE ) ( cryptInfo->userKeyLength >> 8 );
	keyData[ 1 ] = ( BYTE ) cryptInfo->userKeyLength;
	cryptInfo->userKeyLength %= KEYBUFFER_SIZE - 2;
	memcpy( keyData + 2, cryptInfo->userKey, cryptInfo->userKeyLength );

	/* Set the initial key and IV to null */
	memset( cryptInfo->currentIV, 0, MAX_IVSIZE );
	memset( cryptInfo->key, 0, MDCSHS_KEYSIZE );

	/* Convert the endianness of the input data from the canonical form to
	   the local form */
	bigToLittleLong( ( LONG * ) keyData, KEYBUFFER_SIZE );

	/* "Encrypt" the keyData with the given IV and then set the key to
	   the encrypted keyData.  The act of encryption also sets the IV.
	   This is particularly important in the case of SHA, since although only
	   the first SHA_DATASIZE bytes are copied into the key, the IV is
	   still affected by the entire buffer */
	for( count = 0; count < keySetupIterations; count++ )
		{
		mdcshsEncrypt( cryptInfo, keyData, KEYBUFFER_SIZE );
		copyToLong( cryptInfo->key, keyData, SHA_DATASIZE );
		}

	/* Perform one last copy in case they've specified zero iterations and
	   the loop was never executed.  For MDCSHS, the transformed key is the
	   same as the raw encryption key, so we just copy it over */
	copyToLong( cryptInfo->key, keyData, SHA_DATASIZE );

#if 0
	/* Set the key check byte to the last WORD of the encrypted keyData.
	   This is never used for anything (it's 191 bytes past the end of the
	   last value used to set the key) so we're not revealing much to an
	   attacker */
	bigToLittleLong( ( LONG * ) ( keyData + KEYBUFFER_SIZE - sizeof( LONG ) ), sizeof( LONG ) );
	cryptInfo->keyCheck = ( ( WORD ) keyData[ KEYBUFFER_SIZE - 2 ] << 8 ) | \
								   keyData[ KEYBUFFER_SIZE - 1 ];
#endif /* 0 */

	/* Wipe the keyData */
	zeroise( keyData, KEYBUFFER_SIZE );

	return( CRYPT_OK );
	}

/* Initialise the IV */

int mdcshsInitIV( CRYPT_INFO *cryptInfo )
	{
	/* Convert the working IV from the canonical to the internal form */
	bigToLittleLong( ( LONG * ) cryptInfo->currentIV, MAX_IVSIZE );

	return( CRYPT_OK );
	}
