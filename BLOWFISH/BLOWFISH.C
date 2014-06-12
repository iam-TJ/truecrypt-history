/****************************************************************************
*																			*
*						  Blowfish Encryption Algorithm 					*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "blowfish.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "blowfish.h"
#else
  #include "crypt.h"
  #include "blowfish/blowfish.h"
#endif /* Compiler-specific includes */

/* LCRNG start value */

#define LCRNG_START				1

/* Test vectors for the LCRNG and Blowfish-SK itself */

#define LCRNG_INITIAL			23312U
#define LCRNG_FINAL				23021U

#define BLOWFISH_PLAINTEXT		"\x00\x00\x00\x00\x00\x00\x00\x00"
#define BLOWFISH_CIPHERTEXT		"\x4D\x38\xE6\x00\x47\x35\x24\xCF"

/* The LCRNG used for the key setup */

#define lcrng(number)	( WORD ) ( ( ( number * 23311L ) + 1 ) % 65533U )

/* Macros to extract 8-bit values a, b, c, d from a 32-bit value.  The cast
   is necessary because some compilers prefer ints as array indices */

#define exta(x)		( ( int ) ( ( x >> 24 ) & 0xFF ) )
#define extb(x)		( ( int ) ( ( x >> 16 ) & 0xFF ) )
#define extc(x)		( ( int ) ( ( x >> 8 ) & 0xFF ) )
#define extd(x)		( ( int ) ( ( x ) & 0xFF ) )

/* The f-function */

#define f(data,S1,S2,S3,S4)		\
	( ( ( S1[ exta( data ) ] + S2[ extb( data ) ] ) ^ S3[ extc( data ) ] ) + \
													  S4[ extd( data ) ] )
/* The individual encrypt/decrypt rounds */

#define oddRoundE(count,P,S1,S2,S3,S4)	L ^= P[ count - 1 ]; \
										R ^= f( L, S1, S2, S3, S4 )
#define evenRoundE(count,P,S1,S2,S3,S4)	R ^= P[ count - 1 ]; \
										L ^= f( R, S1, S2, S3, S4 )
#define oddRoundD(count,P,S1,S2,S3,S4)	L ^= P[ count + 1 ]; \
										R ^= f( L, S1, S2, S3, S4 )
#define evenRoundD(count,P,S1,S2,S3,S4)	R ^= P[ count + 1 ]; \
										L ^= f( R, S1, S2, S3, S4 )

void blowfishEncrypt( BLOWFISH_KEY *key, BYTE *data )
	{
	BYTE *dataPtr = data;
	LONG *P = key->P, *S1 = key->S1, *S2 = key->S2, *S3 = key->S3, *S4 = key->S4;
	LONG L, R;

	L = mgetBLong( dataPtr );
	R = mgetBLong( dataPtr );

	/* Perform 16 rounds of encryption */
	oddRoundE(   1, P, S1, S2, S3, S4 );
	evenRoundE(  2, P, S1, S2, S3, S4 );
	oddRoundE(   3, P, S1, S2, S3, S4 );
	evenRoundE(  4, P, S1, S2, S3, S4 );
	oddRoundE(   5, P, S1, S2, S3, S4 );
	evenRoundE(  6, P, S1, S2, S3, S4 );
	oddRoundE(   7, P, S1, S2, S3, S4 );
	evenRoundE(  8, P, S1, S2, S3, S4 );
	oddRoundE(   9, P, S1, S2, S3, S4 );
	evenRoundE( 10, P, S1, S2, S3, S4 );
	oddRoundE(  11, P, S1, S2, S3, S4 );
	evenRoundE( 12, P, S1, S2, S3, S4 );
	oddRoundE(  13, P, S1, S2, S3, S4 );
	evenRoundE( 14, P, S1, S2, S3, S4 );
	oddRoundE(  15, P, S1, S2, S3, S4 );
	evenRoundE( 16, P, S1, S2, S3, S4 );

	/* Perform the final XOR's */
	L ^= P[ 16 ];
	R ^= P[ 17 ];

	dataPtr = data;
	mputBLong( dataPtr, R );
	mputBLong( dataPtr, L );
	}

void blowfishDecrypt( BLOWFISH_KEY *key, BYTE *data )
	{
	BYTE *dataPtr = data;
	LONG *P = key->P, *S1 = key->S1, *S2 = key->S2, *S3 = key->S3, *S4 = key->S4;
	LONG L, R;

	R = mgetBLong( dataPtr );
	L = mgetBLong( dataPtr );

	/* Perform 16 rounds of encryption */
	evenRoundD( 16, P, S1, S2, S3, S4 );
	oddRoundD(  15, P, S1, S2, S3, S4 );
	evenRoundD( 14, P, S1, S2, S3, S4 );
	oddRoundD(  13, P, S1, S2, S3, S4 );
	evenRoundD( 12, P, S1, S2, S3, S4 );
	oddRoundD(  11, P, S1, S2, S3, S4 );
	evenRoundD( 10, P, S1, S2, S3, S4 );
	oddRoundD(   9, P, S1, S2, S3, S4 );
	evenRoundD(  8, P, S1, S2, S3, S4 );
	oddRoundD(   7, P, S1, S2, S3, S4 );
	evenRoundD(  6, P, S1, S2, S3, S4 );
	oddRoundD(   5, P, S1, S2, S3, S4 );
	evenRoundD(  4, P, S1, S2, S3, S4 );
	oddRoundD(   3, P, S1, S2, S3, S4 );
	evenRoundD(  2, P, S1, S2, S3, S4 );
	oddRoundD(   1, P, S1, S2, S3, S4 );

	/* Perform the final XOR's */
	R ^= P[ 1 ];
	L ^= P[ 0 ];

	dataPtr = data;
	mputBLong( dataPtr, L );
	mputBLong( dataPtr, R );
	}

/****************************************************************************
*																			*
*						Blowfish Key Management Routines					*
*																			*
****************************************************************************/

/* Get the initial values of the P-array and S-boxes from an external file */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "bf_init.c"
#else
  #include "blowfish/bf_init.c"
#endif /* _MSC_VER */

/* Various defines needed for the key setup */

#define BLOWFISH_NO_ROUNDS	16

/* Set up a Blowfish S-box */

static void initSBox( BLOWFISH_KEY *key, LONG *Sbox, BYTE *buffer )
	{
	int sBoxIndex;

	for( sBoxIndex = 0; sBoxIndex < 256; sBoxIndex += 2 )
		{
		BYTE *bufferPtr = buffer;

		blowfishEncrypt( key, buffer );
		Sbox[ sBoxIndex ] = mgetBLong( bufferPtr );
		Sbox[ sBoxIndex + 1 ] = mgetBLong( bufferPtr );
		}
	}

/* Set up a Blowfish key */

int blowfishKeyInit( BLOWFISH_KEY *key, BYTE *userKey, int userKeyLength )
	{
	BYTE buffer[ BLOWFISH_BLOCKSIZE ];
	int keyIndex = 0, i;

	/* Set up the initial P-array and S-boxes based on the digits of pi */
	memcpy( key->P, initialParray, sizeof( initialParray ) );
	memcpy( key->S1, initialSbox1, sizeof( initialSbox1 ) );
	memcpy( key->S2, initialSbox2, sizeof( initialSbox2 ) );
	memcpy( key->S3, initialSbox3, sizeof( initialSbox3 ) );
	memcpy( key->S4, initialSbox4, sizeof( initialSbox4 ) );

	/* XOR the user key bits into the P-array */
	for( i = 0; i < BLOWFISH_NO_ROUNDS + 2; i++ )
		{
		LONG value = 0L;	/* Needed for > 32-bit processors */
		int byteIndex;

		/* Get 32 bits of user key and XOR them into the P-array */
		for( byteIndex = 0; byteIndex < 4; byteIndex++ )
			{
			value = ( value << 8 ) | userKey[ keyIndex++ ];
			keyIndex %= userKeyLength;
			}
		key->P[ i ] = key->P[ i ] ^ value;
		}

	/* Encrypt the all-zero string with the initial P-array to get the final
	   P-array */
	memset( buffer, 0, BLOWFISH_BLOCKSIZE );
	for( i = 0; i < BLOWFISH_NO_ROUNDS + 2; i += 2 )
		{
		BYTE *bufferPtr = buffer;

		blowfishEncrypt( key, buffer );
		key->P[ i ] = mgetBLong( bufferPtr );
		key->P[ i + 1 ] = mgetBLong( bufferPtr );
		}

	/* Continue the process to fill the S-boxes */
	initSBox( key, key->S1, buffer );
	initSBox( key, key->S2, buffer );
	initSBox( key, key->S3, buffer );
	initSBox( key, key->S4, buffer );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Blowfish-SK Key Management Routines					*
*																			*
****************************************************************************/

/* Set the P-array and S-boxes from a buffer full of keying material */

static void setKeyData( BLOWFISH_KEY *key, BYTE *keyBufPtr )
	{
	LONG *P = key->P, *S1 = key->S1, *S2 = key->S2, *S3 = key->S3, *S4 = key->S4;
	int i;

	/* Move the data from the keybuffer into the P-array and S-boxes,
	   converting it to the local endianness in the process.  We set the
	   four S-boxes one after the other rather than in parallel for
	   compatibility with code which treats them as a single large set of
	   S-boxes */
	for( i = 0; i < BLOWFISH_PARRAY_SIZE; i++ )
		{ P[ i ] = mgetBLong( keyBufPtr ); }
	for( i = 0; i < BLOWFISH_SBOX_SIZE; i++ )
		{ S1[ i ] = mgetBLong( keyBufPtr ); }
	for( i = 0; i < BLOWFISH_SBOX_SIZE; i++ )
		{ S2[ i ] = mgetBLong( keyBufPtr ); }
	for( i = 0; i < BLOWFISH_SBOX_SIZE; i++ )
		{ S3[ i ] = mgetBLong( keyBufPtr ); }
	for( i = 0; i < BLOWFISH_SBOX_SIZE; i++ )
		{ S4[ i ] = mgetBLong( keyBufPtr ); }
	}

/* Encrypt data in CFB mode */

static void encryptCFB( BLOWFISH_KEY *key, BYTE *iv, BYTE *buffer, int noBytes )
	{
	int i, ivCount;

	while( noBytes )
		{
		ivCount = ( noBytes > BLOWFISH_BLOCKSIZE ) ? BLOWFISH_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		blowfishEncrypt( key, iv );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= iv[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( iv, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}
	}

/* Set up a Blowfish-SK key */

int blowfishKeyInitSK( BLOWFISH_KEY *key, BYTE *userKey, int userKeyLength, \
					   int keySetupIterations )
	{
	BYTE *keyData, iv[ BLOWFISH_BLOCKSIZE ];
	WORD lcrngNumber = LCRNG_START;
	int count;

	/* Check that the LCRNG is implemented correctly */
	if( lcrng( lcrngNumber ) != LCRNG_INITIAL )
		return( CRYPT_SELFTEST );

	/* Some environments have real problems allocating the keyData array on
	   the stack.  Under Win16 the program will just exit quietly with no
	   indication of what went wrong.  To avoid this we need to allocate the
	   buffer dynamically.  Since the Blowfish-SK key setup is quite slow
	   anyway, the extra malloc() won't be noticed */
	if( ( keyData = ( BYTE * ) malloc( BLOWFISH_KEYSIZE_BYTES ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the P-array and S-boxes */
	for( count = 0; count < BLOWFISH_KEYSIZE_BYTES; count++ )
		{
		lcrngNumber = lcrng( lcrngNumber );
		keyData[ count ] = ( BYTE ) lcrngNumber;
		}
	if( lcrng( lcrngNumber ) != LCRNG_FINAL )
		{
		free( keyData );
		return( CRYPT_SELFTEST );
		}
	setKeyData( key, keyData );

	/* Make sure the encryption works OK */
	memcpy( iv, BLOWFISH_PLAINTEXT, BLOWFISH_BLOCKSIZE );
	blowfishEncrypt( key, iv );
	if( memcmp( iv, BLOWFISH_CIPHERTEXT, BLOWFISH_BLOCKSIZE ) )
		{
		free( keyData );
		return( CRYPT_SELFTEST );
		}
	blowfishDecrypt( key, iv );
	if( memcmp( iv, BLOWFISH_PLAINTEXT, BLOWFISH_BLOCKSIZE ) )
		{
		free( keyData );
		return( CRYPT_SELFTEST );
		}

	/* Copy the user key (zero-padded) into the keybuffer */
	memset( keyData, 0, BLOWFISH_KEYSIZE_BYTES );
	keyData[ 0 ] = ( BYTE ) ( userKeyLength >> 8 );
	keyData[ 1 ] = ( BYTE ) userKeyLength;
	userKeyLength %= BLOWFISH_KEYSIZE_BYTES - sizeof( WORD );
	memcpy( keyData + sizeof( WORD ), userKey, userKeyLength );

	/* Encrypt the keyData with the given IV and then set the key to the
	   encrypted keyData (initially the IV is still 0 from the self-test).
	   The act of encryption also sets the IV for the next iteration */
	for( count = 0; count < keySetupIterations; count++ )
		{
		encryptCFB( key, iv, keyData, BLOWFISH_KEYSIZE_BYTES );
		setKeyData( key, keyData );
		}

	/* Perform one last copy in case they've specified zero iterations and
	   the loop was never executed */
	setKeyData( key, keyData );

	/* Wipe the keyData and IV */
	zeroise( keyData, BLOWFISH_KEYSIZE_BYTES );
	zeroise( iv, BLOWFISH_BLOCKSIZE );
	free( keyData );

	return( CRYPT_OK );
	}

#ifdef TEST

/* Test routines */

#include <stdio.h>

#ifdef __TURBOC__		/* Only 4K stack under DOS - blechh */
extern unsigned _stklen = 8192;
#endif /* __TURBOC__ */

int main( void )
	{
	BYTE *plain1 = ( BYTE * ) "BLOWFISH";
	BYTE *key1 = ( BYTE * ) "abcdefghijklmnopqrstuvwxyz";
	BYTE *cipher1 = ( BYTE * ) "\x32\x4E\xD0\xFE\xF4\x13\xA2\x03";
	BYTE *plain2 = ( BYTE * ) "\xFE\xDC\xBA\x98\x76\x54\x32\x10";
	BYTE *key2 = ( BYTE * ) "Who is John Galt?";
	BYTE *cipher2 = ( BYTE * ) "\xCC\x91\x73\x2B\x80\x22\xF6\x84";
	BLOWFISH_KEY bfKey;
	BYTE buffer[ 8 ];

	memcpy( buffer, plain1, 8 );
	if( blowfishKeyInit( &bfKey, key1, strlen( ( char * ) key1 ) ) != CRYPT_OK )
		puts( "Init failed" );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher1, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain1, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain2, 8 );
	if( blowfishKeyInit( &bfKey, key2, strlen( ( char * ) key2 ) ) != CRYPT_OK )
		puts( "Init failed" );
	blowfishEncrypt( &bfKey, buffer );
	if( memcmp( buffer, cipher2, 8 ) )
		return( CRYPT_ERROR );
	blowfishDecrypt( &bfKey, buffer );
	if( memcmp( buffer, plain2, 8 ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}
#endif /* TEST */
