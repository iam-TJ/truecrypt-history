/****************************************************************************
*																			*
*				Implementation of the RSA Data Security, Inc.				*
*						MD4 Message-Digest Algorithm						*
*																			*
****************************************************************************/

#include <string.h>
#ifdef _MSC_VER
  #include "../crypt.h"
  #include "md4.h"
#else
  #include "crypt.h"
  #include "md4/md4.h"
#endif /* _MSC_VER */

/****************************************************************************
*																			*
*							The MD4 Transformation							*
*																			*
****************************************************************************/

/* MD4 magic numbers. C2 and C3 are from Knuth, Table 2, p.660, "The Art of
   Programming", Volume 2 (Seminumerical Algorithms), Table 2, p.660.
   Second Edition (1981), Addison-Wesley */

#define I0  0x67452301L      /* Initial values for MD buffer */
#define I1  0xEFCDAB89L
#define I2  0x98BADCFEL
#define I3  0x10325476L
#define C2  013240474631L    /* Round 2 constant: sqrt( 2 ) in octal */
#define C3  015666365641L    /* Round 3 constant: sqrt( 3 ) in octal */

/* Round 1 shift amounts */

#define FS1  3
#define FS2  7
#define FS3 11
#define FS4 19

/* Round 2 shift amounts */

#define GS1  3
#define GS2  5
#define GS3  9
#define GS4 13

/* Round 3 shift amounts */

#define HS1  3
#define HS2  9
#define HS3 11
#define HS4 15

/* F, G, and H are basic MD4 functions */

#define	F(X,Y,Z)	( ( X & Y ) | ( ( ~X ) & Z ) )
#define	G(X,Y,Z)	( ( X & Y ) | ( X & Z ) | ( Y & Z ) )
#define H(X,Y,Z)	( X ^ Y ^ Z )

/* ROTATE_LEFT rotates x left n bits */

#define ROTATE_LEFT(x,n)	( ( x << n ) | ( x >> ( 32 - n ) ) )

/* FF, GG, HH, and II transformations for rounds 1, 2, and 3 */

#ifdef _BIG_WORDS

#define FF(A,B,C,D,X,shiftAmt) \
	A += F( B, C, D ) + X; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ); \
	A &= 0xFFFFFFFFUL

#define GG(A,B,C,D,X,shiftAmt) \
	A += G( B, C,D ) + X + C2; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ); \
	A &= 0xFFFFFFFFUL

#define HH(A,B,C,D,X,shiftAmt) \
	A += H( B, C,D ) + X + C3; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ); \
	A &= 0xFFFFFFFFUL

#else

#define FF(A,B,C,D,X,shiftAmt) \
	A += F( B, C, D ) + X; \
	A = ROTATE_LEFT( A, shiftAmt )

#define GG(A,B,C,D,X,shiftAmt) \
	A += G( B, C,D ) + X + C2; \
	A = ROTATE_LEFT( A, shiftAmt )

#define HH(A,B,C,D,X,shiftAmt) \
	A += H( B, C,D ) + X + C3; \
	A = ROTATE_LEFT( A, shiftAmt )

#endif /* _BIG_WORDS */

/* Basic MD4 step. Transforms digest based on data */

void MD4Transform( LONG *digest, LONG *data )
	{
	LONG A, B, C, D;

	/* Set up local data */
	A = digest[ 0 ];
	B = digest[ 1 ];
	C = digest[ 2 ];
	D = digest[ 3 ];

	/* Round 1 */
	FF( A, B, C, D, data[  0 ], FS1 );
	FF( D, A, B, C, data[  1 ], FS2 );
	FF( C, D, A, B, data[  2 ], FS3 );
	FF( B, C, D, A, data[  3 ], FS4 );
	FF( A, B, C, D, data[  4 ], FS1 );
	FF( D, A, B, C, data[  5 ], FS2 );
	FF( C, D, A, B, data[  6 ], FS3 );
	FF( B, C, D, A, data[  7 ], FS4 );
	FF( A, B, C, D, data[  8 ], FS1 );
	FF( D, A, B, C, data[  9 ], FS2 );
	FF( C, D, A, B, data[ 10 ], FS3 );
	FF( B, C, D, A, data[ 11 ], FS4 );
	FF( A, B, C, D, data[ 12 ], FS1 );
	FF( D, A, B, C, data[ 13 ], FS2 );
	FF( C, D, A, B, data[ 14 ], FS3 );
	FF( B, C, D, A, data[ 15 ], FS4 );

	/* Round 2 */
	GG( A, B, C, D, data[  0 ], GS1 );
	GG( D, A, B, C, data[  4 ], GS2 );
	GG( C, D, A, B, data[  8 ], GS3 );
	GG( B, C, D, A, data[ 12 ], GS4 );
	GG( A, B, C, D, data[  1 ], GS1 );
	GG( D, A, B, C, data[  5 ], GS2 );
	GG( C, D, A, B, data[  9 ], GS3 );
	GG( B, C, D, A, data[ 13 ], GS4 );
	GG( A, B, C, D, data[  2 ], GS1 );
	GG( D, A, B, C, data[  6 ], GS2 );
	GG( C, D, A, B, data[ 10 ], GS3 );
	GG( B, C, D, A, data[ 14 ], GS4 );
	GG( A, B, C, D, data[  3 ], GS1 );
	GG( D, A, B, C, data[  7 ], GS2 );
	GG( C, D, A, B, data[ 11 ], GS3 );
	GG( B, C, D, A, data[ 15 ], GS4 );

	/* Round 3 */
	HH( A, B, C, D, data[  0 ], HS1 );
	HH( D, A, B, C, data[  8 ], HS2 );
	HH( C, D, A, B, data[  4 ], HS3 );
	HH( B, C, D, A, data[ 12 ], HS4 );
	HH( A, B, C, D, data[  2 ], HS1 );
	HH( D, A, B, C, data[ 10 ], HS2 );
	HH( C, D, A, B, data[  6 ], HS3 );
	HH( B, C, D, A, data[ 14 ], HS4 );
	HH( A, B, C, D, data[  1 ], HS1 );
	HH( D, A, B, C, data[  9 ], HS2 );
	HH( C, D, A, B, data[  5 ], HS3 );
	HH( B, C, D, A, data[ 13 ], HS4 );
	HH( A, B, C, D, data[  3 ], HS1 );
	HH( D, A, B, C, data[ 11 ], HS2 );
	HH( C, D, A, B, data[  7 ], HS3 );
	HH( B, C, D, A, data[ 15 ], HS4 );

	/* Build message digest */
#ifdef _BIG_WORDS
	digest[ 0 ] = ( digest[ 0 ] + A ) & 0xFFFFFFFFUL;
	digest[ 1 ] = ( digest[ 1 ] + B ) & 0xFFFFFFFFUL;
	digest[ 2 ] = ( digest[ 2 ] + C ) & 0xFFFFFFFFUL;
	digest[ 3 ] = ( digest[ 3 ] + D ) & 0xFFFFFFFFUL;
#else
	digest[ 0 ] += A;
	digest[ 1 ] += B;
	digest[ 2 ] += C;
	digest[ 3 ] += D;
#endif /* _BIG_WORDS */
	}

/****************************************************************************
*																			*
*							MD4 Support Routines							*
*																			*
****************************************************************************/

/* The routine md4Initial initializes the message-digest context md4Info */

void md4Initial( MD4_INFO *md4Info )
	{
	/* Clear all fields */
	memset( md4Info, 0, sizeof( MD4_INFO ) );

	/* Load magic initialization constants */
	md4Info->digest[ 0 ] = I0;
	md4Info->digest[ 1 ] = I1;
	md4Info->digest[ 2 ] = I2;
	md4Info->digest[ 3 ] = I3;

	/* Initialise bit count */
	md4Info->countLo = md4Info->countHi = 0L;
	}

#ifdef TEST_MD4

/* When run on a big-endian CPU we need to perform byte reversal on an
   array of longwords.  It is possible to make the code endianness-
   independant by fiddling around with data at the byte level, but this
   makes for very slow code, so we rely on the user to sort out endianness
   at compile time */

#if defined( BIG_ENDIAN )

void longReverse( LONG *buffer, int byteCount )
	{
	LONG value;

	byteCount /= sizeof( LONG );
	while( byteCount-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00L ) >> 8  ) | \
				( ( value & 0x00FF00FFL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
	}
#endif /* BIG_ENDIAN */

#endif /* TEST_MD4 */

#ifdef _BIG_WORDS

/* When run on a CPU with > 32 bit word size, we need to move the data from
   the byte-aligned buffer to the final word-aligned data buffer.  We perform
   the endianness-reversal at the same time */

static void extractData( MD4_INFO *md4Info )
	{
	BYTE *bufferPtr = md4Info->dataBuffer;
	int i;

	for( i = 0; i < 16; i++ )
		{
		md4Info->data[ i ] = ( ( LONG ) bufferPtr[ 0 ] ) | \
							 ( ( LONG ) bufferPtr[ 1 ] << 8 ) | \
							 ( ( LONG ) bufferPtr[ 2 ] << 16 ) | \
							 ( ( LONG ) bufferPtr[ 3 ] << 24 );
		bufferPtr += 4;
		}
	}
#endif /* _BIG_WORDS */

/* The routine MD4Update updates the message-digest context to account for
   the presence of each of the characters buffer[ 0 .. count-1 ] in the
   message whose digest is being computed.  This is an optimized version
   which assumes that the buffer is a multiple of MD4_BLOCKSIZE bytes long */

void md4Update( MD4_INFO *md4Info, BYTE *buffer, int count )
	{
	LONG tmp;
	int dataCount;

	/* Update bitcount */
	tmp = md4Info->countLo;
	if ( ( md4Info->countLo = tmp + ( ( LONG ) count << 3 ) ) < tmp )
		md4Info->countHi++;				/* Carry from low to high */
	md4Info->countHi += count >> 29;

	/* Get count of bytes already in data */
	dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if( dataCount )
		{
#ifdef _BIG_WORDS
		BYTE *p = md4Info->dataBuffer + dataCount;
#else
		BYTE *p = ( BYTE * ) md4Info->data + dataCount;
#endif /* _BIG_WORDS */

		dataCount = MD4_DATASIZE - dataCount;
		if( count < dataCount )
			{
			memcpy( p, buffer, count );
			return;
			}
		memcpy( p, buffer, dataCount );
#ifdef _BIG_WORDS
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#else
		littleToBigLong( md4Info->data, MD4_DATASIZE );
#endif /* _BIG_WORDS */
		MD4Transform( md4Info->digest, md4Info->data );
		buffer += dataCount;
		count -= dataCount;
		}

	/* Process data in MD4_DATASIZE chunks */
	while( count >= MD4_DATASIZE )
		{
#ifdef _BIG_WORDS
		memcpy( md4Info->dataBuffer, buffer, MD4_DATASIZE );
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#else
		memcpy( md4Info->data, buffer, MD4_DATASIZE );
		littleToBigLong( md4Info->data, MD4_DATASIZE );
#endif /* _BIG_WORDS */
		MD4Transform( md4Info->digest, md4Info->data );
		buffer += MD4_DATASIZE;
		count -= MD4_DATASIZE;
		}

	/* Handle any remaining bytes of data. */
#ifdef _BIG_WORDS
	memcpy( md4Info->dataBuffer, buffer, count );
#else
	memcpy( md4Info->data, buffer, count );
#endif /* _BIG_WORDS */
	}

/* Final wrapup - pad to MD4_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void md4Final( MD4_INFO *md4Info )
	{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = ( int ) md4Info->countLo;
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
#ifdef _BIG_WORDS
	dataPtr = md4Info->dataBuffer + count;
#else
	dataPtr = ( BYTE * ) md4Info->data + count;
#endif /* _BIG_WORDS */
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = MD4_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 )
		{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( dataPtr, 0, count );
#ifdef _BIG_WORDS
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#else
		littleToBigLong( md4Info->data, MD4_DATASIZE );
#endif /* _BIG_WORDS */
		MD4Transform( md4Info->digest, md4Info->data );

		/* Now fill the next block with 56 bytes */
#ifdef _BIG_WORDS
		memset( md4Info->dataBuffer, 0, MD4_DATASIZE - 8 );
#else
		memset( md4Info->data, 0, MD4_DATASIZE - 8 );
#endif /* _BIG_WORDS */
		}
	else
		/* Pad block to 56 bytes */
		memset( dataPtr, 0, count - 8 );
#ifdef _BIG_WORDS
	copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#endif /* _BIG_WORDS */

	/* Append length in bits and transform */
	md4Info->data[ 14 ] = md4Info->countLo;
	md4Info->data[ 15 ] = md4Info->countHi;

#ifndef _BIG_WORDS
	littleToBigLong( md4Info->data, MD4_DATASIZE - 8 );
#endif /* _BIG_WORDS */
	MD4Transform( md4Info->digest, md4Info->data );

	md4Info->done = TRUE;
	}

/****************************************************************************
*																			*
* 								MD4 Test Code 								*
*																			*
****************************************************************************/

#ifdef TEST_MD4

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Defines for the standalone test version */

#define ERROR	-1
#define OK		0

/* Test the MD4 implementation */

static LONG md4TestResults[][ 5 ] = {
#if 0
	{ 0x31D6CFE0L, 0xD16AE931L, 0xB73C59D7L, 0xE0C089C0L },
	{ 0xBDE52CB3L, 0x1DE33E46L, 0x245E05FBL, 0xDBD6FB24L },
	{ 0xA448017AL, 0xAF21D852L, 0x5FC10AE8L, 0x7AA6729DL },
	{ 0xD9130A81L, 0x64549FE8L, 0x18874806L, 0xE1C7014BL },
	{ 0xD79E1C30L, 0x8AA5BBCDL, 0xEEA8ED63L, 0xDF412DA9L },
	{ 0x043F8582L, 0xF241DB35L, 0x1CE627E1L, 0x53E7F0E4L },
	{ 0xE33B4DDCL, 0x9C38F219L, 0x9C3E7B16L, 0x4FCC0536L } 
#else
	{ 0xE0CFD631L, 0x31E96AD1L, 0xD7593CB7L, 0xC089C0E0L },
	{ 0xB32CE5BDL, 0x463EE31DL, 0xFB055E24L, 0x24FBD6DBL },
	{ 0x7A0148A4L, 0x52D821AFL, 0xE80AC15FL, 0x9D72A67AL },
	{ 0x810A13D9L, 0xE89F5464L, 0x06488718L, 0x4B01C7E1L },
	{ 0x301C9ED7L, 0xCDBBA58AL, 0x63EDA8EEL, 0xA92D41DFL },
	{ 0x82853F04L, 0x35DB41F2L, 0xE127E61CL, 0xE4F0E753L },
	{ 0xDC4D3BE3L, 0x19F2389CL, 0x167B3E9CL, 0x3605CC4FL } 
#endif /* 0 */
	};

static int compareMD4results( MD4_INFO *md4Info, int md4TestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 4; i++ )
		if( md4Info->digest[ i ] != md4TestResults[ md4TestLevel ][ i ] )
			return( ERROR );
	return( OK );
	}

void main( void )
	{
	MD4_INFO md4Info;
	unsigned int i;
	time_t secondCount;
	BYTE data[ 200 ];

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for odd
	   things like middle-endianness without knowing the size of the data
	   types */
#ifdef LITTLE_ENDIAN
	if( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 )
		{
		puts( "Error: Comment out the LITTLE_ENDIAN define in MD4.H and recompile" );
		exit( ERROR );
		}
#else
	if( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" >= 0 )
		{
		puts( "Error: Uncomment the LITTLE_ENDIAN define in MD4.H and recompile" );
		exit( ERROR );
		}
#endif /* LITTLE_ENDIAN */

	/* Test MD4 against values given in MD4 standards document RFC 1321 */
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "", 0 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 0 ) == ERROR )
		{
		puts( "MD4 test 1 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "a", 1 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 1 ) == ERROR )
		{
		puts( "MD4 test 2 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "abc", 3 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 2 ) == ERROR )
		{
		puts( "MD4 test 3 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "message digest", 14 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 3 ) == ERROR )
		{
		puts( "MD4 test 4 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "abcdefghijklmnopqrstuvwxyz", 26 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 4 ) == ERROR )
		{
		puts( "MD4 test 5 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 5 ) == ERROR )
		{
		puts( "MD4 test 6 failed" );
		exit( ERROR );
		}
	md4Initial( &md4Info );
	md4Update( &md4Info, ( BYTE * ) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80 );
	md4Final( &md4Info );
	if( compareMD4results( &md4Info, 6 ) == ERROR )
		{
		puts( "MD4 test 7 failed" );
		exit( ERROR );
		}
	puts( "All MD4 tests passed" );

	printf( "\nTesting speed for 10MB data... " );
	md4Initial( &md4Info );
	secondCount = time( NULL );
	for( i = 0; i < 50000U; i++ )
		md4Update( &md4Info, data, 200 );
	secondCount = time( NULL ) - secondCount;
	printf( "done.  Time = %ld seconds, %ld kbytes/second\n", \
			secondCount, 10050L / secondCount );

	puts( "\nAll MD4 tests passed" );
	exit( OK );
	}
#endif /* TEST_MD4 */
