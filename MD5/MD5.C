/****************************************************************************
*																			*
*				Implementation of the RSA Data Security, Inc.				*
*						MD5 Message-Digest Algorithm						*
*																			*
****************************************************************************/

#include <string.h>
#ifdef _MSC_VER
  #include "../crypt.h"
  #include "md5.h"
#else
  #include "crypt.h"
  #include "md5/md5.h"
#endif /* _MSC_VER */

/****************************************************************************
*																			*
*							The MD5 Transformation							*
*																			*
****************************************************************************/

/* Round 1 shift amounts */

#define S11	7
#define S12	12
#define S13	17
#define S14	22

/* Round 2 shift amounts */

#define S21 5
#define S22 9
#define S23 14
#define S24 20

/* Round 3 shift amounts */

#define S31 4
#define S32 11
#define S33 16
#define S34 23

/* Round 4 shift amounts */

#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions */

#define F(X,Y,Z)	( ( X & Y ) | ( ~X & Z ) )
#define G(X,Y,Z)	( ( X & Z ) | ( Y & ~Z ) )
#define H(X,Y,Z)	( X ^ Y ^ Z )
#define I(X,Y,Z)	( Y ^ ( X | ~Z ) )

/* ROTATE_LEFT rotates x left n bits */

#define ROTATE_LEFT(x,n)	( ( x << n ) | ( x >> ( 32 - n ) ) )

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */

#ifdef _BIG_WORDS

#define FF(A,B,C,D,X,shiftAmt,magicConst) \
	A += F( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ) + B; \
	A &= 0xFFFFFFFFUL

#define GG(A,B,C,D,X,shiftAmt,magicConst) \
	A += G( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ) + B; \
	A &= 0xFFFFFFFFUL

#define HH(A,B,C,D,X,shiftAmt,magicConst) \
	A += H( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ) + B; \
	A &= 0xFFFFFFFFUL

#define II(A,B,C,D,X,shiftAmt,magicConst) \
	A += I( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( ( A & 0xFFFFFFFFUL ), shiftAmt ) + B; \
	A &= 0xFFFFFFFFUL

#else

#define FF(A,B,C,D,X,shiftAmt,magicConst) \
	A += F( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( A, shiftAmt ) + B

#define GG(A,B,C,D,X,shiftAmt,magicConst) \
	A += G( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( A, shiftAmt ) + B

#define HH(A,B,C,D,X,shiftAmt,magicConst) \
	A += H( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( A, shiftAmt ) + B

#define II(A,B,C,D,X,shiftAmt,magicConst) \
	A += I( B, C, D ) + X + magicConst; \
	A = ROTATE_LEFT( A, shiftAmt ) + B

#endif /* _BIG_WORDS */

/* Basic MD5 step. Transforms digest based on data.  Note that if the
   Mysterious Constants are arranged backwards in little-endian order and
   decrypted with DES they produce OCCULT MESSAGES! */

void MD5Transform( LONG *digest, LONG *data )
	{
	LONG A, B, C, D;

	/* Set up local data */
	A = digest[ 0 ];
	B = digest[ 1 ];
	C = digest[ 2 ];
	D = digest[ 3 ];

	/* Round 1 */
	FF( A, B, C, D, data[  0 ], S11, 3614090360UL );	/*  1 */
	FF( D, A, B, C, data[  1 ], S12, 3905402710UL );	/*  2 */
	FF( C, D, A, B, data[  2 ], S13,  606105819UL );	/*  3 */
	FF( B, C, D, A, data[  3 ], S14, 3250441966UL );	/*  4 */
	FF( A, B, C, D, data[  4 ], S11, 4118548399UL );	/*  5 */
	FF( D, A, B, C, data[  5 ], S12, 1200080426UL );	/*  6 */
	FF( C, D, A, B, data[  6 ], S13, 2821735955UL );	/*  7 */
	FF( B, C, D, A, data[  7 ], S14, 4249261313UL );	/*  8 */
	FF( A, B, C, D, data[  8 ], S11, 1770035416UL );	/*  9 */
	FF( D, A, B, C, data[  9 ], S12, 2336552879UL );	/* 10 */
	FF( C, D, A, B, data[ 10 ], S13, 4294925233UL );	/* 11 */
	FF( B, C, D, A, data[ 11 ], S14, 2304563134UL );	/* 12 */
	FF( A, B, C, D, data[ 12 ], S11, 1804603682UL );	/* 13 */
	FF( D, A, B, C, data[ 13 ], S12, 4254626195UL );	/* 14 */
	FF( C, D, A, B, data[ 14 ], S13, 2792965006UL );	/* 15 */
	FF( B, C, D, A, data[ 15 ], S14, 1236535329UL );	/* 16 */

	/* Round 2 */
	GG( A, B, C, D, data[  1 ], S21, 4129170786UL );	/* 17 */
	GG( D, A, B, C, data[  6 ], S22, 3225465664UL );	/* 18 */
	GG( C, D, A, B, data[ 11 ], S23,  643717713UL );	/* 19 */
	GG( B, C, D, A, data[  0 ], S24, 3921069994UL );	/* 20 */
	GG( A, B, C, D, data[  5 ], S21, 3593408605UL );	/* 21 */
	GG( D, A, B, C, data[ 10 ], S22,   38016083UL );	/* 22 */
	GG( C, D, A, B, data[ 15 ], S23, 3634488961UL );	/* 23 */
	GG( B, C, D, A, data[  4 ], S24, 3889429448UL );	/* 24 */
	GG( A, B, C, D, data[  9 ], S21,  568446438UL );	/* 25 */
	GG( D, A, B, C, data[ 14 ], S22, 3275163606UL );	/* 26 */
	GG( C, D, A, B, data[  3 ], S23, 4107603335UL );	/* 27 */
	GG( B, C, D, A, data[  8 ], S24, 1163531501UL );	/* 28 */
	GG( A, B, C, D, data[ 13 ], S21, 2850285829UL );	/* 29 */
	GG( D, A, B, C, data[  2 ], S22, 4243563512UL );	/* 30 */
	GG( C, D, A, B, data[  7 ], S23, 1735328473UL );	/* 31 */
	GG( B, C, D, A, data[ 12 ], S24, 2368359562UL );	/* 32 */

	/* Round 3 */
	HH( A, B, C, D, data[  5 ], S31, 4294588738UL );	/* 33 */
	HH( D, A, B, C, data[  8 ], S32, 2272392833UL );	/* 34 */
	HH( C, D, A, B, data[ 11 ], S33, 1839030562UL );	/* 35 */
	HH( B, C, D, A, data[ 14 ], S34, 4259657740UL );	/* 36 */
	HH( A, B, C, D, data[  1 ], S31, 2763975236UL );	/* 37 */
	HH( D, A, B, C, data[  4 ], S32, 1272893353UL );	/* 38 */
	HH( C, D, A, B, data[  7 ], S33, 4139469664UL );	/* 39 */
	HH( B, C, D, A, data[ 10 ], S34, 3200236656UL );	/* 40 */
	HH( A, B, C, D, data[ 13 ], S31,  681279174UL );	/* 41 */
	HH( D, A, B, C, data[  0 ], S32, 3936430074UL );	/* 42 */
	HH( C, D, A, B, data[  3 ], S33, 3572445317UL );	/* 43 */
	HH( B, C, D, A, data[  6 ], S34,   76029189UL );	/* 44 */
	HH( A, B, C, D, data[  9 ], S31, 3654602809UL );	/* 45 */
	HH( D, A, B, C, data[ 12 ], S32, 3873151461UL );	/* 46 */
	HH( C, D, A, B, data[ 15 ], S33,  530742520UL );	/* 47 */
	HH( B, C, D, A, data[  2 ], S34, 3299628645UL );	/* 48 */

	/* Round 4 */
	II( A, B, C, D, data[  0 ], S41, 4096336452UL );	/* 49 */
	II( D, A, B, C, data[  7 ], S42, 1126891415UL );	/* 50 */
	II( C, D, A, B, data[ 14 ], S43, 2878612391UL );	/* 51 */
	II( B, C, D, A, data[  5 ], S44, 4237533241UL );	/* 52 */
	II( A, B, C, D, data[ 12 ], S41, 1700485571UL );	/* 53 */
	II( D, A, B, C, data[  3 ], S42, 2399980690UL );	/* 54 */
	II( C, D, A, B, data[ 10 ], S43, 4293915773UL );	/* 55 */
	II( B, C, D, A, data[  1 ], S44, 2240044497UL );	/* 56 */
	II( A, B, C, D, data[  8 ], S41, 1873313359UL );	/* 57 */
	II( D, A, B, C, data[ 15 ], S42, 4264355552UL );	/* 58 */
	II( C, D, A, B, data[  6 ], S43, 2734768916UL );	/* 59 */
	II( B, C, D, A, data[ 13 ], S44, 1309151649UL );	/* 60 */
	II( A, B, C, D, data[  4 ], S41, 4149444226UL );	/* 61 */
	II( D, A, B, C, data[ 11 ], S42, 3174756917UL );	/* 62 */
	II( C, D, A, B, data[  2 ], S43,  718787259UL );	/* 63 */
	II( B, C, D, A, data[  9 ], S44, 3951481745UL );	/* 64 */

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
*							MD5 Support Routines							*
*																			*
****************************************************************************/

/* The routine md5Initial initializes the message-digest context md5Info */

void md5Initial( MD5_INFO *md5Info )
	{
	/* Clear all fields */
	memset( md5Info, 0, sizeof( MD5_INFO ) );

	/* Load magic initialization constants */
	md5Info->digest[ 0 ] = 0x67452301L;
	md5Info->digest[ 1 ] = 0xEFCDAB89L;
	md5Info->digest[ 2 ] = 0x98BADCFEL;
	md5Info->digest[ 3 ] = 0x10325476L;

	/* Initialise bit count */
	md5Info->countLo = md5Info->countHi = 0L;
	}

#ifdef TEST_MD5

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

#endif /* TEST_MD5 */

#ifdef _BIG_WORDS

/* When run on a CPU with > 32 bit word size, we need to move the data from
   the byte-aligned buffer to the final word-aligned data buffer.  We perform
   the endianness-reversal at the same time */

static void extractData( MD5_INFO *md5Info )
	{
	BYTE *bufferPtr = md5Info->dataBuffer;
	int i;

	for( i = 0; i < 16; i++ )
		{
		md5Info->data[ i ] = ( ( LONG ) bufferPtr[ 0 ] << 24 ) | \
							 ( ( LONG ) bufferPtr[ 1 ] << 16 ) | \
							 ( ( LONG ) bufferPtr[ 2 ] << 8 ) | \
							 ( ( LONG ) bufferPtr[ 3 ] );
		bufferPtr += 4;
		}
	}
#endif /* _BIG_WORDS */

/* The routine MD5Update updates the message-digest context to account for
   the presence of each of the characters buffer[ 0 .. count-1 ] in the
   message whose digest is being computed.  This is an optimized version
   which assumes that the buffer is a multiple of MD5_BLOCKSIZE bytes long */

void md5Update( MD5_INFO *md5Info, BYTE *buffer, int count )
	{
	LONG tmp;
	int dataCount;

	/* Update bitcount */
	tmp = md5Info->countLo;
	if ( ( md5Info->countLo = tmp + ( ( LONG ) count << 3 ) ) < tmp )
		md5Info->countHi++;				/* Carry from low to high */
	md5Info->countHi += count >> 29;

	/* Get count of bytes already in data */
	dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if( dataCount )
		{
#ifdef _BIG_WORDS
		BYTE *p = md5Info->dataBuffer + dataCount;
#else
		BYTE *p = ( BYTE * ) md5Info->data + dataCount;
#endif /* _BIG_WORDS */

		dataCount = MD5_DATASIZE - dataCount;
		if( count < dataCount )
			{
			memcpy( p, buffer, count );
			return;
			}
		memcpy( p, buffer, dataCount );
#ifdef _BIG_WORDS
		copyToLLong( md5Info->data, md5Info->dataBuffer, MD5_DATASIZE );
#else
		littleToBigLong( md5Info->data, MD5_DATASIZE );
#endif /* _BIG_WORDS */
		MD5Transform( md5Info->digest, md5Info->data );
		buffer += dataCount;
		count -= dataCount;
		}

	/* Process data in MD5_DATASIZE chunks */
	while( count >= MD5_DATASIZE )
		{
#ifdef _BIG_WORDS
		memcpy( md5Info->dataBuffer, buffer, MD5_DATASIZE );
		copyToLLong( md5Info->data, md5Info->dataBuffer, MD5_DATASIZE );
#else
		memcpy( md5Info->data, buffer, MD5_DATASIZE );
		littleToBigLong( md5Info->data, MD5_DATASIZE );
#endif /* _BIG_WORDS */
		MD5Transform( md5Info->digest, md5Info->data );
		buffer += MD5_DATASIZE;
		count -= MD5_DATASIZE;
		}

	/* Handle any remaining bytes of data. */
#ifdef _BIG_WORDS
	memcpy( md5Info->dataBuffer, buffer, count );
#else
	memcpy( md5Info->data, buffer, count );
#endif /* _BIG_WORDS */
	}

/* Final wrapup - pad to MD5_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void md5Final( MD5_INFO *md5Info )
	{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = ( int ) md5Info->countLo;
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
#ifdef _BIG_WORDS
	dataPtr = md5Info->dataBuffer + count;
#else
	dataPtr = ( BYTE * ) md5Info->data + count;
#endif /* _BIG_WORDS */
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = MD5_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 )
		{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( dataPtr, 0, count );
#ifdef _BIG_WORDS
		copyToLLong( md5Info->data, md5Info->dataBuffer, MD5_DATASIZE );
#else
		littleToBigLong( md5Info->data, MD5_DATASIZE );
#endif /* _BIG_WORDS */
		MD5Transform( md5Info->digest, md5Info->data );

		/* Now fill the next block with 56 bytes */
#ifdef _BIG_WORDS
		memset( md5Info->dataBuffer, 0, MD5_DATASIZE - 8 );
#else
		memset( md5Info->data, 0, MD5_DATASIZE - 8 );
#endif /* _BIG_WORDS */
		}
	else
		/* Pad block to 56 bytes */
		memset( dataPtr, 0, count - 8 );
#ifdef _BIG_WORDS
	copyToLLong( md5Info->data, md5Info->dataBuffer, MD5_DATASIZE );
#endif /* _BIG_WORDS */

	/* Append length in bits and transform */
	md5Info->data[ 14 ] = md5Info->countLo;
	md5Info->data[ 15 ] = md5Info->countHi;

#ifndef _BIG_WORDS
	littleToBigLong( md5Info->data, MD5_DATASIZE - 8 );
#endif /* _BIG_WORDS */
	MD5Transform( md5Info->digest, md5Info->data );

	md5Info->done = TRUE;
	}

/****************************************************************************
*																			*
* 								MD5 Test Code 								*
*																			*
****************************************************************************/

#ifdef TEST_MD5

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Defines for the standalone test version */

#define ERROR	-1
#define OK		0

/* Test the MD5 implementation */

static LONG md5TestResults[][ 5 ] = {
#if 0
	{ 0xD41D8CD9L, 0x8F00B204L, 0xE9800998L, 0xECF8427EL },
	{ 0x0CC175B9L, 0xC0F1B6A8L, 0x31C399E2L, 0x69772661L },
	{ 0x90015098L, 0x3CD24FB0L, 0xD6963F7DL, 0x28E17F72L },
	{ 0xF96B697DL, 0x7CB7938DL, 0x525A2F31L, 0xAAF161D0L },
	{ 0xC3FCD3D7L, 0x6192E400L, 0x7DFB496CL, 0xCA67E13BL },
	{ 0xD174AB98L, 0xD277D9F5L, 0xA5611C2CL, 0x9F419D9FL },
	{ 0x57EDF4A2L, 0x2BE3C955L, 0xAC49DA2EL, 0x2107B67AL }
#else
	{ 0xD98C1DD4L, 0x04B2008FL, 0x980980E9L, 0x7E42F8ECL },
	{ 0xB975C10CL, 0xA8B6F1C0L, 0xE299C331L, 0x61267769L },
	{ 0x98500190L, 0xB04FD23CL, 0x7D3F96D6L, 0x727FE128L },
	{ 0x7D696BF9L, 0x8D93B77CL, 0x312F5A52L, 0xD061F1AAL },
	{ 0xD7D3FCC3L, 0x00E49261L, 0x6C49FB7DL, 0x3BE167CAL },
	{ 0x98AB74D1L, 0xF5D977D2L, 0x2C1C61A5L, 0x9F9D419FL },
	{ 0xA2F4ED57L, 0x55C9E32BL, 0x2EDA49ACL, 0x7AB60721L }
#endif /* 0 */
	};

static int compareMD5results( MD5_INFO *md5Info, int md5TestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 4; i++ )
		if( md5Info->digest[ i ] != md5TestResults[ md5TestLevel ][ i ] )
			return( ERROR );
	return( OK );
	}

void main( void )
	{
	MD5_INFO md5Info;
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
		puts( "Error: Comment out the LITTLE_ENDIAN define in MD5.H and recompile" );
		exit( ERROR );
		}
#else
	if( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" >= 0 )
		{
		puts( "Error: Uncomment the LITTLE_ENDIAN define in MD5.H and recompile" );
		exit( ERROR );
		}
#endif /* LITTLE_ENDIAN */

	/* Test MD5 against values given in MD5 standards document RFC 1321 */
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "", 0 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 0 ) == ERROR )
		{
		puts( "MD5 test 1 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "a", 1 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 1 ) == ERROR )
		{
		puts( "MD5 test 2 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "abc", 3 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 2 ) == ERROR )
		{
		puts( "MD5 test 3 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "message digest", 14 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 3 ) == ERROR )
		{
		puts( "MD5 test 4 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "abcdefghijklmnopqrstuvwxyz", 26 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 4 ) == ERROR )
		{
		puts( "MD5 test 5 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 5 ) == ERROR )
		{
		puts( "MD5 test 6 failed" );
		exit( ERROR );
		}
	md5Initial( &md5Info );
	md5Update( &md5Info, ( BYTE * ) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80 );
	md5Final( &md5Info );
	if( compareMD5results( &md5Info, 6 ) == ERROR )
		{
		puts( "MD5 test 7 failed" );
		exit( ERROR );
		}
	puts( "All MD5 tests passed" );

	printf( "\nTesting speed for 10MB data... " );
	md5Initial( &md5Info );
	secondCount = time( NULL );
	for( i = 0; i < 50000U; i++ )
		md5Update( &md5Info, data, 200 );
	secondCount = time( NULL ) - secondCount;
	printf( "done.  Time = %ld seconds, %ld kbytes/second\n", \
			secondCount, 10050L / secondCount );

	puts( "\nAll MD5 tests passed" );
	exit( OK );
	}
#endif /* TEST_MD5 */
