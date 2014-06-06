/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#define mputLong(memPtr,data) \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 24 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 16 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 8 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( data ) & 0xFF )

#define mputWord(memPtr,data) \
	*memPtr++ = ( unsigned char ) ( ( ( data ) >> 8 ) & 0xFF ), \
	*memPtr++ = ( unsigned char ) ( ( data ) & 0xFF )

#define mputByte(memPtr,data)	\
	*memPtr++ = ( unsigned char ) data

#define mputBytes(memPtr,data,len)  \
	memcpy (memPtr,data,len); \
	memPtr += len;

/* Macros to read and write 16 and 32-bit quantities in a portable manner.
   These functions are implemented as macros rather than true functions as
   the need to adjust the memory pointers makes them somewhat painful to call
   in user code */

#define mgetLong(memPtr) 		\
	( ( ( unsigned long ) memPtr[ 0 ] << 24 ) | ( ( unsigned long ) memPtr[ 1 ] << 16 ) | \
	  ( ( unsigned long ) memPtr[ 2 ] << 8 ) | ( unsigned long ) memPtr[ 3 ] ); \
	memPtr += 4

#define mgetWord(memPtr) 		\
	( ( unsigned short ) memPtr[ 0 ] << 8 ) | ( ( unsigned short ) memPtr[ 1 ] ); \
	memPtr += 2

#define mgetByte(memPtr)		\
	( ( unsigned char ) *memPtr++ )

#define LITTLE_ENDIAN 1

/* Everything below this line is automatically updated by the -mkproto-tool- */

void LongReverse ( unsigned long *buffer , unsigned byteCount );
