/****************************************************************************
*																			*
*						STREAM Class Constants and Structures				*
*						  Copyright Peter Gutmann 1993-1996					*
*																			*
****************************************************************************/

#ifndef _STREAM_DEFINED

#define _STREAM_DEFINED

#include <stdio.h>
#if defined( INC_CHILD )
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* There are a few OS's broken enough to not define the standard seek codes
   which are needed by sFileSeek() (SunOS springs to mind), so we define
   them here just in case */

#ifndef SEEK_SET
  #define SEEK_SET	0
  #define SEEK_CUR	1
  #define SEEK_END	2
#endif /* SEEK_SET */

/****************************************************************************
*																			*
*								STREAM Constants							*
*																			*
****************************************************************************/

/* STREAM error types */

#define STREAM_OK				0	/* No error */
#define STREAM_ERROR			-1	/* General error */
#define STREAM_BADPARAM			-2	/* Bad parameter passed to function */
#define STREAM_OPEN				-3	/* Cannot open stream */
#define STREAM_CLOSE			-4	/* Cannot close stream */
#define STREAM_READ				-5	/* Read error on stream */
#define STREAM_WRITE			-6	/* Write error on stream */
#define STREAM_SEEK				-7	/* Seek error on stream */
#define STREAM_FULL				-8	/* No space left on stream */
#define STREAM_EMPTY			-9	/* No data left in stream */
#define STREAM_BADDATA			-10	/* User-defined data error in stream */

/* Occasionally we want to connect a memory stream to a fixed-length buffer
   whose size is "big enough for the data it needs to hold", but of an
   unknown length.  Using the following as the length will avoid various
   checks on the input length */

#define STREAMSIZE_UNKNOWN		-1

/****************************************************************************
*																			*
*							STREAM Class Structures							*
*																			*
****************************************************************************/

/* The STREAM data type */

typedef struct {
	/* Information for memory I/O */
	BYTE *buffer;				/* Buffer to R/W to */
	int bufSize;				/* Total size of buffer */
	int bufPos;					/* Current position in buffer */
	int bufEnd;					/* Last buffer position with valid data */

	/* Information for file I/O */
	FILE *filePtr;				/* The file associated with this stream */

	/* General information for the stream */
	BOOLEAN isNull;				/* Whether this is a null stream */
	int status;					/* Current stream status */
	int lastChar;				/* Last char read, for ungetc() function */
	int ungetChar;				/* Whether we need to return lastChar next */
	} STREAM;

/****************************************************************************
*																			*
*							STREAM Class Function Prototypes				*
*																			*
****************************************************************************/

/* Read and write a byte or block of data to/from a stream */

int sputc( STREAM *stream, int data );
int sgetc( STREAM *stream );
int sungetc( STREAM *stream );
int sread( STREAM *stream, void *buffer, int length );
int swrite( STREAM *stream, const void *buffer, const int length );

/* Skip a number of bytes in a stream */

int sSkip( STREAM *stream, const int length );

/* Inquire as to the health of a stream */

#define sGetStatus( stream )			( stream )->status

/* Set/clear user-defined error state for the stream */

#define sSetError( stream, error )		if( ( stream )->status == STREAM_OK ) \
											( stream )->status = ( error )
#define sClearError( stream )			( stream )->status = STREAM_OK

/* Clear the unget buffer for a stream */

#define sClearUnget( stream )			sungetc( stream ); sgetc( stream );

/* Functions to work with memory streams */

int sMemOpen( STREAM *stream, void *buffer, const int length );
int sMemNullOpen( STREAM *stream );
int sMemClose( STREAM *stream );
int sMemConnect( STREAM *stream, void *buffer, const int length );
int sMemDisconnect( STREAM *stream );
int sMemSeek( STREAM *stream, const size_t position );
int sMemReset( STREAM *stream );
int sMemSize( STREAM *stream );

/* Functions to work with file streams */

int sFileOpen( STREAM *stream, const char *fileName, const char *mode );
int sFileClose( STREAM *stream );
int sFileConnect( STREAM *stream, FILE *filePtr );
int sFileDisconnect( STREAM *stream );
int sFileSeek( STREAM *stream, const long position );

#endif /* _STREAM_DEFINED */
