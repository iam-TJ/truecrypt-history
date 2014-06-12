/****************************************************************************
*																			*
*								The STREAM Class							*
*						Copyright Peter Gutmann 1993-1996					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "stream.h"
#else
  #include "keymgmt/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Stream I/O Functions						*
*																			*
****************************************************************************/

/* Read a byte from a stream */

int sgetc( STREAM *stream )
	{
	int ch;

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != STREAM_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = STREAM_EMPTY;
		return( STREAM_EMPTY );
		}

	/* If we ungot a char, return this */
	if( stream->ungetChar )
		{
		ch = stream->lastChar;
		stream->ungetChar = FALSE;
		return( ch );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( stream->bufSize )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufEnd )
			{
			stream->status = STREAM_EMPTY;
			return( STREAM_EMPTY );
			}
		return( stream->lastChar = stream->buffer[ stream->bufPos++ ] );
		}

	/* It's a file stream, read the data from the file */
	if( ( ch = getc( stream->filePtr ) ) == EOF )
		{
		stream->status = STREAM_READ;
		return( STREAM_READ );
		}
	return( stream->lastChar = ch );
	}

/* Write a byte to a stream */

int sputc( STREAM *stream, int data )
	{
	register int regData = data;

	/* With any luck localData is now in a register, so we can try to destroy
	   the copy of the data on the stack.  We do this by assigning a live
	   value to it and using it a little later on.  A really good optimizing
	   compiler should detect that this is a nop, but with any luck most
	   compilers won't */
	data = stream->status;

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( data != STREAM_OK )
		return( data );		/* Equal to stream->status, force reuse of data */

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos++;
		return( STREAM_OK );
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( stream->bufSize )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufSize )
			{
			stream->status = STREAM_FULL;
			return( STREAM_FULL );
			}
		stream->buffer[ stream->bufPos++ ] = regData;
		stream->bufEnd = stream->bufPos;
		return( STREAM_OK );
		}

	/* It's a file stream, write the data to the file */
	if( putc( regData, stream->filePtr ) == EOF )
		{
		stream->status = STREAM_WRITE;
		return( STREAM_WRITE );
		}
	return( STREAM_OK );
	}

/* Unget a byte from a stream */

int sungetc( STREAM *stream )
	{
	stream->ungetChar = TRUE;
	return( STREAM_OK );
	}

/* Read a block of data from a stream.  If not enough data is available it
   will fail with STREAM_EMPTY rather than trying to read as much as it
   can, which mirrors the behaviour of most read()/fread() implementations */

int sread( STREAM *stream, void *buffer, int length )
	{
	BYTE *bufPtr = buffer;

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != STREAM_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = STREAM_EMPTY;
		return( STREAM_EMPTY );
		}
	if( length == 0 )
		return( STREAM_OK );

	/* If we ungot a char, return this first */
	if( stream->ungetChar )
		{
		*bufPtr++ = stream->lastChar;
		stream->ungetChar = FALSE;
		if( !--length )
			return( STREAM_OK );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( stream->bufSize )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufEnd )
			{
			stream->status = STREAM_EMPTY;
			return( STREAM_EMPTY );
			}
		memcpy( buffer, stream->buffer + stream->bufPos, length );
		stream->bufPos += length;
		return( STREAM_OK );
		}

	/* It's a file stream, read the data from the file */
	if( fread( bufPtr, 1, length, stream->filePtr ) != ( size_t ) length )
		{
		stream->status = STREAM_READ;
		return( STREAM_READ );
		}
	return( STREAM_OK );
	}

/* Write a block of data from a stream.  If not enough data is available it
   will fail with STREAM_FULL rather than trying to write as much as it
   can, which mirrors the behaviour of most write()/fwrite()
   implementations */

int swrite( STREAM *stream, const void *buffer, const int length )
	{
	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( stream->status != STREAM_OK )
		return( stream->status );
	if( length == 0 )
		return( STREAM_OK );

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos += length;
		return( STREAM_OK );
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( stream->bufSize )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufSize )
			{
			stream->status = STREAM_FULL;
			return( STREAM_FULL );
			}
		memcpy( stream->buffer + stream->bufPos, buffer, length );
		stream->bufEnd += length;
		stream->bufPos += length;
		return( STREAM_OK );
		}

	/* It's a file stream, write the data to the file */
	if( fwrite( buffer, 1, length, stream->filePtr ) != ( size_t ) length )
		{
		stream->status = STREAM_WRITE;
		return( STREAM_WRITE );
		}
	return( STREAM_OK );
	}

/* Skip a number of bytes in a stream */

int sSkip( STREAM *stream, const int length )
	{
	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != STREAM_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = STREAM_EMPTY;
		return( STREAM_EMPTY );
		}
	if( length == 0 )
		return( STREAM_OK );

	/* If it's a memory stream, move ahead in the buffer */
	if( stream->bufSize )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufEnd )
			{
			stream->status = STREAM_EMPTY;
			return( STREAM_EMPTY );
			}
		stream->bufPos += length;
		return( STREAM_OK );
		}

	/* It's a file stream, skip the data in the file */
	if( fseek( stream->filePtr, ( long ) length, SEEK_CUR ) )
		{
		stream->status = STREAM_READ;
		return( STREAM_READ );
		}
	return( STREAM_OK );
	}

/****************************************************************************
*																			*
*							Memory Stream Functions							*
*																			*
****************************************************************************/

/* Open a memory stream */

int sMemOpen( STREAM *stream, void *buffer, const int length )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL || buffer == NULL || \
		( length < 1 && length != STREAMSIZE_UNKNOWN ) )
		return( STREAM_BADPARAM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->buffer = buffer;
	stream->bufSize = stream->bufEnd = length;
	if( stream->bufSize != STREAMSIZE_UNKNOWN )
		memset( stream->buffer, 0, stream->bufSize );

	return( STREAM_OK );
	}

/* Create a null stream to serve as a data sink - this is useful for
   implementing sizeof() functions by writing data to null streams */

int sMemNullOpen( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->isNull = TRUE;

	return( STREAM_OK );
	}

/* Close a memory stream */

int sMemClose( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Clear the stream structure */
	if( stream->buffer != NULL && stream->bufSize != STREAMSIZE_UNKNOWN )
		zeroise( stream->buffer, stream->bufSize );
	zeroise( stream, sizeof( STREAM ) );

	return( STREAM_OK );
	}

/* Connect a memory stream without destroying the buffer contents */

int sMemConnect( STREAM *stream, void *buffer, const int length )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL || buffer == NULL || \
		( length < 1 && length != STREAMSIZE_UNKNOWN ) )
		return( STREAM_BADPARAM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->buffer = buffer;
	stream->bufSize = stream->bufEnd = length;

	return( STREAM_OK );
	}

/* Disconnect a memory stream without destroying the buffer contents */

int sMemDisconnect( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Clear the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	return( STREAM_OK );
	}

/* Move the read/write pointer to a certain position in the stream */

int sMemSeek( STREAM *stream, const size_t position )
	{
	/* Make sure all parameters are in order.  We don't need to check for
	   position < 0 because size_t is always unsigned */
	if( stream == NULL || ( stream->bufSize != STREAMSIZE_UNKNOWN && \
							( int ) position > stream->bufSize ) )
		return( STREAM_BADPARAM );

	/* Set the new R/W position */
	stream->bufPos = ( int ) position;
	return( STREAM_OK );
	}

/* Reset the buffer contents to empty */

int sMemReset( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Reset the buffer information for an empty stream */
	if( stream->buffer != NULL && stream->bufSize != STREAMSIZE_UNKNOWN )
		zeroise( stream->buffer, stream->bufSize );
	stream->bufPos = stream->bufEnd = 0;

	return( STREAM_OK );
	}

/* Evaluate the size of the stream */

int sMemSize( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	return( stream->bufPos );
	}

/****************************************************************************
*																			*
*							File Stream Functions							*
*																			*
****************************************************************************/

/* Open a file stream */

int sFileOpen( STREAM *stream, const char *fileName, const char *mode )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL || fileName == NULL || mode == NULL )
		return( STREAM_BADPARAM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	if( ( stream->filePtr = fopen( fileName, mode ) ) == NULL )
		return( STREAM_OPEN );

	return( STREAM_OK );
	}

/* Close a file stream */

int sFileClose( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Close the file and clear the stream structure */
	if( fclose( stream->filePtr ) )
		return( STREAM_CLOSE );
	zeroise( stream, sizeof( STREAM ) );

	return( STREAM_OK );
	}

/* Connect a file with a stream */

int sFileConnect( STREAM *stream, FILE *filePtr )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL || filePtr == NULL )
		return( STREAM_BADPARAM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->filePtr = filePtr;

	return( STREAM_OK );
	}

/* Disconnect a file from a stream */

int sFileDisconnect( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Clear the stream structure */
	zeroise( stream, sizeof( STREAM ) );

	return( STREAM_OK );
	}

/* Seek to a position in a file stream */

int sFileSeek( STREAM *stream, const long position )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( STREAM_BADPARAM );

	/* Seek to the position in the file */
	if( fseek( stream->filePtr, position, SEEK_SET ) )
		return( STREAM_SEEK );

	return( STREAM_OK );
	}
