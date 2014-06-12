/****************************************************************************
*																			*
*						 ASN.1 Object Management Routines					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Context-specific tag for the message digest information record */

enum { CTAG_MD_ALGOINFO };

/* Context-specific tag for the key information record */

enum { CTAG_KI_ALGOINFO };

/* Context-specific tags for the conventional-encrypted key record */

enum { CTAG_CK_ALGOINFO, CTAG_CK_DERIVATIONINFO, CTAG_CK_KEYCOOKIE,
	   CTAG_CK_CONTROLVECTOR, CTAG_CK_IV };

/* Context-specific tags for the PKC-encrypted key record */

enum { CTAG_PK_ALGOINFO, CTAG_PK_KEYCOOKIE, CTAG_PK_CONTROLVECTOR };

/* Context-specific tag for the signature record */

enum { CTAG_SG_ALGOINFO, CTAG_SG_SIGNATURECOOKIE };

/* Context-specific tag for the encrypted data record */

enum { CTAG_ED_KEYCOOKIE };

/* Context-specific tag for the signed data record */

enum { CTAG_SD_SIGNATURECOOKIE };

/* Evaluate the size of the algorithm-specific parameters field (the
   constant 2 defines the size of the tag and the length field) */

static int sizeofAlgorithmParams( const CRYPT_INFO *cryptInfo )
	{
	BOOLEAN boolean;
	long integer;

	switch( cryptInfo->capabilityInfo->cryptAlgo )
		{
		case CRYPT_ALGO_DES:
		case CRYPT_ALGO_3DES:
			return( sizeofBoolean() + 2 );

		case CRYPT_ALGO_MDCSHS:
			integer = getMDCSHSinfo( cryptInfo );
			return( sizeofShortInteger( integer ) + 2 );

#ifndef NO_PATENT
		case CRYPT_ALGO_RC5:
			integer = getRC5info( cryptInfo );
			return( sizeofShortInteger( integer ) + 2 );
#endif /* NO_PATENT */

		case CRYPT_ALGO_SAFER:
			integer = getSaferInfo( cryptInfo, &boolean );
			return( sizeofBoolean() + sizeofShortInteger( integer ) + 2 );

		case CRYPT_ALGO_BLOWFISH:
			integer = getBlowfishInfo( cryptInfo, &boolean );
			return( sizeofBoolean() + sizeofShortInteger( integer ) + 2 );
		}

	return( CRYPT_ERROR );	/* Internal error, should never happen */
	}

/* Write the parameters for a conventional encryption algorithm */

static void writeAlgorithmParams( STREAM *stream,
								  const CAPABILITY_INFO *capabilityInfo,
								  const CRYPT_INFO *cryptInfo )
	{
	/* It's a composite type.  First, write the algorithm ID fields */
	writeEnumerated( stream, capabilityInfo->cryptAlgo, DEFAULT_TAG );
	writeEnumerated( stream, capabilityInfo->cryptMode, DEFAULT_TAG );

	/* Now write any algorithm-specific fields.  We've already checked
	   above for unknown algorithms so we don't need to include a default
	   case for this here */
	if( !cryptInfo->privateUseDefaults )
		{
		BOOLEAN boolean;
		long integer;

		writeCtag( stream, CTAG_KI_ALGOINFO, TRUE );
		switch( capabilityInfo->cryptAlgo )
			{
			case CRYPT_ALGO_DES:
				boolean = getDESinfo( cryptInfo );
				writeLength( stream, sizeofBoolean() );
				writeBoolean( stream, boolean, DEFAULT_TAG );
				break;

			case CRYPT_ALGO_3DES:
				boolean = get3DESinfo( cryptInfo );
				writeLength( stream, sizeofBoolean() );
				writeBoolean( stream, boolean, DEFAULT_TAG );
				break;

			case CRYPT_ALGO_MDCSHS:
				integer = getMDCSHSinfo( cryptInfo );
				writeLength( stream, sizeofShortInteger( integer ) );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;

#ifndef NO_PATENT
			case CRYPT_ALGO_RC5:
				integer = getRC5info( cryptInfo );
				writeLength( stream, sizeofShortInteger( integer ) );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;
#endif /* NO_PATENT */

			case CRYPT_ALGO_SAFER:
				integer = getSaferInfo( cryptInfo, &boolean );
				writeLength( stream, sizeofBoolean() +
							 sizeofShortInteger( integer ) );
				writeBoolean( stream, boolean, DEFAULT_TAG );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;

			case CRYPT_ALGO_BLOWFISH:
				integer = getBlowfishInfo( cryptInfo, &boolean );
				writeLength( stream, sizeofBoolean() +
							 sizeofShortInteger( integer ) );
				writeBoolean( stream, boolean, DEFAULT_TAG );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;
			}
		}
	}

/* Read the parameters for a conventional encryption algorithm and either
   read them into a CRYPT_OBJECT_INFO structure or create an encryption
   context to hold them */

static int readAlgorithmParams( STREAM *stream, CRYPT_CONTEXT *cryptContext,
								CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	CRYPT_INFO *cryptInfo;
	int readDataLength, tagLength, status;

	/* Read the encryption algorithm and type and make sure we know what to
	   do with it */
	readDataLength = readEnumerated( stream, ( int * ) &cryptAlgo );
	readDataLength += readEnumerated( stream, ( int * ) &cryptMode );
	if( cryptObjectInfo != NULL )
		{
		cryptObjectInfo->cryptAlgo = cryptAlgo;
		cryptObjectInfo->cryptMode = cryptMode;
		}
	if( cryptStatusError( status = cryptModeAvailable( cryptAlgo, cryptMode ) ) )
		return( status );

	/* Create an encryption context to hold the encrypted data information if
	   required */
	if( cryptContext != NULL )
		{
		if( cryptStatusError( status = cryptCreateContext( cryptContext,
												cryptAlgo, cryptMode ) ) )
			return( status );
		cryptInfo = CONTEXT_TO_INFO( *cryptContext );
		}

	/* Read the algorithm-specific parameters if necessary */
	tagLength = checkReadCtag( stream, CTAG_KI_ALGOINFO, TRUE );
	if( tagLength )
		{
		long length, integer;
		BOOLEAN boolean;
		void *cPtr;

		/* Set up a pointer to the extended parameters area if necessary (we
		   can reuse the keyID memory because it's only used for PKC's) */
		if( cryptObjectInfo != NULL )
			{
			cryptObjectInfo->cryptContextExInfo = cryptObjectInfo->keyID;
			cPtr = cryptObjectInfo->cryptContextExInfo;
			}

		readLength( stream, &length );
		readDataLength += ( int ) length + tagLength;
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_DES:
				readBoolean( stream, &boolean );
				if( cryptContext == NULL )
					( ( CRYPT_INFO_DES * ) cPtr )->isDESX = boolean;
				else
					setDESinfo( cryptInfo, boolean );
				break;

			case CRYPT_ALGO_3DES:
				readBoolean( stream, &boolean );
				if( cryptContext == NULL )
					( ( CRYPT_INFO_3DES * ) cPtr )->isThreeKey = boolean;
				else
					set3DESinfo( cryptInfo, boolean );
				break;

			case CRYPT_ALGO_MDCSHS:
				readShortInteger( stream, &integer );
				if( cryptContext == NULL )
					( ( CRYPT_INFO_MDCSHS * ) cPtr )->keySetupIterations = \
															( int ) integer;
				else
					setMDCSHSinfo( cryptInfo, ( int ) integer );
				break;

#ifndef NO_PATENT
			case CRYPT_ALGO_RC5:
				readShortInteger( stream, &integer );
				if( cryptContext == NULL )
					( ( CRYPT_INFO_RC5 * ) cPtr )->rounds = ( int ) integer;
				else
					setRC5info( cryptInfo, ( int ) integer );
				break;
#endif /* NO_PATENT */

			case CRYPT_ALGO_SAFER:
				readBoolean( stream, &boolean );
				readShortInteger( stream, &integer );
				if( cryptContext == NULL )
					{
					( ( CRYPT_INFO_SAFER * ) cPtr )->useSaferSK = boolean;
					( ( CRYPT_INFO_SAFER * ) cPtr )->rounds = ( int ) integer;
					}
				else
					setSaferInfo( cryptInfo, boolean, ( int ) integer );
				break;

			case CRYPT_ALGO_BLOWFISH:
				readBoolean( stream, &boolean );
				readShortInteger( stream, &integer );
				if( cryptContext == NULL )
					{
					( ( CRYPT_INFO_BLOWFISH * ) cPtr )->useBlowfishSK = boolean;
					( ( CRYPT_INFO_BLOWFISH * ) cPtr )->keySetupIterations = \
															( int ) integer;
					}
				else
					setBlowfishInfo( cryptInfo, boolean, ( int ) integer );
				break;

			default:
				if( cryptContext != NULL )
					cryptDestroyContext( *cryptContext );
				return( CRYPT_NOALGO );
			}
		}
	else
		/* No algorithm-specific parameters, use default settings */
		if( cryptObjectInfo != NULL )
			cryptObjectInfo->cryptContextExInfo = ( void * ) CRYPT_UNUSED;

	return( readDataLength );
	}

/* Read a generic cookie */

static int readCookie( STREAM *stream, BYTE *cookie, int *cookieSize,
					   const int expectedSize )
	{
	BYTE buffer[ MAX_COOKIE_SIZE ];
	int readDataLength, length;

	readDataLength = readStaticOctetStringData( stream, buffer, &length,
												expectedSize );
	if( ( readDataLength <= 0 ) || ( length != expectedSize ) )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	memcpy( cookie, buffer, expectedSize );
	*cookieSize = expectedSize;

	return( readDataLength );
	}

/* Write/read the key cookie and control vector */

static void writeKeyParams( STREAM *stream, const BYTE *keyCookie,
							const int cookieTag, const long controlVector,
							const int vectorTag )
	{
	if( keyCookie != NULL )
		writeByteString( stream, keyCookie, KEY_COOKIE_SIZE, cookieTag );
	if( controlVector )
		writeBitString( stream, controlVector, vectorTag );
	}

static int readKeyParams( STREAM *stream, BYTE *keyCookie, int *cookieSize,
						  const int cookieTag, long *controlVector,
						  const int vectorTag )
	{
	int readDataLength = 0, tagLength;

	/* Read the key cookie if necessary */
	*cookieSize = 0;
	tagLength = checkReadCtag( stream, cookieTag, FALSE );
	if( tagLength )
		readDataLength += readCookie( stream, keyCookie, cookieSize,
									  KEY_COOKIE_SIZE ) + tagLength;

	/* Read the control vector if necessary */
	tagLength = checkReadCtag( stream, vectorTag, FALSE );
	if( tagLength )
		readDataLength += readBitStringData( stream, controlVector ) + tagLength;

	return( readDataLength );
	}

/* Read the outer wrapper and start of a cryptlib object */

int readObjectWrapper( STREAM *stream, CRYPT_OBJECT_TYPE *objectType,
					   long *length )
	{
	static struct { int tag; CRYPT_OBJECT_TYPE objectType; } tagType[] = {
		{ BER_ENCRYPTED_KEY, CRYPT_OBJECT_ENCRYPTED_KEY },
		{ BER_PKCENCRYPTED_KEY, CRYPT_OBJECT_PKCENCRYPTED_KEY },
		{ BER_SIGNATURE, CRYPT_OBJECT_SIGNATURE },
		{ BER_ENCRYPTED_DATA, CRYPT_OBJECT_ENCRYPTED_DATA },
		{ BER_COMPRESSED_DATA, CRYPT_OBJECT_COMPRESSED_DATA },
		{ BER_SIGNED_DATA, CRYPT_OBJECT_SIGNED_DATA },
		{ BER_RAW_DATA, CRYPT_OBJECT_RAW_DATA },
		{ BER_NONDATA, CRYPT_OBJECT_NONDATA },
		{ 0, 0 } };
	int readDataLength, tag, i;
	long dummy;

	/* Read the outer wrapper identifier and length fields */
	tag = readTag( stream );
	for( i = 0; tagType[ i ].tag; i++ )
		if( tagType[ i ].tag == tag )
			break;
	if( tagType[ i ].tag )
		*objectType = tagType[ i ].objectType;
	else
		{
		*objectType = CRYPT_OBJECT_NONE;
		sSetError( stream, STREAM_BADDATA );
		}
	readDataLength = readLength( stream, length ) + 1;
	*length += readDataLength;	/* Include size of tag in total length */

	/* Read the identifier and length fields */
	if( readTag( stream ) != BER_SEQUENCE || *objectType == CRYPT_ERROR )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &dummy ) + 1;

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Read the start of a conventionally encrypted key object */

int readCKObject( STREAM *stream, CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int readDataLength, tagLength;

	/* Read the algorithm parameters */
	readDataLength = readAlgorithmParams( stream, NULL, cryptObjectInfo );
	if( cryptStatusError( readDataLength ) )
		return( readDataLength );

	/* Read the key derivation information */
	tagLength = checkReadCtag( stream, CTAG_CK_DERIVATIONINFO, TRUE );
	if( tagLength )
		{
		long integer, length;

		readLength( stream, &length );
		readDataLength = ( int ) length + tagLength;
		readEnumerated( stream, ( int * ) &cryptObjectInfo->keySetupAlgo );
		readShortInteger( stream, &integer );
		cryptObjectInfo->keySetupIterations = ( int ) integer;
		}
	else
		{
		/* Use the default settings if none are given */
		cryptObjectInfo->keySetupAlgo = DEFAULT_KEYSETUP_ALGO;
		cryptObjectInfo->keySetupIterations = DEFAULT_KEYSETUP_ITERATIONS;
		}

	/* Read the key cookie and control vector */
	readDataLength += readKeyParams( stream, cryptObjectInfo->cookie,
									 &cryptObjectInfo->cookieSize,
									 CTAG_CK_KEYCOOKIE,
									 &cryptObjectInfo->controlVector,
									 CTAG_CK_CONTROLVECTOR );

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Read the start of a public-key encrypted key or signed object */

int readPKObject( STREAM *stream, BYTE *keyID, int *keyIDsize,
				  CRYPT_ALGO *cryptAlgo )
	{
	int readDataLength, status;

	/* Read the key ID */
	readDataLength = readRawObject( stream, keyID, keyIDsize,
									CRYPT_MAX_KEYIDSIZE, BER_SEQUENCE );
	if( cryptStatusError( readDataLength ) )
		return( CRYPT_BADDATA );
	*keyIDsize += sizeof( BYTE ) + sizeof( BYTE );	/* Add header size */

	/* Read the PKC algorithm type and make sure we can handle it */
	readDataLength += readEnumerated( stream, ( int * ) cryptAlgo );
	if( cryptStatusError( status = cryptAlgoAvailable( *cryptAlgo ) ) )
		return( status );

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Read more of a public-key encrypted PKObject */

int readPKKeyObject( STREAM *stream, CRYPT_ALGO cryptAlgo,
					 CRYPT_CONTEXT *cryptContext,
					 CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int readDataLength = 0, tagLength;
	long length;

	/* Make sure we generate an error if we don't load a context */
	if( cryptContext != NULL )
		*cryptContext = NULL;

	/* Skip any optional algorithm-specific information */
	tagLength = checkReadCtag( stream, CTAG_PK_ALGOINFO, TRUE );
	if( tagLength )
		{
		int status;

		readLength( stream, &length );
		readDataLength = ( int ) length + tagLength;
		if( cryptContext == NULL )
			sSkip( stream, ( int ) length );
		else
			switch( cryptAlgo )
				{
				case CRYPT_ALGO_DH:
					/* Read the encryption algorithm information and create
					   an encryption context from it */
					if( cryptStatusError( status = \
							readAlgorithmParams( stream, cryptContext, NULL ) ) )
						return( status );
					break;

				default:
					return( CRYPT_NOALGO );
				}
		}
	else
		/* No algorithm-specific parameters, use default settings */
		if( cryptObjectInfo != NULL )
			cryptObjectInfo->cryptContextExInfo = ( void * ) CRYPT_UNUSED;

	/* Read the key cookie and control vector */
	readDataLength += readKeyParams( stream, cryptObjectInfo->cookie,
									 &cryptObjectInfo->cookieSize,
									 CTAG_PK_KEYCOOKIE,
									 &cryptObjectInfo->controlVector,
									 CTAG_PK_CONTROLVECTOR );

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Generate a key cookie */

int generateKeyCookie( CRYPT_INFO *cryptInfo )
	{
	STREAM stream;
	BYTE *buffer;
	int dataLength, status = CRYPT_OK;

	/* Allocate a buffer for the DER-encoded key parameters and write
	   everything but the key to it */
	if( ( buffer = ( BYTE * ) malloc( CRYPT_MAX_PKCSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );
	status = writeKeyInfo( &stream, cryptInfo, &dataLength, FALSE );
	if( cryptStatusOK( status ) )
		{
		CRYPT_CONTEXT cryptContext;

		/* Hash the algorithm parameters and key and copy the first
		   KEY_COOKIE_SIZE bytes to the key cookie.  Since we're dealing with
		   sensitive keying material here, we need to use the external hash
		   API rather than the internal one to make sure the memory
		   containing the key is protected */
		status = cryptCreateContext( &cryptContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
		if( cryptStatusOK( status ) )
			{
			CRYPT_QUERY_INFO cryptQueryInfo;

			cryptEncrypt( cryptContext, buffer, dataLength );
			cryptEncrypt( cryptContext, cryptInfo->userKey, cryptInfo->userKeyLength );
			cryptEncrypt( cryptContext, buffer, 0 );
			cryptQueryContext( cryptContext, &cryptQueryInfo );
			cryptDestroyContext( cryptContext );
			memcpy( cryptInfo->keyCookie, cryptQueryInfo.hashValue, KEY_COOKIE_SIZE );
			zeroise( &cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) );
			}
		}

	/* Clean up */
	sMemClose( &stream );
	free( buffer );
	return( status );
	}

/* Wrap an ASN.1 data type up inside an explicitly tagged type (this
   converts, for example, a SEQUENCE into an [APPLICATION 0] SEQUENCE).
   The extraLength parameter is provided for incomplete types where further
   data will be added by the caller later on.

   This function is somewhat nasty in that it uses direct access to the
   streams buffer to save complex byte-by-byte copying, which means we have to
   be careful about what sort of stream we're working with */

static void wrapExplicitTag( STREAM *stream, int tag, long extraLength )
	{
	STREAM tagStream;
	BYTE tagBuffer[ 10 ];
	int length = sMemSize( stream ), tagLength;

	/* Write the explicit tag to a temporary stream */
	sMemOpen( &tagStream, tagBuffer, 10 );
	writeTag( &tagStream, tag );
	writeLength( &tagStream, length + extraLength );
	tagLength = sMemSize( &tagStream );

	/* Make sure there's enough room to add the new tag to the output */
	if( stream->isNull )
		stream->bufPos = tagLength + length;
	else
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			tagLength + length > stream->bufSize )
			stream->status = STREAM_FULL;
		else
			{
			/* Make room for the new tag and prepend it to the data */
			memmove( stream->buffer + tagLength, stream->buffer, length );
			memcpy( stream->buffer, tagStream.buffer, tagLength );
			stream->bufPos = stream->bufEnd = tagLength + length;
			}
	sMemClose( &tagStream );
	}

/****************************************************************************
*																			*
*							Message Digest Routines							*
*																			*
****************************************************************************/

/* Write/read the message digest algorithm and optional parameters */

static int sizeofMessageDigestParams( const CRYPT_ALGO algorithm,
									  const int parameter,
									  const int extraLength )
	{
	int size;

	/* Evaluate the size of the enumerated value needed to encode the MD
	   algorithm type and any optional algorithm-specific information */
	size = sizeofEnumerated( algorithm );
	if( algorithm == CRYPT_ALGO_SHA && parameter )
		/* The parameter is written as a SEQUENCE with a single BOOLEAN
		   field */
		size += 2 + sizeofBoolean();
	return( size + extraLength );
	}

static void writeMessageDigestParams( STREAM *stream, const CRYPT_ALGO algorithm,
									  const int parameter, const int extraLength,
									  const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, sizeofMessageDigestParams( algorithm, parameter,
													extraLength ) );

	/* It's a composite type.  First write the enumeration which encodes the
	   MD type */
	writeEnumerated( stream, algorithm, DEFAULT_TAG );

	/* Now write any algorithm-specific fields */
	if( parameter )
		{
		writeCtag( stream, CTAG_MD_ALGOINFO, TRUE );
		switch( algorithm )
			{
			case CRYPT_ALGO_SHA:
				writeLength( stream, sizeofBoolean() );
				writeBoolean( stream, ( BOOLEAN ) parameter, DEFAULT_TAG );
				break;
			}
		}
	}

static int readMessageDigestParams( STREAM *stream, CRYPT_ALGO *algorithm,
									int *parameter, const BOOLEAN readIdent )
	{
	int readDataLength = 0, tagLength;
	long dummy;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_BADDATA );
			}
		readDataLength++;
		}

	/* Read the algorithm type */
	readDataLength += readLength( stream, &dummy );	/* Skip SEQUENCE length info */
	readDataLength += readEnumerated( stream, ( int * ) algorithm );
	*parameter = 0;		/* Most algorithms have no parameters */

	/* Read the algorithm-specific parameters if necessary */
	tagLength = checkReadCtag( stream, CTAG_MD_ALGOINFO, TRUE );
	if( tagLength )
		{
		long length;

		readLength( stream, &length );
		readDataLength += ( int ) length + tagLength;
		switch( *algorithm )
			{
			case CRYPT_ALGO_SHA:
				readBoolean( stream, ( BOOLEAN * ) parameter );
				break;

			default:
				return( CRYPT_NOALGO );
			}
		}

	return( readDataLength );
	}

/* Initialise a message digest to a given value, and destroy it afterwards */

int newMessageDigest( MESSAGE_DIGEST *messageDigest, const CRYPT_ALGO mdAlgo,
					  const BYTE *md, const int length )
	{
	/* Set up MD information */
	memset( messageDigest, 0, sizeof( MESSAGE_DIGEST ) );
	messageDigest->type = mdAlgo;
	messageDigest->length = length;
	if( length )
		memcpy( messageDigest->data, md, length );

	return( CRYPT_OK );
	}

int deleteMessageDigest( MESSAGE_DIGEST *messageDigest )
	{
	/* Zero the message digest fields */
	return( newMessageDigest( messageDigest, CRYPT_ALGO_NONE, NULL, 0 ) );
	}

/* Determine the encoded size of a message digest value */

int sizeofMessageDigest( const MESSAGE_DIGEST *messageDigest )
	{
	int size;

	/* It's a composite type.  Evaluate the size of the algorithm parameters
	   and the octet string needed to encode the MD itself */
	size = sizeofMessageDigestParams( messageDigest->type,
		   messageDigest->isSHA, ( int ) sizeofObject( messageDigest->length ) );
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Write a message digest value */

int writeMessageDigest( STREAM *stream, const MESSAGE_DIGEST *messageDigest,
						const int tag )
	{
	/* Write the header and algorithm information fields */
	writeMessageDigestParams( stream, messageDigest->type,
			messageDigest->isSHA, ( int ) sizeofObject( messageDigest->length ),
			tag );

	/* Finally write the data as an octet string */
	writeByteString( stream, messageDigest->data, messageDigest->length,
					 DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a message digest value */

int _readMessageDigest( STREAM *stream, MESSAGE_DIGEST *messageDigest,
						const BOOLEAN readIdent )
	{
	int readDataLength = 0;

	/* Read the message digest algorithm information and optional parameters */
	readDataLength = readMessageDigestParams( stream, &messageDigest->type,
											  ( int * ) &messageDigest->isSHA,
											  readIdent );
	if( cryptStatusError( readDataLength ) )
		return( readDataLength );

	/* Finally, read the digest itself */
	readDataLength += readStaticOctetString( stream, messageDigest->data,
											 &messageDigest->length,
											 CRYPT_MAX_HASHSIZE );

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/****************************************************************************
*																			*
*							Key Information Routines						*
*																			*
****************************************************************************/

/* Determine the encoded size of a key information record */

int sizeofKeyInfo( const CRYPT_INFO *cryptInfo, const BOOLEAN addPadding )
	{
	int size;

	/* It's a composite type.  Evaluate the size of the enumerated value
	   needed to encode the algorithm type and mode, the size of the
	   encoded extra information, and the octet string needed to encode the
	   key */
	size = sizeofEnumerated( cryptInfo->capabilityInfo->cryptAlgo );
	size += sizeofEnumerated( cryptInfo->capabilityInfo->cryptMode );
	if( !cryptInfo->privateUseDefaults )
		size += sizeofAlgorithmParams( cryptInfo );
	size += ( int ) sizeofObject( cryptInfo->userKeyLength );

	/* Determine the total encoded size.  If we're padding the length, we
	   just return the nearest KEYINFO_PADSIZE-byte value above this,
	   otherwise we return the real size */
	size = sizeof( BYTE ) + calculateLengthSize( size ) + size;
	if( addPadding && ( size & ( KEYINFO_PADSIZE - 1 ) ) )
		/* We only need to pad if it's not a multiple of KEYINFO_PADSIZE
		   bytes long.  The three bytes added to the calculation are for the
		   minimum-length octet string possible for the padding */
		return( ( size + 3 + ( KEYINFO_PADSIZE - 1 ) ) & ~( KEYINFO_PADSIZE - 1 ) );
	return( size );
	}

/* Write the key information.  Since this is only ever written to a memory
   stream prior to being encrypted with a public key, there's no need to
   specify the tag type.  The first function writes only the header
   information (but not the key itself) for use in various locations which
   need to process encryption key information formatted in a standardised
   manner) */

int writeKeyInfoHeader( STREAM *stream, const CRYPT_INFO *cryptInfo,
						int keyLength )
	{
	CAPABILITY_INFO *capabilityInfo = cryptInfo->capabilityInfo;
	int algorithmInfoSize = 0;

	/* Determine the size of the algorithm-specific components and check we
	   can handle this algorithm */
	if( !cryptInfo->privateUseDefaults && \
		( algorithmInfoSize = sizeofAlgorithmParams( cryptInfo ) ) < 0 )
		return( CRYPT_ERROR );	/* Internal error, should never happen */

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofEnumerated( capabilityInfo->cryptAlgo ) +
				 sizeofEnumerated( capabilityInfo->cryptMode ) +
				 algorithmInfoSize + ( int ) sizeofObject( keyLength ) );

	/* Write the algorithm parameters */
	writeAlgorithmParams( stream, capabilityInfo, cryptInfo );

	/* Write the start of the octetString which contains the key */
	writeTag( stream, BER_OCTETSTRING );
	writeLength( stream, keyLength );

	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

int writeKeyInfo( STREAM *stream, const CRYPT_INFO *cryptInfo,
				  int *keyOffset, const BOOLEAN addPadding )
	{
	BYTE dummy[ CRYPT_MAX_KEYSIZE ];

	/* Write the start of the KeyInformation record */
	writeKeyInfoHeader( stream, cryptInfo, cryptInfo->userKeyLength );
	*keyOffset = sMemSize( stream );

	/* Insert the dummy key */
	swrite( stream, dummy, cryptInfo->userKeyLength );

	/* If we want to pad the output and it's not a multiple of
	   KEYINFO_PADSIZE bytes long, write an octet string to make it the
	   right length */
	if( addPadding && ( sMemSize( stream ) & ( KEYINFO_PADSIZE - 1 ) ) )
		{
		BYTE padding[ KEYINFO_PADSIZE ];
		int padSize;

		/* Find out how long the padding data needs to be (the three-byte
		   value is the minimum-size octet string, the two-byte value is the
		   size of the octet string header) */
		padSize = ( sMemSize( stream ) + 3 + ( KEYINFO_PADSIZE - 1 ) ) & \
				  ~( KEYINFO_PADSIZE - 1 );
		padSize -= sMemSize( stream ) + 2;

		/* Write the octet string with the padding.  It doesn't have to
		   be cryptographically strong, or even random for that matter,
		   although writing a constant string is inadvisable */
		getNonce( padding, padSize );	/* Insert subliminal channel here */
		writeByteString( stream, padding, padSize, DEFAULT_TAG );
		}

	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read the key information.  Since this is only ever read from a memory
   stream prior to being loaded into an encryption context, there's no need
   to specify whether we'll read the tag type */

int readKeyInfo( STREAM *stream, CRYPT_CONTEXT *cryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int readDataLength, status;
	long length;

	/* Read the identifier and length fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &length ) + 1;

	/* Read the encryption algorithm information and create an encryption
	   context from it */
	if( cryptStatusError( length = readAlgorithmParams( stream, cryptContext, NULL ) ) )
		return( ( int ) length );
	readDataLength += ( int ) length;

	/* Finally, read the encryption key and load it into the encryption
	   context.  Like the equivalent code in writeEncryptedDataInfo(), we
	   never actually read the data into an octet string but load it
	   directly into the encryption context, so we need to duplicate most of
	   readOctetString() here */
	if( readTag( stream ) != BER_OCTETSTRING )
		{
		cryptDestroyContext( *cryptContext );
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &length ) + 1;
	cryptInfoPtr = CONTEXT_TO_INFO( *cryptContext );
	cryptInfoPtr->clearBuffer = TRUE;
	status = cryptLoadContext( *cryptContext, stream->buffer + stream->bufPos,
							   ( int ) length );
	cryptInfoPtr->clearBuffer = FALSE;
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		return( status );
		}

	/* There could be padding after the key, but we don't need to do anything
	   with it so we can exit now */
	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength + ( int ) length );
	}

/****************************************************************************
*																			*
*						Conventionally-Encrypted Key Routines				*
*																			*
****************************************************************************/

/* Write a conventionally encrypted key */

int writeEncryptedKey( STREAM *stream, const CRYPT_INFO *cryptInfo,
					   const CRYPT_INFO *sessionKeyInfo, const BYTE *buffer,
					   const int length )
	{
	CAPABILITY_INFO *capabilityInfo = cryptInfo->capabilityInfo;
	BYTE *keyCookie = NULL;
	int algorithmInfoSize = 0, controlVectorSize = 0, ivSize = 0;
	int derivationInfoSize = 0, cookieSize = 0;

	/* Determine the size of the algorithm information components and check
	   we can handle this algorithm */
	if( !cryptInfo->privateUseDefaults && \
		( algorithmInfoSize = sizeofAlgorithmParams( cryptInfo ) ) < 0 )
		return( CRYPT_ERROR );	/* Internal error, should never happen */

	/* Determine the size of any optional parameters */
	if( sessionKeyInfo->controlVector )
		controlVectorSize = sizeofBitString( sessionKeyInfo->controlVector );
	if( capabilityInfo->cryptMode != CRYPT_MODE_ECB )
		ivSize = ( int ) sizeofObject( CRYPT_MAX_IVSIZE );
	if( sessionKeyInfo->exportKeyCookie == TRUE || \
		( sessionKeyInfo->exportKeyCookie == CRYPT_USE_DEFAULT && \
		  getOptionExportKeyCookie() ) )
		{
		cookieSize = ( int ) sizeofObject( KEY_COOKIE_SIZE );
		keyCookie = ( BYTE * ) sessionKeyInfo->keyCookie;
		}
	if( cryptInfo->keySetupAlgorithm != DEFAULT_KEYSETUP_ALGO || \
		cryptInfo->keySetupIterations != DEFAULT_KEYSETUP_ITERATIONS )
		{
		/* The constant 2 is the size of the tag and length fields */
		derivationInfoSize = 2 + sizeofEnumerated( sessionKeyInfo->keySetupAlgorithm ) + \
							 sizeofShortInteger( sessionKeyInfo->keySetupIterations );
		}

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofEnumerated( capabilityInfo->cryptAlgo ) +
				 sizeofEnumerated( capabilityInfo->cryptMode ) +
				 algorithmInfoSize + derivationInfoSize + cookieSize +
				 controlVectorSize + ivSize + ( int ) sizeofObject( length ) );

	/* Write the algorithm, mode, and algorithm parameters */
	writeAlgorithmParams( stream, capabilityInfo, cryptInfo );

	/* Write the key derivation info if necessary */
	if( derivationInfoSize )
		{
		writeCtag( stream, CTAG_CK_DERIVATIONINFO, TRUE );
		writeLength( stream, derivationInfoSize - 2 );
		writeEnumerated( stream, cryptInfo->keySetupAlgorithm,
						 DEFAULT_TAG );
		writeShortInteger( stream, cryptInfo->keySetupIterations,
						   DEFAULT_TAG );
		}

	/* Write the key cookie and control vector */
	writeKeyParams( stream, keyCookie, CTAG_CK_KEYCOOKIE,
					sessionKeyInfo->controlVector, CTAG_CK_CONTROLVECTOR );

	/* Write the encryted key.  cryptLoadIV() pads the IV with zeroes if need
	   be so we don't need to worry about the IV not being CRYPT_MAX_IVSIZE
	   in length */
	if( capabilityInfo->cryptMode != CRYPT_MODE_ECB )
		writeByteString( stream, cryptInfo->iv, CRYPT_MAX_IVSIZE, CTAG_CK_IV );
	writeByteString( stream, buffer, length, DEFAULT_TAG );

	/* Clean up */
	wrapExplicitTag( stream, BER_ENCRYPTED_KEY, 0 );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read a conventionally encrypted key */

int readEncryptedKey( STREAM *stream, const CRYPT_INFO *cryptInfo,
					  CRYPT_OBJECT_INFO *cryptObjectInfo, int *keyInfoLength )
	{
	CRYPT_OBJECT_TYPE objectType;
	int readDataLength, tagLength, status;
	long length;

	/* Read the general information at the start of the encrypted key record */
	if( ( readDataLength = readObjectWrapper( stream, &objectType, &length ) ) < 0 )
		return( readDataLength );
	if( objectType != CRYPT_OBJECT_ENCRYPTED_KEY )
		return( CRYPT_BADDATA );

	/* Read the encryption algorithm information and make sure the key
	   we'll be using to import it matches the requirements.  Checking the
	   algorithm-specific parameters for the encryption context is a bit too
	   complex since they're processed internally by the library routines
	   when the context is created and may not be present in an easily-
	   accessible form.  If the caller has used cryptQueryObject() to get the
	   parameters to create the context then they'll be set up correctly
	   anyway, and the key decrypt will catch any errors if they're not */
	status = readCKObject( stream, cryptObjectInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptInfo->capabilityInfo->cryptAlgo != cryptObjectInfo->cryptAlgo || \
		cryptInfo->capabilityInfo->cryptMode != cryptObjectInfo->cryptMode )
		return( CRYPT_BADPARM );
	readDataLength += status;

	/* Read the IV if necessary.  Strictly speaking we don't need to look for
	   the context-specific tag for the IV since we can tell whether it'll be
	   present based on the encryption mode */
	tagLength = checkReadCtag( stream, CTAG_CK_IV, FALSE );
	if( tagLength )
		readDataLength += readStaticOctetStringData( stream,
							cryptObjectInfo->iv, &cryptObjectInfo->ivSize,
							CRYPT_MAX_IVSIZE ) + tagLength;

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the decrypt function */
	if( readTag( stream ) != BER_OCTETSTRING )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &length ) + 1;
	*keyInfoLength = ( int ) length;

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength + *keyInfoLength );
	}

/****************************************************************************
*																			*
*							PKC-Encrypted Key Routines						*
*																			*
****************************************************************************/

/* Write a PKC-encrypted key.  This gets a bit complicated because there are
   two different types of records, a Diffie-Hellman one where the
   conventional-encryption parameters are stored as part of the key record,
   and a general PKC one where the conventional-encryption parameters are
   wrapped up alongside the encrypted key */

int writePKCEncryptedKey( STREAM *stream, const CRYPT_INFO *pkcInfo,
						  const CRYPT_INFO *sessionKeyInfo,
						  const BYTE *buffer, const int length )
	{
	CAPABILITY_INFO *capabilityInfo = sessionKeyInfo->capabilityInfo;
	CRYPT_ALGO pkcAlgo = pkcInfo->capabilityInfo->cryptAlgo;
	INTEGER encryptedKey;
	BYTE *keyCookie = NULL;
	int controlVectorSize = 0, cookieSize = 0;

	/* Set up an integer which corresponds to the buffer contents (these are
	   always big-endian so there's no need to perform an conversion) */
	newInteger( &encryptedKey, 0 );
	encryptedKey.longInteger = ( BYTE * ) buffer;
	encryptedKey.precision = length;

	/* Determine the size of any optional parameters */
	if( sessionKeyInfo->controlVector )
		controlVectorSize = sizeofBitString( sessionKeyInfo->controlVector );
	if( pkcAlgo != CRYPT_ALGO_DH && \
		( sessionKeyInfo->exportKeyCookie == TRUE || \
		  ( sessionKeyInfo->exportKeyCookie == CRYPT_USE_DEFAULT && \
			getOptionExportKeyCookie() ) ) )
		{
		cookieSize = ( int ) sizeofObject( KEY_COOKIE_SIZE );
		keyCookie = ( BYTE * ) sessionKeyInfo->keyCookie;
		}

	/* Write the appropriate record depending on whether it's a DH or generic
	   PKC */
	writeTag( stream, BER_SEQUENCE );
	if( pkcAlgo == CRYPT_ALGO_DH )
		{
		int algorithmInfoSize = 0;

		/* Determine the size of the algorithm information components and
		   check we can handle this algorithm */
		if( !sessionKeyInfo->privateUseDefaults && \
			( algorithmInfoSize = sizeofAlgorithmParams( sessionKeyInfo ) ) < 0 )
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		algorithmInfoSize += sizeofEnumerated( capabilityInfo->cryptAlgo ) +
							 sizeofEnumerated( capabilityInfo->cryptMode );

		/* Write the length field, PKC algorithm type, conventional algorithm
		   parameters, and a dummy cookie */
		writeLength( stream,  +
					 sizeofEnumerated( pkcAlgo ) + algorithmInfoSize +
					 controlVectorSize + sizeofInteger( &encryptedKey ) );
		writeRawObject( stream, pkcInfo->keyID, pkcInfo->keyIDlength );
		writeEnumerated( stream, pkcAlgo, DEFAULT_TAG );
		writeCtag( stream, CTAG_PK_ALGOINFO, TRUE );
		writeLength( stream, algorithmInfoSize );
		writeAlgorithmParams( stream, capabilityInfo, sessionKeyInfo );
		}
	else
		{
		/* Write the length field, PKC algorithm type, and key cookie */
		writeLength( stream, pkcInfo->keyIDlength +
					 sizeofEnumerated( pkcAlgo ) + cookieSize +
					 controlVectorSize + sizeofInteger( &encryptedKey ) );
		writeRawObject( stream, pkcInfo->keyID, pkcInfo->keyIDlength );
		writeEnumerated( stream, pkcAlgo, DEFAULT_TAG );
		}
	writeKeyParams( stream, keyCookie, CTAG_PK_KEYCOOKIE,
					sessionKeyInfo->controlVector, CTAG_PK_CONTROLVECTOR );

	/* Write the encryted key */
	writeInteger( stream, &encryptedKey, DEFAULT_TAG );

	/* Clean up */
	encryptedKey.longInteger = NULL;
	deleteInteger( &encryptedKey );

	wrapExplicitTag( stream, BER_PKCENCRYPTED_KEY, 0 );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read a PKC-encrypted key */

int readPKCEncryptedKey( STREAM *stream, CRYPT_INFO *pkcInfo,
						 CRYPT_CONTEXT *sessionKeyContext,
						 CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	CAPABILITY_INFO *capabilityInfo = pkcInfo->capabilityInfo;
	CRYPT_OBJECT_TYPE objectType;
	CRYPT_ALGO cryptAlgo;
	int readDataLength;
	long length;

	/* Read the general information at the start of the encrypted key record */
	if( ( readDataLength = readObjectWrapper( stream, &objectType, &length ) ) < 0 )
		return( readDataLength );
	if( objectType != CRYPT_OBJECT_PKCENCRYPTED_KEY )
		return( CRYPT_BADDATA );
	if( ( readDataLength = readPKObject( stream, pkcInfo->keyID,
								&pkcInfo->keyIDlength, &cryptAlgo ) ) < 0 )
		return( readDataLength );
	if( cryptAlgo != capabilityInfo->cryptAlgo )
		return( CRYPT_NOTAVAIL );

	/* Read the encrypted key-specific parameters if necessary */
	readDataLength += readPKKeyObject( stream, cryptAlgo, sessionKeyContext,
									   cryptObjectInfo );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the PKC decrypt function */
	if( readTag( stream ) != BER_INTEGER )
		{
		if( cryptAlgo == CRYPT_ALGO_DH )
			cryptDestroyContext( *sessionKeyContext );
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &length ) + 1;

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength + ( int ) length );
	}

/****************************************************************************
*																			*
*								Signature Routines							*
*																			*
****************************************************************************/

/* Write/read the message digest information record which is contained inside
   the signature */

int sizeofMessageDigestInfo( const MESSAGE_DIGEST *messageDigest )
	{
	int size = ( int ) sizeofObject( 8 ) + sizeofMessageDigest( messageDigest );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

int writeMessageDigestInfo( STREAM *stream, const MESSAGE_DIGEST *messageDigest )
	{
	BYTE nonce[ 8 ];

	/* Create the nonce
	getNonce( nonce, 8 );

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, ( int ) sizeofObject( 8 ) +
				 sizeofMessageDigest( messageDigest ) );

	/* Write the nonce and message digest */
	writeByteString( stream, nonce, 8, DEFAULT_TAG );
	writeMessageDigest( stream, messageDigest, DEFAULT_TAG );

	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

int readMessageDigestInfo( STREAM *stream, MESSAGE_DIGEST *messageDigest )
	{
	BYTE nonce[ 8 ];
	int readDataLength, dummyInt;
	long dummy;

	/* Read the identifier and length fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &dummy ) + 1;

	/* Read the nonce and message digest */
	readDataLength += readStaticOctetString( stream, nonce, &dummyInt, 8 );
	readDataLength += readMessageDigest( stream, messageDigest );

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Write the signature */

int writeSignature( STREAM *stream, const CRYPT_INFO *pkcInfo,
					const BYTE *buffer, const int length )
	{
	CRYPT_ALGO pkcAlgo = pkcInfo->capabilityInfo->cryptAlgo;

	/* Write the identifier and length fields.  We evaluate the size of the
	   signature itself as the size of the BIT STRING needed to encapsulate
	   it */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, pkcInfo->keyIDlength + sizeofEnumerated( pkcAlgo ) +
				 sizeofObject( length + 1 ) );

	/* Write the key ID and PKC algorithm type */
	writeRawObject( stream, pkcInfo->keyID, pkcInfo->keyIDlength );
	writeEnumerated( stream, pkcAlgo, DEFAULT_TAG );

	/* Write the signature encapsulated in a BIT STRING.  The signature is
	   always big-endian so there's no need to perform a conversion */
	writeTag( stream, BER_BITSTRING );
	writeLength( stream, length + 1 );
	sputc( stream, 0 );		/* Write bit remainder octet */
	writeRawObject( stream, buffer, length );

	wrapExplicitTag( stream, BER_SIGNATURE, 0 );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read a signature */

int readSignature( STREAM *stream, CRYPT_INFO *pkcInfo )
	{
	CAPABILITY_INFO *capabilityInfo = pkcInfo->capabilityInfo;
	CRYPT_OBJECT_TYPE objectType;
	CRYPT_ALGO cryptAlgo;
	int readDataLength, tagLength;
	long length;

	/* Read the general information at the start of the signature record */
	if( ( readDataLength = readObjectWrapper( stream, &objectType, &length ) ) < 0 )
		return( readDataLength );
	if( objectType != CRYPT_OBJECT_SIGNATURE )
		return( CRYPT_BADPARM );
	if( ( readDataLength = readPKObject( stream, pkcInfo->keyID,
								&pkcInfo->keyIDlength, &cryptAlgo ) ) < 0 )
		return( readDataLength );
	if( cryptAlgo != capabilityInfo->cryptAlgo )
		return( CRYPT_NOTAVAIL );

	/* Read the algorithm-specific parameters if necessary */
	tagLength = checkReadCtag( stream, CTAG_SG_ALGOINFO, TRUE );
	if( tagLength )
		{
		readLength( stream, &length );
		readDataLength += ( int ) length + tagLength;
		switch( cryptAlgo )
			{
			default:
				return( CRYPT_NOALGO );
			}
		}

	/* Read the signature cookie if necessary */
	tagLength = checkReadCtag( stream, CTAG_SG_SIGNATURECOOKIE, TRUE );
	if( tagLength )
		/* We can't handle signature cookies yet, just skip it for now */
		readDataLength += readUniversalData( stream ) + tagLength;

	/* Finally, read the start of the signature itself.  We never read the
	   data since it's passed directly to the PKC function */
	if( readTag( stream ) != BER_BITSTRING )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &length ) + 2;
	sgetc( stream );		/* Read bit remainder octet */

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength + ( int ) length );
	}

/****************************************************************************
*																			*
*								Data Object Routines						*
*																			*
****************************************************************************/

/* Write the start of a RawData or NonData object */

int writeBasicObject( STREAM *stream, const BOOLEAN isContinued,
					  const long dataLength, const BOOLEAN isDataObject )
	{
	int continuationLength = ( isContinued ) ? sizeofBoolean() : 0;

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, continuationLength + sizeofObject( dataLength ) );

	/* Write the continuation flag if necessary */
	if( isContinued )
		writeBoolean( stream, TRUE, DEFAULT_TAG );

	/* Write the start of the OCTET STRING field */
	writeTag( stream, BER_OCTETSTRING );
	writeLength( stream, dataLength );

	wrapExplicitTag( stream, isDataObject ? BER_RAW_DATA : BER_NONDATA,
					 dataLength );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read the start of a RawData or NonData object */

int readBasicObject( STREAM *stream, BOOLEAN *isContinued, long *dataLength )
	{
	int readDataLength = 0;

	/* Read the continuation flag if necessary */
	if( checkReadTag( stream, BER_BOOLEAN ) )
		readDataLength += readBooleanData( stream, isContinued ) + 1;
	else
		*isContinued = FALSE;

	/* Read the start of the OCTET STRING field */
	if( readTag( stream ) != BER_OCTETSTRING )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, dataLength ) + 1;

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Write the start of an EncryptedData object */

int writeEncryptedObject( STREAM *stream, const BOOLEAN isContinued,
						  const long dataLength,
						  const CRYPT_INFO *cryptInfoPtr )
	{
	int continuationLength = ( isContinued ) ? sizeofBoolean() : 0;
	int cookieSize = ( cryptInfoPtr->exportKeyCookie == TRUE || \
					   ( cryptInfoPtr->exportKeyCookie == CRYPT_USE_DEFAULT && \
						 getOptionExportKeyCookie() ) ) ? \
					 ( int ) sizeofObject( KEY_COOKIE_SIZE ) : 0;

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, continuationLength + cookieSize +
				 sizeofObject( CRYPT_MAX_IVSIZE ) +
				 sizeofObject( dataLength ) );

	/* Write the continuation flag if necessary */
	if( isContinued )
		writeBoolean( stream, TRUE, DEFAULT_TAG );

	/* Write the key cookie and IV.  cryptLoadIV() pads the IV with zeroes if
	   need be so we don't need to worry about the IV not being
	   CRYPT_MAX_IVSIZE in length */
	if( cookieSize )
		writeByteString( stream, cryptInfoPtr->keyCookie, KEY_COOKIE_SIZE,
						 CTAG_ED_KEYCOOKIE );
	writeByteString( stream, cryptInfoPtr->iv, CRYPT_MAX_IVSIZE, DEFAULT_TAG );

	/* Write the start of the OCTET STRING field for the encrypted data */
	writeTag( stream, BER_OCTETSTRING );
	writeLength( stream, dataLength );

	wrapExplicitTag( stream, BER_ENCRYPTED_DATA, dataLength );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read the start of an EncryptedData object */

int readEncryptedObject( STREAM *stream, BOOLEAN *isContinued,
						 long *dataLength,
						 CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int readDataLength = 0, tagLength;

	/* Read the continuation flag if necessary */
	if( checkReadTag( stream, BER_BOOLEAN ) )
		readDataLength += readBooleanData( stream, isContinued ) + 1;
	else
		*isContinued = FALSE;

	/* Read the key cookie if necessary */
	tagLength = checkReadCtag( stream, CTAG_ED_KEYCOOKIE, FALSE );
	if( tagLength )
		readDataLength += readCookie( stream, cryptObjectInfo->cookie,
					&cryptObjectInfo->cookieSize, KEY_COOKIE_SIZE ) + tagLength;

	/* Read the IV */
	readDataLength += readStaticOctetString( stream, cryptObjectInfo->iv,
								&cryptObjectInfo->ivSize, CRYPT_MAX_IVSIZE );
	if( cryptObjectInfo->ivSize != CRYPT_MAX_IVSIZE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}

	/* Read the start of the OCTET STRING field */
	if( readTag( stream ) != BER_OCTETSTRING )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, dataLength ) + 1;

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}

/* Write the start of a SignedData object */

int writeSignedObject( STREAM *stream, const BOOLEAN isContinued,
					   const CRYPT_INFO *cryptInfoPtr, const long dataLength )
	{
	int continuationLength = ( isContinued ) ? sizeofBoolean() : 0;
	int cookieSize = ( cryptInfoPtr->exportSigCookie == TRUE || \
					   ( cryptInfoPtr->exportSigCookie == CRYPT_USE_DEFAULT && \
						 getOptionExportSigCookie() ) ) ? \
					 ( int ) sizeofObject( SIGNATURE_COOKIE_SIZE ) : 0;
	int mdInfoSize = 0, noHashes;

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, continuationLength + cookieSize +
				 sizeofObject( dataLength ) );

	/* Write the continuation flag if necessary */
	if( isContinued )
		writeBoolean( stream, TRUE, DEFAULT_TAG );

	/* Write the signature cookie and hash algorithm information */
	if( cookieSize )
		writeByteString( stream, cryptInfoPtr->sigCookie,
						 SIGNATURE_COOKIE_SIZE, CTAG_SD_SIGNATURECOOKIE );

	/* Evaluate the size of the SET OF MessageDigestParams */
	for( noHashes = 0; noHashes < 1; noHashes++ )
		{
		CRYPT_ALGO algorithm = cryptInfoPtr->capabilityInfo->cryptAlgo;
		int parameter = 0, size;

		/* Get any optional algorithm-specific parameters */
		if( algorithm == CRYPT_ALGO_SHA )
			parameter = getSHAinfo( cryptInfoPtr );

		/* Determine the size of this set of algorithm parameters */
		size = sizeofMessageDigestParams( algorithm, parameter, 0 );
		mdInfoSize += sizeof( BYTE ) + calculateLengthSize( size ) + size;
		}

	/* Now that we know the total size of the collection of algorithm
	   parameters, write the SET OF header */
	writeTag( stream, BER_SET );
	writeLength( stream, mdInfoSize );

	/* Finally, write the collection of algorithm parameters */
	for( noHashes = 0; noHashes < 1; noHashes++ )
		{
		CRYPT_ALGO algorithm = cryptInfoPtr->capabilityInfo->cryptAlgo;
		int parameter = 0;

		/* Get any optional algorithm-specific parameters */
		if( algorithm == CRYPT_ALGO_SHA )
			parameter = getSHAinfo( cryptInfoPtr );

		/* Determine the size of this set of algorithm parameters */
		writeMessageDigestParams( stream, algorithm, parameter, 0, DEFAULT_TAG );
		}

	wrapExplicitTag( stream, BER_SIGNED_DATA, dataLength );
	return( ( sGetStatus( stream ) != STREAM_OK ) ? CRYPT_ERROR : CRYPT_OK );
	}

/* Read the start of a SignedData object */

int readSignedObject( STREAM *stream, BOOLEAN *isContinued,
					  CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int readDataLength = 0, tagLength;
	long dataLength;

	/* Read the continuation flag if necessary */
	if( checkReadTag( stream, BER_BOOLEAN ) )
		readDataLength += readBooleanData( stream, isContinued ) + 1;
	else
		*isContinued = FALSE;

	/* Read the signature cookie if necessary */
	tagLength = checkReadCtag( stream, CTAG_SD_SIGNATURECOOKIE, FALSE );
	if( tagLength )
		readDataLength += readCookie( stream, cryptObjectInfo->cookie,
									  &cryptObjectInfo->cookieSize,
									  SIGNATURE_COOKIE_SIZE ) + tagLength;

	/* Finally, read the collection of algorithm parameters */
	if( readTag( stream ) != BER_SET )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &dataLength ) + 1;
	readDataLength += ( int ) dataLength;
	while( dataLength > 0 )
		{
		int parameter, parameterLength;

		/* Read the message digest algorithm information and optional
		   parameters */
		parameterLength = readMessageDigestParams( stream,
							&cryptObjectInfo->cryptAlgo, &parameter, TRUE );
		dataLength -= parameterLength;
		if( parameterLength <= 0 )
			return( parameterLength );	/* Error in reading data */

		/* Handle any extended parameters area if necessary (we can reuse the
		   IV memory because it's only used for conventional algorithms).
		   Since the only algorithm with parameters is SHA and this is
		   checked for by readMessageDigestParams(), we can safely assume SHA
		   here */
		if( parameter )
			{
			cryptObjectInfo->cryptContextExInfo = cryptObjectInfo->iv;
			( ( CRYPT_INFO_SHA * ) cryptObjectInfo->cryptContextExInfo )->isSHA = parameter;
			}
		else
			cryptObjectInfo->cryptContextExInfo = ( void * ) CRYPT_UNUSED;

		/* In theory we would just keep going until we'd read the entire SET
		   OF values, but currently we can only handle sets of size one */
		while( dataLength > 0 )
			if( sgetc( stream ) < 0 )
				break;
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( CRYPT_BADDATA );
	return( readDataLength );
	}
