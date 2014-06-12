/****************************************************************************
*																			*
*						  ASN.1 Key Management Routines						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* The restart marker used to identify the start of a key record */

#define RESTART_MARKER		( BYTE * ) "\x0D\x0A\xA0\x00"
#define RESTART_MARKER_SIZE	4

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Context-specific tags for the public-key information record */

enum { CTAG_PK_VALIDFROM, CTAG_PK_VALIDTO };

/* Context-specific tags for the key collection header record */

enum { CTAG_KH_DESCRIPTION };

/* ASN.1's encoding rules always use the big-endian format, so we may need to
   reverse the endianness before we read/write them */

static void byteReverse( BYTE *data, int count )
	{
	int sourceCount = 0;

	/* Swap endianness of data */
	for( count--; count > sourceCount; count--, sourceCount++ )
		{
		BYTE temp;

		temp = data[ sourceCount ];
		data[ sourceCount ] = data[ count ];
		data[ count ] = temp;
		}
	}

/* Read/write a bignum with endianness conversion */

static int writeConvertStaticInteger( STREAM *stream, const BYTE *integer,
									  const int integerLength,
									  const int endianness )
	{
	/* If it's little-endian, make it big-endian before writing it */
	if( endianness == CRYPT_COMPONENTS_LITTLENDIAN )
		{
		BYTE buffer[ CRYPT_MAX_PKCSIZE ];
		int status;

		/* Endianess-reverse the integer and map the reversed data into a
		   temporary integer.  This sort of messing around with internal
		   integer values is rather naughty, but saves a mostly useless
		   malloc() */
		memcpy( buffer, integer, integerLength );
		byteReverse( buffer, integerLength );
		status = writeStaticInteger( stream, buffer, integerLength, DEFAULT_TAG );
		zeroise( buffer, CRYPT_MAX_PKCSIZE );

		return( status );
		}

	/* It's big-endian already, output it as is */
	return( writeStaticInteger( stream, integer, integerLength, DEFAULT_TAG ) );
	}

static int readConvertStaticInteger( STREAM *stream, BYTE *integer,
									 int *integerLength, const int endianness )
	{
	int status;

	/* Read the value into a fixed buffer */
	status = readStaticInteger( stream, integer, integerLength, CRYPT_MAX_PKCSIZE );

	/* If it's meant to be little-endian, convert it */
	if( endianness == CRYPT_COMPONENTS_LITTLENDIAN )
		byteReverse( integer, *integerLength );

	return( status );
	}

/* Read the DH public key components */

static int readDHcomponents( STREAM *stream, CRYPT_PKCINFO_DH *dhKey )
	{
	int readDataLength, length;
	long dummy;

	/* Read start of public-key info sequence fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &dummy ) + 1;	/* Skip SEQ len.*/

	/* Read the key components */
	readDataLength += readConvertStaticInteger( stream, dhKey->p, &length, dhKey->endianness );
	dhKey->pLen = bytesToBits( length );
	readDataLength += readConvertStaticInteger( stream, dhKey->g, &length, dhKey->endianness );
	dhKey->gLen = bytesToBits( length );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Write the DH public key components */

static void writeDHcomponents( STREAM *stream,
							   const CRYPT_PKCINFO_DH *dhKey )
	{
	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofObject( bitsToBytes( dhKey->pLen ) ) +
				 sizeofObject( bitsToBytes( dhKey->gLen ) ) );

	/* Write the the PKC fields */
	writeConvertStaticInteger( stream, dhKey->p, bitsToBytes( dhKey->pLen ),
							   dhKey->endianness );
	writeConvertStaticInteger( stream, dhKey->g, bitsToBytes( dhKey->gLen ),
							   dhKey->endianness );
	}

/* Read the RSA public or private key components */

static int readRSAcomponents( STREAM *stream, CRYPT_PKCINFO_RSA *rsaKey,
							  const BOOLEAN isPublicKey )
	{
	int readDataLength, length;
	long dummy;

	/* Read start of public-key info sequence fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &dummy ) + 1;	/* Skip SEQ len.*/

	/* Read the key components */
	if( !isPublicKey )
		/* Ignored, present for PKCS compatibility only */
		readDataLength += readShortInteger( stream, &dummy );
	readDataLength += readConvertStaticInteger( stream, rsaKey->n, &length, rsaKey->endianness );
	rsaKey->nLen = bytesToBits( length );
	readDataLength += readConvertStaticInteger( stream, rsaKey->e, &length, rsaKey->endianness );
	rsaKey->eLen = bytesToBits( length );
	if( !isPublicKey )
		{
		readDataLength += readConvertStaticInteger( stream, rsaKey->d, &length, rsaKey->endianness );
		rsaKey->dLen = bytesToBits( length );
		readDataLength += readConvertStaticInteger( stream, rsaKey->p, &length, rsaKey->endianness );
		rsaKey->pLen = bytesToBits( length );
		readDataLength += readConvertStaticInteger( stream, rsaKey->q, &length, rsaKey->endianness );
		rsaKey->qLen = bytesToBits( length );
		readDataLength += readConvertStaticInteger( stream, rsaKey->e1, &length, rsaKey->endianness );
		rsaKey->e1Len = bytesToBits( length );
		readDataLength += readConvertStaticInteger( stream, rsaKey->e2, &length, rsaKey->endianness );
		rsaKey->e2Len = bytesToBits( length );
		readDataLength += readConvertStaticInteger( stream, rsaKey->u, &length, rsaKey->endianness );
		rsaKey->uLen = bytesToBits( length );
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Write the RSA public or private key components */

static void writeRSAcomponents( STREAM *stream,
								const CRYPT_PKCINFO_RSA *rsaKey )
	{
	BOOLEAN isPublicKey = rsaKey->isPublicKey;
	long size = 0;

	/* Determine the size of the private fields */
	if( !isPublicKey )
		size = sizeofEnumerated( 0 ) +
			   sizeofObject( bitsToBytes( rsaKey->dLen ) ) +
			   sizeofObject( bitsToBytes( rsaKey->pLen ) ) +
			   sizeofObject( bitsToBytes( rsaKey->qLen ) ) +
			   sizeofObject( bitsToBytes( rsaKey->e1Len ) ) +
			   sizeofObject( bitsToBytes( rsaKey->e2Len ) ) +
			   sizeofObject( bitsToBytes( rsaKey->uLen ) );

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofObject( bitsToBytes( rsaKey->nLen ) ) +
				 sizeofObject( bitsToBytes( rsaKey->eLen ) ) + size );

	/* Write the the PKC fields */
	if( !isPublicKey )
		writeEnumerated( stream, 0, DEFAULT_TAG );	/* For PKCS compatibility */
	writeConvertStaticInteger( stream, rsaKey->n, bitsToBytes( rsaKey->nLen ),
							   rsaKey->endianness );
	writeConvertStaticInteger( stream, rsaKey->e, bitsToBytes( rsaKey->eLen ),
							   rsaKey->endianness );
	if( !isPublicKey )
		{
		writeConvertStaticInteger( stream, rsaKey->d, bitsToBytes( rsaKey->dLen ),
								   rsaKey->endianness );
		writeConvertStaticInteger( stream, rsaKey->p, bitsToBytes( rsaKey->pLen ),
								   rsaKey->endianness );
		writeConvertStaticInteger( stream, rsaKey->q, bitsToBytes( rsaKey->qLen ),
								   rsaKey->endianness );
		writeConvertStaticInteger( stream, rsaKey->e1, bitsToBytes( rsaKey->e1Len ),
								   rsaKey->endianness );
		writeConvertStaticInteger( stream, rsaKey->e2, bitsToBytes( rsaKey->e2Len ),
								   rsaKey->endianness );
		writeConvertStaticInteger( stream, rsaKey->u, bitsToBytes( rsaKey->uLen ),
								   rsaKey->endianness );
		}
	}

/* Read the DSA public or private key components */

static int readDSAcomponents( STREAM *stream, CRYPT_PKCINFO_DSA *dsaKey,
							  const BOOLEAN isPublicKey )
	{
	int readDataLength = 0, length;
	long dummy;

	/* Read start of public-key info sequence fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength += readLength( stream, &dummy ) + 1;	/* Skip SEQ len.*/

	/* Read the key components */
	if( !isPublicKey )
		/* Ignored, present for PKCS compatibility only */
		readDataLength += readEnumerated( stream, &length );
	readDataLength += readConvertStaticInteger( stream, dsaKey->p, &length, dsaKey->endianness );
	dsaKey->pLen = bytesToBits( length );
	readDataLength += readConvertStaticInteger( stream, dsaKey->q, &length, dsaKey->endianness );
	dsaKey->qLen = bytesToBits( length );
	readDataLength += readConvertStaticInteger( stream, dsaKey->x, &length, dsaKey->endianness );
	dsaKey->xLen = bytesToBits( length );
	if( !isPublicKey )
		{
		readDataLength += readConvertStaticInteger( stream, dsaKey->y, &length, dsaKey->endianness );
		dsaKey->yLen = bytesToBits( length );
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Write the DSA public or private key components */

static void writeDSAcomponents( STREAM *stream,
								const CRYPT_PKCINFO_DSA *dsaKey )
	{
	BOOLEAN isPublicKey = dsaKey->isPublicKey;
	long size = 0;

	/* Determine the size of the private fields */
	if( !isPublicKey )
		size = sizeofEnumerated( 0 ) +
			   sizeofObject( bitsToBytes( dsaKey->yLen ) ) +

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofObject( bitsToBytes( dsaKey->pLen ) ) +
				 sizeofObject( bitsToBytes( dsaKey->qLen ) ) +
				 sizeofObject( bitsToBytes( dsaKey->xLen ) ) + size );

	/* Write the the PKC fields */
	if( !isPublicKey )
		writeEnumerated( stream, 0, DEFAULT_TAG );	/* For PKCS compatibility */
	writeConvertStaticInteger( stream, dsaKey->p, bitsToBytes( dsaKey->pLen ),
							   dsaKey->endianness );
	writeConvertStaticInteger( stream, dsaKey->q, bitsToBytes( dsaKey->qLen ),
							   dsaKey->endianness );
	writeConvertStaticInteger( stream, dsaKey->x, bitsToBytes( dsaKey->xLen ),
							   dsaKey->endianness );
	if( !isPublicKey )
		writeConvertStaticInteger( stream, dsaKey->y, bitsToBytes( dsaKey->yLen ),
								   dsaKey->endianness );
	}

/* Generate a key ID */

int generateKeyID( CRYPT_ALGO algorithm, BYTE *keyID, int *keyIDlength,
				   void *pkcInfo )
	{
	STREAM stream;
	MESSAGE_DIGEST mdKeyID;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 50 ];
	BYTE hashResult[ CRYPT_MAX_HASHSIZE ];
	int isPublicKey;
	int hashAlgorithm, hashInfoSize, hashInputSize, hashOutputSize;
	HASHFUNCTION hashFunction;

	/* The following define makes the code to access the public-key flag in
	   various structures slightly less ugly */
	#define pubkeyField( pointer, type )	( ( type * ) pointer )->isPublicKey

	/* Get the hash algorithm information */
	hashAlgorithm = CRYPT_ALGO_SHA;		/* Always use SHA for now */
	if( !getHashParameters( hashAlgorithm, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );	/* API error, should never occur */

	/* Write the public key fields to a buffer.  We cheat a bit here in that
	   we know the memory stream is connected to the buffer, so we don't
	   bother reading it out into a temporary buffer.  Since the key we've
	   been passed might be a private or public key, we need to fool the
	   write function into only writing the public fields, so we make it look
	   like a public key while it's being written */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 2 ) + 50 );
	switch( algorithm )
		{
		case CRYPT_ALGO_DH:
			isPublicKey = pubkeyField( pkcInfo, CRYPT_PKCINFO_DH );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_DH ) = TRUE;
			writeDHcomponents( &stream, ( CRYPT_PKCINFO_DH * ) pkcInfo );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_DH ) = isPublicKey;
			break;

		case CRYPT_ALGO_RSA:
			isPublicKey = pubkeyField( pkcInfo, CRYPT_PKCINFO_RSA );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_RSA ) = TRUE;
			writeRSAcomponents( &stream, ( CRYPT_PKCINFO_RSA * ) pkcInfo );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_RSA ) = isPublicKey;
			break;

		case CRYPT_ALGO_DSA:
			isPublicKey = pubkeyField( pkcInfo, CRYPT_PKCINFO_DSA );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_DSA ) = TRUE;
			writeDSAcomponents( &stream, ( CRYPT_PKCINFO_DSA * ) pkcInfo );
			pubkeyField( pkcInfo, CRYPT_PKCINFO_DSA ) = isPublicKey;
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}
	if( sGetStatus( &stream ) != STREAM_OK )
		return( CRYPT_ERROR );		/* Internal error, should never happen */

	/* Hash the DER-encoded public key fields to get the key ID */
	hashFunction( NULL, hashResult, buffer, sMemSize( &stream ), HASH_ALL );
	sMemClose( &stream );

	/* Write the key ID (in encoded format) to the key ID buffer */
	sMemOpen( &stream, keyID, CRYPT_MAX_KEYIDSIZE );
	newMessageDigest( &mdKeyID, hashAlgorithm, hashResult, hashOutputSize );
	writeMessageDigest( &stream, &mdKeyID, DEFAULT_TAG );
	deleteMessageDigest( &mdKeyID );
	*keyIDlength = sMemSize( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						sizeof() methods for ASN.1 Types					*
*																			*
****************************************************************************/

/* Determine the size of an AlgorithmIdentifier record */

static int sizeofAlgorithmIdentifier( const PKC_INFO *pkcInfo )
	{
	int size = sizeof( BYTE ) + sizeof( BYTE ) + sizeofNull();

	/* Add the size of the AlgorithmIdentifier record */
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			return( size + sizeofOID( OID_DHKEYAGREEMENT ) );

		case CRYPT_ALGO_RSA:
			return( size + sizeofOID( OID_RSAENCRYPTION ) );

		case CRYPT_ALGO_DSA:
			return( size + sizeofOID( OID_DSAENCRYPTION ) );
		}

	return( CRYPT_ERROR );	/* Internal error, should never happen */
	}

/* Determine the size of the DH public key components */

static int sizeofDHcomponents( const CRYPT_PKCINFO_DH *dhKey )
	{
	long size;

	size = sizeofObject( bitsToBytes( dhKey->pLen ) ) +
		   sizeofObject( bitsToBytes( dhKey->gLen ) );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + ( int ) size );
	}

/* Determine the size of the RSA public or private key components */

static int sizeofRSAcomponents( const CRYPT_PKCINFO_RSA *rsaKey )
	{
	long size;

	size = sizeofObject( bitsToBytes( rsaKey->nLen ) ) +
		   sizeofObject( bitsToBytes( rsaKey->eLen ) );
	if( !rsaKey->isPublicKey )
		size += sizeofEnumerated( 0 ) +
				sizeofObject( bitsToBytes( rsaKey->dLen ) ) +
				sizeofObject( bitsToBytes( rsaKey->pLen ) ) +
				sizeofObject( bitsToBytes( rsaKey->qLen ) ) +
				sizeofObject( bitsToBytes( rsaKey->e1Len ) ) +
				sizeofObject( bitsToBytes( rsaKey->e2Len ) ) +
				sizeofObject( bitsToBytes( rsaKey->uLen ) );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + ( int ) size );
	}

/* Determine the size of the DSA public or private key components */

static int sizeofDSAcomponents( const CRYPT_PKCINFO_DSA *dsaKey )
	{
	long size;

	size = sizeofObject( bitsToBytes( dsaKey->pLen ) ) +
		   sizeofObject( bitsToBytes( dsaKey->qLen ) ) +
		   sizeofObject( bitsToBytes( dsaKey->xLen ) );
	if( !dsaKey->isPublicKey )
		size += sizeofEnumerated( 0 ) +
				sizeofObject( bitsToBytes( dsaKey->yLen ) );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + ( int ) size );
	}

/* Determine the size of the data payload of an X.509 SubjectPublicKeyInfo
   record (not including the SEQUENCE encapsulation) */

static int sizeofPublicKeyData( const PKC_INFO *pkcInfo )
	{
	int size;

	/* Determine the size of the PKC information */
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			size = sizeofDHcomponents( ( CRYPT_PKCINFO_DH * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_RSA:
			size = sizeofRSAcomponents( ( CRYPT_PKCINFO_RSA * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_DSA:
			size = sizeofDSAcomponents( ( CRYPT_PKCINFO_DSA * ) pkcInfo->keyInfo );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	/* Return the size of the AlgorithmIdentifier record and the BITSTRING-
	   encapsulated public-key data */
	return( sizeofAlgorithmIdentifier( pkcInfo ) + sizeof( BYTE ) +
			calculateLengthSize( size ) + size );
	}

/****************************************************************************
*																			*
*							Read/Write X.509 Key Records					*
*																			*
****************************************************************************/

/* Read a public key from an X.509 SubjectPublicKeyInfo record */

int readPublicKey( STREAM *stream, PKC_INFO *pkcInfo )
	{
	BYTE buffer[ MAX_OID_SIZE ];
	int readDataLength, totalLength, bufferLength;
	long length;

	/* Clear the return data in case we don't get anything useful */
	memset( pkcInfo, 0, sizeof( PKC_INFO ) );

	/* Read the SubjectPublicKeyInfo header field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readDataLength = readLength( stream, &length ) + 1;
	totalLength = ( int ) length + readDataLength;

	/* Read the AlgorithmIdentifier header */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readDataLength += readLength( stream, &length ) + 1;

	/* Determine the key type based on the AlgorithmIdentifier field */
	readDataLength += readRawObject( stream, buffer, &bufferLength,
									 MAX_OID_SIZE, BER_OBJECT_IDENTIFIER );
	if( !memcmp( buffer, OID_DHKEYAGREEMENT, bufferLength ) )
		{
		pkcInfo->algorithm = CRYPT_ALGO_DH;
		pkcInfo->keyInfoSize = sizeof( CRYPT_PKCINFO_RSA );
		}
	if( !memcmp( buffer, OID_RSAENCRYPTION, bufferLength ) )
		{
		pkcInfo->algorithm = CRYPT_ALGO_RSA;
		pkcInfo->keyInfoSize = sizeof( CRYPT_PKCINFO_RSA );
		}
	if( !memcmp( buffer, OID_DSAENCRYPTION, bufferLength ) )
		{
		pkcInfo->algorithm = CRYPT_ALGO_DSA;
		pkcInfo->keyInfoSize = sizeof( CRYPT_PKCINFO_RSA );
		}
	if( pkcInfo->algorithm == CRYPT_ALGO_NONE )
		{
		/* Unknown algorithm type, return */
		sSkip( stream, totalLength - readDataLength );
		return( CRYPT_NOALGO );
		}
	/* Read the BITSTRING encapsulation of the public key fields */
	if( readTag( stream ) != BER_BITSTRING )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	sgetc( stream );	/* Skip extra bit count in bitfield */

	/* Finally, read the PKC information and generate the key ID for it */
	if( ( pkcInfo->keyInfo = malloc( pkcInfo->keyInfoSize ) ) == NULL )
		return( CRYPT_NOMEM );
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			readDataLength += readDHcomponents( stream,
						( CRYPT_PKCINFO_DH * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_RSA:
			readDataLength += readRSAcomponents( stream,
						( CRYPT_PKCINFO_RSA * ) pkcInfo->keyInfo, TRUE );
			break;

		case CRYPT_ALGO_DSA:
			readDataLength += readDSAcomponents( stream,
						( CRYPT_PKCINFO_DSA * ) pkcInfo->keyInfo, TRUE );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	if( sGetStatus( stream ) != STREAM_OK )
		{
		zeroise( pkcInfo->keyInfo, pkcInfo->keyInfoSize );
		free( pkcInfo->keyInfo );
		zeroise( pkcInfo, sizeof( PKC_INFO ) );
		return( CRYPT_BADDATA );
		}
	return( readDataLength );
	}

/* Write a public key to an X.509 SubjectPublicKeyInfo record */

int writePublicKey( STREAM *stream, const PKC_INFO *pkcInfo )
	{
	/* Write the SubjectPublicKeyInfo header field */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofPublicKeyData( pkcInfo ) );

	/* Write the AlgorithmIdentifier field.  The type and length will
	   always be encoded as two bytes so we use sizeofAlgorithmIdentifier()
	   and subtract the size of the header for the length */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofAlgorithmIdentifier( pkcInfo ) -
				 sizeof( BYTE ) + sizeof( BYTE ) );
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			swrite( stream, OID_DHKEYAGREEMENT, sizeofOID( OID_DHKEYAGREEMENT ) );
			break;

		case CRYPT_ALGO_RSA:
			swrite( stream, OID_RSAENCRYPTION, sizeofOID( OID_RSAENCRYPTION ) );
			break;

		case CRYPT_ALGO_DSA:
			swrite( stream, OID_DSAENCRYPTION, sizeofOID( OID_DSAENCRYPTION ) );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	/* Write the BITSTRING wrapper for the PKC information */
	writeTag( stream, BER_SEQUENCE );
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			writeLength( stream, sizeofDHcomponents( ( CRYPT_PKCINFO_DH * ) \
						 pkcInfo->keyInfo ) );
			break;

		case CRYPT_ALGO_RSA:
			writeLength( stream, sizeofRSAcomponents( ( CRYPT_PKCINFO_RSA * ) \
						 pkcInfo->keyInfo ) );
			break;

		case CRYPT_ALGO_DSA:
			writeLength( stream, sizeofDSAcomponents( ( CRYPT_PKCINFO_DSA * ) \
						 pkcInfo->keyInfo ) );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	/* Finally, write the PKC information */
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			writeDHcomponents( stream, ( CRYPT_PKCINFO_DH * ) \
							   pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_RSA:
			writeRSAcomponents( stream, ( CRYPT_PKCINFO_RSA * ) \
								pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_DSA:
			writeDSAcomponents( stream, ( CRYPT_PKCINFO_DSA * ) \
								pkcInfo->keyInfo );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*					Read/Write Key Collection/Record Headers				*
*																			*
****************************************************************************/

#ifdef FULL_KEYMGMT

/* Read a key collection header record */

int _readHeader( STREAM *stream, int *noRecords, int *maxVersion,
				 char *description, const BOOLEAN readIdent )
	{
	int readDataLength = 0, dataLength, tagLength;
	long length;

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
	readDataLength += readLength( stream, &length );

	/* Read the various components */
	dataLength = readShortInteger( stream, ( long * ) noRecords );
	dataLength += readShortInteger( stream, ( long * ) maxVersion );
	tagLength = checkReadCtag( stream, CTAG_KH_DESCRIPTION, TRUE );
	if( tagLength )
		dataLength += readStaticTextString( stream, description,
									CRYPT_MAX_TEXTSIZE, FALSE ) + tagLength;

	/* Read any extra fields which might be present */
	if( dataLength < length )
		{
		int remainder = ( int ) length - dataLength;

		sSkip( stream, remainder );
		dataLength += remainder;
		}

	if( *noRecords < 1 || *maxVersion < 0 )
		return( CRYPT_BADDATA );
	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + dataLength );
	}

/* Write a key collection header record */

int writeHeader( STREAM *stream, const int noRecords, const int maxVersion,
				 const char *description, const int tag )
	{
	int size = 0;

	/* If there's a description for this key collection, evaluate the size
	   of the encoded string */
	if( description != NULL )
		size += sizeofTextString( description );

	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, sizeofShortInteger( noRecords ) +
				 sizeofShortInteger( maxVersion ) + size );

	/* It's a composite type.  Write the various fields */
	writeShortInteger( stream, noRecords, DEFAULT_TAG );
	writeShortInteger( stream, maxVersion, DEFAULT_TAG );
	if( description != NULL )
		writeTextString( stream, description, CTAG_KH_DESCRIPTION );

	return( sGetStatus( stream ) );
	}

/* Read a key record header */

int _readKeyRecordHeader( STREAM *stream, int *length, const BOOLEAN readIdent )
	{
	int readDataLength = 0, size, markerLength;
	long longLength;
	BYTE buffer[ 5 ];

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
	readDataLength += readLength( stream, &longLength );
	*length = ( int ) longLength;

	/* Read and check the restart marker */
	markerLength = readStaticOctetString( stream, buffer, &size,
										  RESTART_MARKER_SIZE );
	if( memcmp( buffer, RESTART_MARKER, size ) )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	*length -= markerLength;

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + markerLength );
	}

/* Write a key record header */

int writeKeyRecordHeader( STREAM *stream, int length, const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, ( int ) sizeofObject( RESTART_MARKER_SIZE ) + length );

	/* Write the restart marker */
	writeByteString( stream, RESTART_MARKER, RESTART_MARKER_SIZE, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*							Read/Write Key Record 							*
*																			*
****************************************************************************/

/* Read the start of a generic public or private key record */

static int readKeyHeader( STREAM *stream, PKC_INFO *pkcInfo, int *length,
						  const BOOLEAN readIdent )
	{
	KEYID *keyIDptr = &pkcInfo->keyID;
	MESSAGE_DIGEST keyID;
	TIME validFrom, validTo;
	int readDataLength = 0, dataLength, tagLength;
	long longLength;

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

	/* Read key ID and validity period */
	readDataLength += readLength( stream, &longLength );
	*length = ( int ) longLength;
	dataLength = readMessageDigest( stream, &keyID );
	keyIDptr->hashAlgo = keyID.type;
	keyIDptr->keyIDlength = keyID.length;
	memcpy( keyIDptr->keyID, keyID.data, keyID.length );
	deleteMessageDigest( &keyID );
	newTime( &validFrom, 0, 0 );
	newTime( &validTo, 0, 0 );
	tagLength = checkReadCtag( stream, CTAG_PK_VALIDFROM, TRUE );
	if( tagLength )
		dataLength += readTimeData( stream, &validFrom ) + tagLength;
	tagLength = checkReadCtag( stream, CTAG_PK_VALIDTO, TRUE );
	if( tagLength )
		dataLength += readTimeData( stream, &validTo ) + tagLength;
	dataLength += readEnumerated( stream, ( int * ) &pkcInfo->algorithm );
	pkcInfo->validFrom = validFrom.seconds;
	pkcInfo->validTo = validTo.seconds;
	deleteTime( &validFrom );
	deleteTime( &validTo );
	*length -= dataLength;

	/* Since this is an internal routine there's no need for an error check
	   at this point */
	return( readDataLength + dataLength );
	}

/* Write the start of a generic public or private key record */

static int writeKeyHeader( STREAM *stream, const int tag, PKC_INFO *pkcInfo )
	{
	KEYID *keyIDptr = &pkcInfo->keyID;
	CRYPT_ALGO pkcAlgo = pkcInfo->algorithm;
	TIME validFrom, validTo;
	MESSAGE_DIGEST keyID;
	int size;

	/* Get the size of the key components */
	if( cryptStatusError( size = sizeofKeyComponents( pkcInfo ) ) )
		return( size );

	/* Initialise the ASN.1 types */
	newTime( &validFrom, pkcInfo->validFrom, 0 );
	newTime( &validTo, pkcInfo->validTo, 0 );
	newMessageDigest( &keyID, keyIDptr->hashAlgo, keyIDptr->keyID,
					  keyIDptr->keyIDlength );

	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, size );

	/* Write the key ID, validity period, and algorithm ID fields */
	writeMessageDigest( stream, &keyID, DEFAULT_TAG );
	if( pkcInfo->validFrom )
		writeTime( stream, &validFrom, CTAG_PK_VALIDFROM );
	if( pkcInfo->validTo )
		writeTime( stream, &validTo, CTAG_PK_VALIDTO );
	writeEnumerated( stream, pkcAlgo, DEFAULT_TAG );

	/* Clean up */
	deleteTime( &validFrom );
	deleteTime( &validTo );
	deleteMessageDigest( &keyID );

	/* Since this is an internal routine there's no need for an error check
	   at this point */
	return( CRYPT_OK );
	}

/* Read a key info/cert header */

int _readKeyInfoHeader( STREAM *stream, int *length, const BOOLEAN readIdent )
	{
	int readDataLength = 0;
	long longLength;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SET )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_BADDATA );
			}
		readDataLength++;
		}
	readDataLength += readLength( stream, &longLength );
	*length = ( int ) longLength;
	if( checkReadTag( stream, BER_NULL ) )
		{
		readDataLength += readNull( stream );
		*length = 0;
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Write a key info/cert header */

int writeKeyInfoHeader( STREAM *stream, int length, const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SET );
	else
		writeCtag( stream, tag, TRUE );
	if( !length )
		{
		writeLength( stream, sizeofNull() );
		writeNull( stream, DEFAULT_TAG );
		}
	else
		writeLength( stream, ( int ) sizeofObject( RESTART_MARKER_SIZE ) + length );

	return( sGetStatus( stream ) );
	}

/* Read a public or private key value */

int _readKey( STREAM *stream, PKC_INFO *pkcInfo, const BOOLEAN readIdent,
			  const BOOLEAN isPublicKey )
	{
	int readDataLength, length;

	/* Read the header field */
	readDataLength = readKeyHeader( stream, pkcInfo, &length, readIdent );
	if( cryptStatusError( readDataLength ) )
		return( readDataLength );

	/* Read the PKC information */
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			readDataLength += readDHcomponents( stream,
						( CRYPT_PKCINFO_DH * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_RSA:
			readDataLength += readRSAcomponents( stream,
						( CRYPT_PKCINFO_RSA * ) pkcInfo->keyInfo, isPublicKey );
			break;

		case CRYPT_ALGO_DSA:
			readDataLength += readDSAcomponents( stream,
						( CRYPT_PKCINFO_DSA * ) pkcInfo->keyInfo, isPublicKey );
			break;

		default:
			sSkip( stream, length );
			return( CRYPT_NOALGO );
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Write a public or private key */

int writeKey( STREAM *stream, PKC_INFO *pkcInfo, const int tag )
	{
	/* Write the general record header */
	writeKeyHeader( stream, tag, pkcInfo );

	/* Write the PKC information */
	switch( pkcInfo->algorithm )
		{
		case CRYPT_ALGO_DH:
			writeDHcomponents( stream,
					( CRYPT_PKCINFO_DH * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_RSA:
			writeRSAcomponents( stream,
					( CRYPT_PKCINFO_RSA * ) pkcInfo->keyInfo );
			break;

		case CRYPT_ALGO_DSA:
			writeDSAcomponents( stream,
					( CRYPT_PKCINFO_DSA * ) pkcInfo->keyInfo );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	return( sGetStatus( stream ) );
	}
#endif /* FULL_KEYMGMT */
