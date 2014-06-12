/****************************************************************************
*																			*
*							  X.509 Key Read Routines						*
*							Copyright Peter Gutmann 1996					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1oid.h"
  #include "keymgmt.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/keymgmt.h"
#endif /* Compiler-specific includes */

/* The minimum and maximum X.509 certificate format we recognise */

#define MIN_X509_VERSION		0	/* X.509v1 */
#define MAX_X509_VERSION		2	/* X.509v3 */

/* The maximum length of an X.500 commonName */

#define MAX_COMMONNAME_LENGTH	64

/* Context-specific tags for the X.509 certificate */

enum { CTAG_XC_VERSION, CTAG_XC_ISSUERID, CTAG_XC_SUBJECTID,
	   CTAG_XC_EXTENSIONS };

/****************************************************************************
*																			*
*						Object Identifier Handling Routines					*
*																			*
****************************************************************************/

/* Read a SEQUENCE { OBJECT IDENTIFIER, ... } object and compare it with an
   expected value.  This routine doesn't compare the passed-in object ID
   length with the read length since sometimes all we need is a match down
   one arc of the graph and not a complete match.

   This function returns information in a complex and screwball manner:

	CRYPT_BADDATA if an object identifier in the correct format wasn't
	found

	0 and skips the associated attribute data, storing the total number of
	bytes read in remainingData if an object identifier was found by didn't
	match the required one,

	The number of bytes read and the associated attribute data ready to read
	if a match was found */

#define checkOID( stream, oid, remainingData ) \
		_checkOID( stream, oid, remainingData, TRUE )
#define checkOIDdata( stream, oid, remainingData ) \
		_checkOID( stream, oid, remainingData, FALSE )

static int _checkOID( STREAM *stream, const BYTE *oid, int *remainingData,
					  const BOOLEAN readIdent )
	{
	BYTE buffer[ MAX_OID_SIZE ];
	long totalLength;
	const int oidLength = sizeofOID( oid );
	int readDataLength, bufferLength;

	/* Perform a quick sanity check */
	if( oidLength > MAX_OID_SIZE )
		return( CRYPT_ERROR );

	/* Read the identifier and length fields */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &totalLength ) + 1;

	/* Read the raw object identifier data and compare it to the expected
	   OID */
	readDataLength += readRawObject( stream, buffer, &bufferLength,
									 MAX_OID_SIZE, BER_OBJECT_IDENTIFIER );
	if( bufferLength < oidLength )
		return( CRYPT_BADDATA );
	totalLength -= bufferLength + 1;
	if( memcmp( buffer, oid, oidLength ) )
		{
		/* It's not what we want, skip any associated attribute data */
		if( totalLength )
			readDataLength += readUniversal( stream );
		*remainingData = 0;
		return( 0 );
		}

	/* Remember the length of any optional attribute fields */
	*remainingData = ( int ) totalLength;

	return( readDataLength );
	}

/* Check and OID and skip any associated attribute data */

static int checkReadOID( STREAM *stream, BYTE *oid )
	{
	int remainingData, status;

	status = checkOID( stream, oid, &remainingData );
	if( !cryptStatusError( status ) && remainingData > 0 )
		readUniversal( stream );

	return( status );
	}

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Find a Common Name (CN) in a Name record */

static int readName( STREAM *stream, char *commonName )
	{
	int readDataLength;
	long totalLength;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readDataLength = readLength( stream, &totalLength ) + 1;
	readDataLength += ( int ) totalLength;

	/* Walk through the SEQUENCE OF RelativeDistinguishedNames looking
	   for the common name */
	while( totalLength > 0 )
		{
		long setLength;

		/* Read the identifier field */
		if( readTag( stream ) != BER_SET )
			return( CRYPT_BADDATA );
		totalLength -= readLength( stream, &setLength ) + 1;
		totalLength -= setLength;

		/* Walk through the SET OF AttributeValueAssertions looking for the
		   first common name */
		while( setLength > 0 )
			{
			int remainingData, status;

			/* Check for a commonName */
			status = checkOID( stream, OID_COMMONNAME, &remainingData );
			if( cryptStatusError( status ) )
				return( status );
			if( status )
				{
				int commonNameLength;

				/* Read in the common name */
				if( readTag( stream ) != BER_STRING_PRINTABLE )
					return( CRYPT_BADDATA );
				status += readStaticOctetStringData( stream, ( BYTE * )
								commonName, &commonNameLength,
								MAX_COMMONNAME_LENGTH ) + 1;
				commonName[ commonNameLength ] = '\0';

				/* Subtract the number of bytes read from the set length */
				setLength -= status;
				}
			else
				/* We've read the OID/attribute sequence as part of
				   checkOID(), subtract it from the set length */
				setLength -= remainingData;
			}
		if( setLength < 0 )
			return( CRYPT_BADDATA );
		}
	if( totalLength < 0 )
		return( CRYPT_BADDATA );

	return( readDataLength );
	}

/* Get the subtype of the key file */

KEYSET_SUBTYPE x509GetKeysetType( FILE *filePtr )
	{
	STREAM stream;
	int status = KEYSET_SUBTYPE_ERROR;

	/* Connect the file to an I/O stream */
	sFileConnect( &stream, filePtr );

	/* Make sure it's some sort of ASN.1-encapsulated object */
	if( readTag( &stream ) == BER_SEQUENCE )
		{
		BYTE dataType[ 11 ];
		int dataTypeLength;
		long length;

		readLength( &stream, &length );

		/* Check for a SEQUENCE identifier field */
		if( readTag( &stream ) == BER_SEQUENCE )
			status = KEYSET_SUBTYPE_PUBLIC;
		else
			{
			sungetc( &stream );

			/* Check for a Netscape private key file */
			if( !cryptStatusError( readStaticOctetString( &stream, dataType,
												&dataTypeLength, 11 ) ) && \
				dataTypeLength == 11 && !memcmp( dataType, "private-key", 11 ) )
				status = KEYSET_SUBTYPE_PRIVATE;
			}
		}

	/* Clean up */
	sFileSeek( &stream, 0L );	/* Move back to start of file */
	sFileDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Read an X.509/SET Public Key					*
*																			*
****************************************************************************/

/* Read an X.509/SET key */

static int readX509key( STREAM *stream, PKC_INFO *pkcInfo,
						const GETKEY_INFO *getkeyInfo, char *name )
	{
	long length, integer;
	time_t time;
	int status;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the version number and certificate serial number */
	if( checkReadCtag( stream, CTAG_XC_VERSION, TRUE ) )
		{
		readLength( stream, &length );
		readShortInteger( stream, &integer );
		if( integer < MIN_X509_VERSION || integer > MAX_X509_VERSION )
			return( CRYPT_BADDATA );
		}
	if( readTag( stream ) != BER_INTEGER )
		return( CRYPT_BADDATA );
	readUniversalData( stream );

	/* Read the signature algorithm type */
	status = checkReadOID( stream, OID_PKCS1 );
	if( status <= 0 )
		return( CRYPT_BADDATA );

	/* Read the certificate issuer name */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readUniversalData( stream );

	/* Read the certificate validity period */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	readUTCTime( stream, &time );
	readUTCTime( stream, &time );

	/* Read the subject name if we're looking for a match by name, otherwise
	   skip this field */
	if( !getkeyInfo->isKeyID )
		{
		readName( stream, name );
		if( !matchSubstring( getkeyInfo->keyID, name ) )
			return( CRYPT_KEYSET_NOTFOUND );
		}
	else
		{
		if( readTag( stream ) != BER_SEQUENCE )
			return( CRYPT_BADDATA );
		readUniversalData( stream );
		}

	/* Read the SubjectPublicKeyInfo field */
	status = readPublicKey( stream, pkcInfo );
	if( !cryptStatusError( status ) )
		{
		BYTE blem[ CRYPT_MAX_KEYIDSIZE ];
		int blemsize;

		status = generateKeyID( CRYPT_ALGO_RSA, blem, &blemsize,
								pkcInfo->keyInfo );
		}

	return( status );
	}

/* Read an X.509/SET public key certificate */

static int readX509certificate( STREAM *stream, PKC_INFO *pkcInfo,
								const GETKEY_INFO *getkeyInfo, char *name )
	{
	long length;
	int status;

	/* Clear the return data in case we don't get anything useful */
	memset( pkcInfo, 0, sizeof( PKC_INFO ) );

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}
	readLength( stream, &length );

	status = readX509key( stream, pkcInfo, getkeyInfo, name );
	return( status );
	}

/****************************************************************************
*																			*
*							Read an X.509/SET Private Key					*
*																			*
****************************************************************************/

/* Read a PKCS #8 private key */

static int readPKCS8PrivateKey( BYTE *buffer, int bufferLength,
								PKC_INFO *pkcInfo )
	{
	STREAM stream;
	long integer, length;
	int status = CRYPT_WRONGKEY;

	/* Connect the memory buffer to an I/O stream */
	sMemConnect( &stream, buffer, bufferLength );

	/* Read the start of the private-key encapsulation as a check that the
	   correct decryption key was used.  We check that we've got a SEQUENCE,
	   that the size of the object is > 128 bytes (which is about the
	   minimum a 256-bit key can be encoded in, and also catches any cases
	   of the BER short length encoding), that the size of the object is
	   < 8192 bytes (which is a suspiciously large key of about 8K+ bits),
	   and that the version number is 0 */
	if( readTag( &stream ) != BER_SEQUENCE )
		{
		sMemClose( &stream );
		return( CRYPT_WRONGKEY );
		}
	readLength( &stream, &length );
	readShortInteger( &stream, &integer );
	if( length < 128 || length > 8192 || integer )
		{
		sMemClose( &stream );
		return( CRYPT_WRONGKEY );
		}
	sMemDisconnect( &stream );

	/* Now that we're reasonably sure we've used the correct decryption key,
	   reconnect the stream and read the private key fields */
	sMemConnect( &stream, buffer, bufferLength );
/*	status = readRSAcomponents( &stream, pkcInfo, FALSE ); */
	if( pkcInfo );	/* Get rid of compiler warning */
	status = CRYPT_ERROR;
	if( !cryptStatusError( status ) )
		status = CRYPT_OK;	/* readXXX() functions return a byte count */

	/* Clean up */
	sMemClose( &stream );
	return( status );
	}

/* Read a Netscape private key, which contains Netscapes encapsulation of the
   PKCS #8 RSA private key fields.  The format is:

	SEQUENCE {
		OCTET STRING 'private-key',
		SEQUENCE {
			SEQUENCE {
				OBJECT IDENTIFIER '1 2 840 113549 3 4' (rc4),
				NULL
				}
			OCTET STRING encrypted-private-key
			}
		}

	The OCTET STRING decrypts to a standard PKCS #8 private key object */

static int readNetscapeKey( STREAM *stream, PKC_INFO *pkcInfo,
							const GETKEY_INFO *getkeyInfo )
	{
    CRYPT_CONTEXT cryptContext;
	BYTE *buffer, hashResult[ CRYPT_MAX_HASHSIZE ], dataType[ 11 ];
	int hashInfoSize, hashInputSize, hashOutputSize;
	HASHFUNCTION hashFunction;
	long length;
	int dataTypeLength, status;

	/* Clear the return data in case we don't get anything useful */
	memset( pkcInfo, 0, sizeof( PKC_INFO ) );

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the data type field */
	if( cryptStatusError( readStaticOctetString( stream, dataType,
												 &dataTypeLength, 11 ) ) || \
		dataTypeLength != 11 || memcmp( dataType, "private-key", 11 ) )
		return( CRYPT_BADDATA );

	/* Read the inner SEQUENCE field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the encryption algorithm type */
	status = checkReadOID( stream, OID_RC4 );
	if( status <= 0 )
		return( CRYPT_BADDATA );

	/* Read the OCTET STRING containing the encrypted RSA key */
	if( readTag( stream ) != BER_OCTETSTRING )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	if( length > 8192 )
		return( CRYPT_BADDATA );

	/* Read the encrypted data into an in-memory buffer */
	if( ( buffer = ( BYTE * ) malloc( ( size_t ) length ) ) == NULL )
		return( CRYPT_NOMEM );
	sread( stream, buffer, ( int ) length );
	if( ( status = sGetStatus( stream ) ) == STREAM_EMPTY ||
		status == STREAM_READ )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( CRYPT_BADDATA );
		}

	/* Hash the passphrase with MD5 */
	if( !getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( CRYPT_ERROR );	/* API error, should never occur */
		}
	hashFunction( NULL, hashResult, getkeyInfo->password,
				  getkeyInfo->passwordSize, HASH_ALL );

	/* Load the hashed passphrase into an encryption context */
	status = cryptCreateContext( &cryptContext, CRYPT_ALGO_RC4,
								 CRYPT_MODE_STREAM );
	if( !cryptStatusError( status ) )
		status = cryptLoadContext( cryptContext, hashResult, hashOutputSize );
	zeroise( hashResult, hashOutputSize );
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( status );
		}

	/* Decrypt the private key components */
	cryptDecrypt( cryptContext, buffer, ( int ) length );
	cryptDestroyContext( cryptContext );

	/* Read the private key fields */
	status = readPKCS8PrivateKey( buffer, ( int ) length, pkcInfo );

	/* Clean up (the buffer has already been wiped in readPKCS8PrivateKey() */
	free( buffer );
	return( status );
	}

/* Get an X.509 key */

int x509GetKey( FILE *filePtr, CRYPT_CONTEXT *cryptContext,
				const GETKEY_INFO *getkeyInfo )
	{
	PKC_INFO pkcInfo;
	STREAM stream;
	char name[ MAX_COMMONNAME_LENGTH + 1 ];
	int status;

	/* Read the public or private key */
	sFileConnect( &stream, filePtr );
	if( getkeyInfo->isPublicKey )
		status = readX509certificate( &stream, &pkcInfo, getkeyInfo, name );
	else
		status = readNetscapeKey( &stream, &pkcInfo, getkeyInfo );

	/* Create the encryption context and load the key into it */
	if( cryptStatusOK( status ) )
		{
		status = cryptCreateContext( cryptContext, pkcInfo.algorithm,
									 CRYPT_MODE_PKC );
		if( cryptStatusOK( status ) )
			status = cryptLoadContext( *cryptContext, pkcInfo.keyInfo,
									   CRYPT_UNUSED );
		}
	sFileDisconnect( &stream );

	/* Store the name in the encryption context as well in case we want to
	   later export the key to another type of keyset */
	if( getkeyInfo->isPublicKey && cryptStatusOK( status ) )
		{
		CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( *cryptContext );

		if( ( cryptInfoPtr->userID = ( char * ) \
					malloc( strlen( name + 1 ) ) ) == NULL )
			{
			cryptDestroyContext( *cryptContext );
			return( CRYPT_NOMEM );
			}
		strcpy( cryptInfoPtr->userID, name );
		}

	/* Clean up */
	if( pkcInfo.keyInfo != NULL )
		cleanFree( &pkcInfo.keyInfo, pkcInfo.keyInfoSize );
	zeroise( &pkcInfo, sizeof( PKC_INFO ) );
	return( status );
	}
