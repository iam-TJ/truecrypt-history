/****************************************************************************
*																			*
*						cryptlib Object Management Routines					*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1objs.h"
#else
  #include "keymgmt/asn1objs.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Object Management Functions						*
*																			*
****************************************************************************/

/* Query an object */

CRET cryptQueryObject( const void CPTR object,
					   CRYPT_OBJECT_INFO CPTR cryptObjectInfo )
	{
	CRYPT_OBJECT_TYPE objectType;
	STREAM stream;
	BOOLEAN isContinued;
	long length;
	int headerSize, status;

	/* Perform basic error checking */
	if( object == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptObjectInfo == NULL )
		return( CRYPT_BADPARM2 );

	/* Clear the query information in case we can't do anything with the
	   object */
	memset( cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Read the information from the start of the object */
	sMemConnect( &stream, ( void * ) object, STREAMSIZE_UNKNOWN );
	status = readObjectWrapper( &stream, &objectType, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	cryptObjectInfo->type = objectType;
	cryptObjectInfo->size = length;
	headerSize = status;

	/* If it's encrypted data, read the continuation field, key cookie, and
	   IV, and work out the header and payload size */
	if( objectType == CRYPT_OBJECT_ENCRYPTED_DATA )
		{
		status = readEncryptedObject( &stream, &isContinued, &length,
									  cryptObjectInfo );
		if( !cryptStatusError( status ) )
			{
			cryptObjectInfo->headerSize = headerSize + status;
			cryptObjectInfo->payloadSize = length;
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */
			}
		}

	/* If it's raw data or non-data, read the continuation field and work out
	   the header and payload size */
	if( objectType == CRYPT_OBJECT_RAW_DATA || \
		objectType == CRYPT_OBJECT_NONDATA )
		{
		status = readBasicObject( &stream, &isContinued, &length );
		if( !cryptStatusError( status ) )
			{
			cryptObjectInfo->headerSize = headerSize + status;
			cryptObjectInfo->payloadSize = length;
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */
			}
		}

	/* If it's a signed data object, read the signature cookie and hash
	   algorithm details */
	if( objectType == CRYPT_OBJECT_SIGNED_DATA )
		{
		status = readSignedObject( &stream, &isContinued,
								   cryptObjectInfo );
		if( !cryptStatusError( status ) )
			{
			/* We can't determine the payload size directly because a
			   SignedData object directly encapsulates arbitrary object types
			   whose length gets difficult to determine without recursively
			   reading them as well, so we calculate it as ( objectSize -
			   headerSize ) */
			cryptObjectInfo->cryptMode = CRYPT_MODE_PKC;
			cryptObjectInfo->headerSize = headerSize + status;
			cryptObjectInfo->payloadSize = cryptObjectInfo->size -
										   cryptObjectInfo->headerSize;
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */
			}
		}

	/* If it's a conventional-encrypted key object, read the encryption
	   algorithm details */
	if( objectType == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		status = readCKObject( &stream, cryptObjectInfo );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */

		/* Set the header size information.  For this type of object the
		   payload size is always zero */
		if( cryptStatusOK( status ) )
			cryptObjectInfo->headerSize = ( int ) cryptObjectInfo->size;
		}

	/* If it's a PKC-encrypted key or signature object, read the PKC
	   details */
	if( objectType == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		objectType == CRYPT_OBJECT_SIGNATURE )
		{
		CRYPT_ALGO cryptAlgo;
		BYTE keyID[ CRYPT_MAX_KEYIDSIZE ];
		int keyIDsize;

		/* Read the basic PKC details */
		status = readPKObject( &stream, keyID, &keyIDsize, &cryptAlgo );
		if( !cryptStatusError( status ) )
			{
			cryptObjectInfo->cryptAlgo = cryptAlgo;
			cryptObjectInfo->cryptMode = CRYPT_MODE_PKC;
			memcpy( cryptObjectInfo->keyID, keyID, keyIDsize );
			cryptObjectInfo->keyIDsize = keyIDsize;

			/* Read further information depending on the object type */
			if( objectType == CRYPT_OBJECT_SIGNATURE )
				status = CRYPT_OK;	/* The readXXX() fns.return a byte count */
			else
				{
				status = readPKKeyObject( &stream, cryptAlgo, NULL,
										  cryptObjectInfo );
				if( !cryptStatusError( status ) )
					status = CRYPT_OK;	/* The readXXX() fns.return a byte count */
				}

			/* Set the header size information.  For this type of object the
			   payload size is always zero */
			if( cryptStatusOK( status ) )
				cryptObjectInfo->headerSize = ( int ) cryptObjectInfo->size;
			}
		}

	sMemDisconnect( &stream );
	return( status );
	}

/* Export a general data object.  This currently doesn't support the full
   capability of the data format:

   - Continuations aren't supported for any data types
   - Only one hash algorithm type at a time is supported for SignedData
     types */

CRET cryptExportObjectEx( void CPTR object, int CPTR objectLength,
						  CRYPT_OBJECT_TYPE objectType, const long dataLength,
						  const CRYPT_CONTEXT cryptContext )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	STREAM stream;
	int status;

	/* Perform basic error checking */
	if( objectType < CRYPT_OBJECT_ENCRYPTED_DATA || \
		objectType > CRYPT_OBJECT_NONDATA )
		return( CRYPT_BADPARM1 );
	if( objectLength == NULL )
		return( CRYPT_BADPARM2 );
	if( objectType == CRYPT_OBJECT_ENCRYPTED_DATA || \
		objectType == CRYPT_OBJECT_SIGNED_DATA )
		{
		if( isBadCookie( cryptContext ) || \
			cryptInfoPtr->checkValue != CRYPT_MAGIC )
			return( CRYPT_BADPARM3 );
		if( objectType == CRYPT_OBJECT_ENCRYPTED_DATA &&
			( cryptInfoPtr->isPKCcontext || \
			  cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE ) )
			return( CRYPT_BADPARM3 );
		if( objectType == CRYPT_OBJECT_SIGNED_DATA && \
			cryptInfoPtr->capabilityInfo->cryptMode != CRYPT_MODE_NONE )
			return( CRYPT_BADPARM3 );
		}
	else
		if( cryptContext != ( CRYPT_CONTEXT ) CRYPT_UNUSED )
			return( CRYPT_BADPARM5 );
	if( dataLength < 0 )
		return( CRYPT_BADPARM4 );

	/* If it's compressed data, return with a bad parameter error (we don't
	   handle this data type yet) */
	if( objectType == CRYPT_OBJECT_COMPRESSED_DATA )
		return( CRYPT_BADPARM1 );

	/* Open a null or normal stream depending on whether we're just getting
	   the length or actually outputting data */
	if( object == NULL )
		sMemNullOpen( &stream );
	else
		sMemOpen( &stream, object, STREAMSIZE_UNKNOWN );

	/* If it's a basic data type, just write the data header */
	if( objectType == CRYPT_OBJECT_RAW_DATA || \
		objectType == CRYPT_OBJECT_NONDATA )
		status = writeBasicObject( &stream, FALSE, dataLength,
								   objectType == CRYPT_OBJECT_RAW_DATA );

	/* If it's encrypted data, write the key cookie, IV, and data header */
	if( objectType == CRYPT_OBJECT_ENCRYPTED_DATA )
		{
		/* If the algorithm requires an IV and there isn't already one
		   loaded, load one now.  This is somewhat nasty in that a side-
		   effect of calling cryptCreateDataObject() is to load an IV into
		   the encryption context, which isn't really part of the functions
		   job description.  However the alternative is to require the user
		   to either manually load an IV or to make at least one call to
		   cryptEncrypt() before calling cryptCreateDataObject(), which is
		   equally nasty.  The lesser of the two evils is to load the IV here
		   and assume that anyone messing with the low-level cryptLoadIV()
		   function will read the docs which warn about the side-effects of
		   cryptCreateDataObject() (anyone who needs to call cryptLoadIV()
		   probably won't be using the high-level object management functions
		   anyway) */
		if( !cryptInfoPtr->ivSet )
			{
			BYTE iv[ CRYPT_MAX_IVSIZE ];
			int status;

			getNonce( iv, cryptInfoPtr->ivLength );
			if( ( status = loadIV( cryptInfoPtr, iv, cryptInfoPtr->ivLength ) ) != CRYPT_OK )
				return( status );
			}

		/* Write the information to the stream */
		status = writeEncryptedObject( &stream, FALSE, dataLength, cryptInfoPtr );
		}

	/* If it's signed data, write the signature cookie, hash algorithm info,
	   and data header */
	if( objectType == CRYPT_OBJECT_SIGNED_DATA )
		status = writeSignedObject( &stream, FALSE, cryptInfoPtr, dataLength );

	*objectLength = sMemSize( &stream );

	sMemDisconnect( &stream );
	return( status );
	}

/* Import a general data object.  This currently doesn't support the full
   capability of the data format:

   - Continuations aren't supported for any data types
   - Only one hash algorithm type at a time is supported for SignedData types
   - Checking of signature cookies isn't supported (it has to be done by
	 the user */

CRET cryptImportObjectEx( const void CPTR object, int CPTR payloadStart,
						  long CPTR payloadLength,
						  CRYPT_CONTEXT CPTR cryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	CRYPT_OBJECT_INFO cryptObjectInfo;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	if( object == NULL )
		return( CRYPT_BADPARM1 );
	if( payloadStart == NULL )
		return( CRYPT_BADPARM2 );
	if( payloadLength == NULL )
		return( CRYPT_BADPARM3 );
	if( cryptContext == NULL )
		return( CRYPT_BADPARM4 );

	/* Find out what sort of object we're dealing with */
	status = cryptQueryObject( object, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptObjectInfo.type == CRYPT_OBJECT_ENCRYPTED_DATA || \
		cryptObjectInfo.type == CRYPT_OBJECT_SIGNED_DATA )
		{
		if( cryptContext == ( CRYPT_CONTEXT CPTR ) CRYPT_UNUSED )
			return( CRYPT_BADPARM4 );

		cryptInfoPtr = CONTEXT_TO_INFO( *cryptContext );
		if( cryptObjectInfo.type == CRYPT_OBJECT_ENCRYPTED_DATA && \
			( isBadCookie( *cryptContext ) || \
			  cryptInfoPtr->checkValue != CRYPT_MAGIC ) )
			return( CRYPT_BADPARM4 );
		}
	else
		if( cryptContext != ( CRYPT_CONTEXT CPTR ) CRYPT_UNUSED )
			return( CRYPT_BADPARM4 );
	*payloadStart = cryptObjectInfo.headerSize;
	*payloadLength = cryptObjectInfo.payloadSize;

	/* If it's an encrypted data object, check the cookie and load the IV */
	if( cryptObjectInfo.type == CRYPT_OBJECT_ENCRYPTED_DATA )
		{
		/* Make sure the encryption context is of the correct type */
		if( cryptInfoPtr->isPKCcontext || \
			cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE )
			return( CRYPT_BADPARM2 );

		/* Check that we're using the correct decryption key */
		if( cryptObjectInfo.cookieSize && \
			memcmp( cryptInfoPtr->keyCookie, cryptObjectInfo.cookie,
					KEY_COOKIE_SIZE ) )
			return( CRYPT_WRONGKEY );

		/* Load the IV from the encrypted data object */
		if( needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
			status = loadIV( cryptInfoPtr, cryptObjectInfo.iv,
							 cryptObjectInfo.ivSize );
		}

	/* If it's a signed data object, create the hash context */
	if( cryptObjectInfo.type == CRYPT_OBJECT_SIGNED_DATA )
		{
		/* The lower-level functions report back what algorithms were found,
		   but don't complain if they find unknown ones (the data may have
		   been created by a newer version of the library), so we check here
		   that a given algorithm is actually available, and that it's a
		   hash algorithm */
		status = cryptModeAvailable( cryptObjectInfo.cryptAlgo,
									 CRYPT_MODE_NONE );
		if( cryptStatusError( status ) )
			return( status );

		/* Create the hash context.  If we get a parameter error for the
		   fourth parameter (a newer version of the library may add
		   parameters to existing algorithms) then we convert it to an no
		   algorithm error */
		status = cryptCreateContextEx( cryptContext,
									   cryptObjectInfo.cryptAlgo,
									   CRYPT_MODE_NONE,
									   cryptObjectInfo.cryptContextExInfo );
		if( status == CRYPT_BADPARM4 )
			status = CRYPT_NOALGO;
		}

	return( status );
	}
