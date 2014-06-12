/****************************************************************************
*																			*
*						cryptlib PKCS Interface Routines					*
*						Copyright Peter Gutmann 1993-1996					*
*																			*
****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1objs.h"
#else
  #include "keymgmt/asn1objs.h"
#endif /* Compiler-specific includes */

/* The following routines try to keep the amount of time in which sensitive
   information is present in buffers to an absolute minimum (although the
   buffers are pagelocked on most OS's, there are some systems where this
   isn't possible).  The code is structured to keep the operations which
   create and those which use sensitive information in memory as close
   together as possible and to clear the memory as soon as it's used.  For
   this reason the structure is somewhat unusual, with everything in one
   linear block of code with jumps to clearly-defined locations to exit the
   current nesting level in the case of errors.  This is necessary to ensure
   that the approriate cleanup operations are performed at each level, and
   that the in-memory data is destroyed as soon as possible - the prime goal
   is to destroy the data as soon as we can.  Security-conscious code isn't
   necessary cleanly-structured code */

/****************************************************************************
*																			*
*							Create/Check a Signature 						*
*																			*
****************************************************************************/

/* Create a signature for a block of data */

CRET cryptCreateSignature( void CPTR signature, int CPTR signatureLength,
						   const CRYPT_CONTEXT pkcContext,
						   const CRYPT_CONTEXT hashContext )
	{
	CRYPT_INFO *hashInfoPtr = CONTEXT_TO_INFO( hashContext );
	CRYPT_INFO *pkcInfoPtr = CONTEXT_TO_INFO( pkcContext );
	CRYPT_QUERY_INFO hashQueryInfo;
	BYTE dataToSign[ CRYPT_MAX_PKCSIZE ];
	MESSAGE_DIGEST hash;
	STREAM stream;
	int length, payloadSize, status, i;

	/* Perform basic error checking */
	if( signatureLength == NULL )
		return( CRYPT_BADPARM2 );
	if( isBadCookie( pkcContext ) || pkcInfoPtr->checkValue != CRYPT_MAGIC || \
		!pkcInfoPtr->isPKCcontext || pkcInfoPtr->isPublicKey )
		return( CRYPT_BADPARM3 );
	if( isBadCookie( hashContext ) || hashInfoPtr->checkValue != CRYPT_MAGIC || \
		hashInfoPtr->capabilityInfo->cryptMode != CRYPT_MODE_NONE )
		return( CRYPT_BADPARM4 );
	if( !pkcInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( pkcInfoPtr->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );
	length = bitsToBytes( pkcInfoPtr->keySizeBits );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( signature == NULL )
		{
		STREAM nullStream;

		sMemNullOpen( &nullStream );
		status = writeSignature( &nullStream, pkcInfoPtr, dataToSign, length );
		*signatureLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Extract the hash information from the hash context, turn it into a
	   message digest record, and find out how much space we need to
	   allocate to it in the signature record.  There's no need for a length
	   check as there is for the key export function since even the largest
	   hash fits easily within the shortest PKC key the library allows */
	if( cryptQueryContext( hashContext, &hashQueryInfo ) != CRYPT_OK )
		return( CRYPT_BADPARM4 );
	newMessageDigest( &hash, hashQueryInfo.cryptAlgo,
					  hashQueryInfo.hashValue, hashQueryInfo.blockSize );
	payloadSize = sizeofMessageDigestInfo( &hash );
	zeroise( &hashQueryInfo, sizeof( CRYPT_QUERY_INFO ) );

	/* Encode the payload using the format given in PKCS #1.  The format for
	   signed data is [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is
	   done by the following code */
	sMemOpen( &stream, dataToSign, CRYPT_MAX_PKCSIZE );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	for( i = 0; i < length - ( payloadSize + 3 ); i++ )
		sputc( &stream, 0xFF );
	sputc( &stream, 0 );
	writeMessageDigestInfo( &stream, &hash );
	deleteMessageDigest( &hash );

	/* Sign the data by decrypting it with the private key */
	status = pkcInfoPtr->capabilityInfo->decryptFunction( pkcInfoPtr, dataToSign, length );

	/* Write the signature record to the output and clean up */
	if( cryptStatusOK( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, signature, STREAMSIZE_UNKNOWN );
		status = writeSignature( &outputStream, pkcInfoPtr, dataToSign, length );
		*signatureLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}
	sMemClose( &stream );

	return( status );
	}

/* Check a signature on a block of data */

CRET cryptCheckSignature( const void CPTR signature,
						  const CRYPT_CONTEXT pkcContext,
						  const CRYPT_CONTEXT hashContext )
	{
	CRYPT_INFO *hashInfoPtr = CONTEXT_TO_INFO( hashContext );
	CRYPT_INFO *pkcInfoPtr = CONTEXT_TO_INFO( pkcContext );
	CRYPT_QUERY_INFO hashQueryInfo;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE ];
	STREAM stream;
	int length, status;

	/* Perform basic error checking */
	if( signature == NULL )
		return( CRYPT_BADPARM1 );
	if( isBadCookie( pkcContext ) || pkcInfoPtr->checkValue != CRYPT_MAGIC || \
		!pkcInfoPtr->isPKCcontext )
		return( CRYPT_BADPARM2 );
	if( isBadCookie( hashContext ) || hashInfoPtr->checkValue != CRYPT_MAGIC || \
		hashInfoPtr->capabilityInfo->cryptMode != CRYPT_MODE_NONE )
		return( CRYPT_BADPARM3 );
	if( !pkcInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( pkcInfoPtr->capabilityInfo->decryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* Get information on the hash context */
	if( cryptQueryContext( hashContext, &hashQueryInfo ) != CRYPT_OK )
		return( CRYPT_BADPARM3 );
	length = bitsToBytes( pkcInfoPtr->keySizeBits );

	/* Read the signature record up to the start of the encrypted key */
	sMemConnect( &stream, ( void * ) signature, STREAMSIZE_UNKNOWN );
	status = readSignature( &stream, pkcInfoPtr );
	if( cryptStatusError( status ) )
		goto endCheckSignature;

	/* Recover the data by encrypting the signature with the public key */
	memcpy( decryptedSignature, ( BYTE * ) signature + sMemSize( &stream ), length );
	status = pkcInfoPtr->capabilityInfo->encryptFunction( pkcInfoPtr, decryptedSignature, length );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DIGEST hash;
		STREAM inputStream;
		int ch, i;

		newMessageDigest( &hash, CRYPT_ALGO_NONE, NULL, 0 );

		/* Undo the PKCS #1 padding.  The PKCS format for signed data is
		   [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is checked for by
		   the following code */
		sMemConnect( &inputStream, decryptedSignature, length );
		if( sgetc( &inputStream ) != 0 || sgetc( &inputStream ) != 1 )
			{
			status = CRYPT_BADDATA;
			goto endCheckSignatureInfo;
			}
		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &inputStream ) ) != 0xFF )
				break;
		if( ch != 0 || readMessageDigestInfo( &inputStream, &hash ) < 0 )
			{
			status = CRYPT_BADDATA;
			goto endCheckSignatureInfo;
			}

		/* Finally, make sure the two hash values match */
		if( hashQueryInfo.cryptAlgo != hash.type ||
			memcmp(	hash.data, hashQueryInfo.hashValue, hashQueryInfo.blockSize ) )
			status = CRYPT_BADSIG;

		/* Clean up */
endCheckSignatureInfo:
		deleteMessageDigest( &hash );
		sMemClose( &inputStream );
		}
endCheckSignature:
	zeroise( &hashQueryInfo, sizeof( CRYPT_QUERY_INFO ) );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*				Import/Export a Conventional or PKC-Encrypted Key			*
*																			*
****************************************************************************/

/* Export a conventional-encrypted session key.  This is seperated out from
   the main cryptExportKey() code because the conventional and PKC export
   code is completely different, even though it's called via the same API */

static int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
								  CRYPT_CONTEXT cryptContext,
								  const CRYPT_INFO *sessionKeyInfoPtr )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	STREAM stream;
	BYTE *buffer;
	int status, keyOffset;

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];	/* See note below */

		sMemNullOpen( &nullStream );
		status = writeEncryptedKey( &nullStream, cryptInfoPtr,
									sessionKeyInfoPtr, dummyBuffer,
									sizeofKeyInfo( sessionKeyInfoPtr, TRUE ) );
		*encryptedKeyLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Initialise various things (the use of CRYPT_MAX_PKCSIZE isn't
	   strictly appropriate here, but it's a good indication of the amount
	   of memory needed) */
	if( ( status = secureMalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );

	/* Write the key information into the buffer and encrypt it */
	status = writeKeyInfo( &stream, sessionKeyInfoPtr, &keyOffset, TRUE );
	if( cryptStatusOK( status ) )
		{
		/* Copy the key in at the last possible moment, then encrypt it */
		memcpy( buffer + keyOffset, sessionKeyInfoPtr->userKey,
				sessionKeyInfoPtr->userKeyLength );
		status = cryptEncrypt( cryptContext, buffer, sMemSize( &stream ) );
		}

	/* Now write the encrypted key to the output stream */
	if( cryptStatusOK( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeEncryptedKey( &outputStream, cryptInfoPtr,
									sessionKeyInfoPtr, buffer,
									sMemSize( &stream ) );
		*encryptedKeyLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	secureFree( ( void ** ) &buffer );
	sMemClose( &stream );
	return( status );
	}

/* Export an encrypted session key */

CRET cryptExportKey( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					 const CRYPT_CONTEXT cryptContext,
					 const CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CRYPT_INFO *sessionKeyInfoPtr = CONTEXT_TO_INFO( sessionKeyContext );
	CRYPT_ALGO cryptAlgo;
	STREAM stream;
	BYTE *buffer;
	int length, status, payloadSize, i;

	/* Perform basic error checking */
	if( encryptedKeyLength == NULL )
		return( CRYPT_BADPARM2 );
	if( isBadCookie( cryptContext ) || \
		cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM3 );
	if( isBadCookie( sessionKeyContext ) || \
		sessionKeyInfoPtr->checkValue != CRYPT_MAGIC || \
		sessionKeyInfoPtr->isPKCcontext || \
		sessionKeyInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE )
		return( CRYPT_BADPARM4 );
	cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	if( !cryptInfoPtr->keySet || \
		( cryptAlgo != CRYPT_ALGO_DH && !sessionKeyInfoPtr->keySet ) )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* If it's a conventional encryption context, export it as such */
	if( !cryptInfoPtr->isPKCcontext )
		return( exportConventionalKey( encryptedKey, encryptedKeyLength,
									   cryptContext, sessionKeyInfoPtr ) );

	/* Evaluate the size of the encrypted information if it's a conventional
	   PKC and make sure the key is long enough to encrypt the payload.
	   PKCS #1 requires that the maximum payload size be 11 bytes less than
	   the length (to give a minimum of 8 bytes of random padding) */
	length = bitsToBytes( cryptInfoPtr->keySizeBits );
	if( cryptAlgo != CRYPT_ALGO_DH )
		{
		payloadSize = sizeofKeyInfo( sessionKeyInfoPtr, FALSE );
		if( payloadSize > length - 11 )
			return( CRYPT_DATASIZE );
		}

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];

		sMemNullOpen( &nullStream );
		status = writePKCEncryptedKey( &nullStream, cryptInfoPtr,
									   sessionKeyInfoPtr, dummyBuffer, length );
		*encryptedKeyLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Initialise various things */
	if( ( status = secureMalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	sMemOpen( &stream, buffer, length );

	/* Diffie-Hellman and conventional PKC's are treated slightly
	   differently since DH can't embed information in the shared secret */
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		/* For Diffie-Hellman we can't convey any information in the
		   encrypted data, so we simply encrypt a buffer full of random data */
		for( i = 0; i < length; i++ )
			sputc( &stream, getRandomByte() );
		buffer[ 0 ] |= 0x80;	/* Make the random value as big as possible */
		status = cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr,
													buffer, CRYPT_UNUSED );
		}
	else
		{
		int keyOffset;

		/* Encode the payload using the format given in PKCS #1.  The format
		   for encrypted data is [ 0 ][ 2 ][ nonzero random padding ][ 0 ]
		   [ payload ] which is done by the following code.  Note that the
		   random padding is a nice place for a subliminal channel,
		   especially with large public key sizes where you can communicate
		   more information in the padding than in the payload */
		sputc( &stream, 0 );
		sputc( &stream, 2 );
		for( i = 0; i < length - ( payloadSize + 3 ); i++ )
			{
			register int ch;	/* Try and keep it out of memory */

			/* Insert subliminal channel here */
			while( ( ch = getRandomByte() ) == 0 );
			sputc( &stream, ch );
			}
		sputc( &stream, 0 );
		status = writeKeyInfo( &stream, sessionKeyInfoPtr, &keyOffset, FALSE );

		/* Write the key into the buffer and encrypt it */
		if( cryptStatusOK( status ) )
			{
			/* Copy the key in at the last possible moment, then encrypt it */
			memcpy( buffer + keyOffset, sessionKeyInfoPtr->userKey,
					sessionKeyInfoPtr->userKeyLength );
			status = cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr,
													buffer, CRYPT_UNUSED );
			}
		}

	/* Now write the encrypted key to the output stream */
	if( cryptStatusOK( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writePKCEncryptedKey( &outputStream, cryptInfoPtr,
									   sessionKeyInfoPtr, buffer, length );
		*encryptedKeyLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	secureFree( ( void ** ) &buffer );
	sMemClose( &stream );
	return( status );
	}

/* Import a conventional-encrypted session key.  This is seperated out from
   the main cryptImportKey() code because the conventional and PKC export
   code is completely different, even though it's called via the same API */

static int importConventionalKey( void *encryptedKey,
								  CRYPT_INFO *cryptInfoPtr,
								  CRYPT_CONTEXT *sessionKeyContext )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	STREAM stream;
	BYTE *buffer;
	int status, keyInfoLength;

	/* Initialise various things */
	if( ( status = secureMalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );

	/* Read the encrypted key record up to the start of the encrypted key */
	status = readEncryptedKey( &stream, cryptInfoPtr, &cryptObjectInfo,
							   &keyInfoLength );
	if( status == CRYPT_BADPARM )
		/* Make the error code more specific if we're passed the wrong
		   encryption context to decrypt the key */
		status = CRYPT_BADPARM2;

	/* Extract the encrypted key from the buffer and decrypt it */
	if( !cryptStatusError( status ) && \
		cryptStatusOK( status = loadIV( cryptInfoPtr, cryptObjectInfo.iv,
										cryptObjectInfo.ivSize ) ) )
		{
		memcpy( buffer, ( BYTE * ) encryptedKey + sMemSize( &stream ),
				keyInfoLength );
		status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
													buffer, keyInfoLength );
		}
	sMemDisconnect( &stream );

	/* Create an encryption context loaded with keying information from the
	   decrypted buffer contents */
	if( cryptStatusOK( status ) )
		{
		STREAM inputStream;

		sMemConnect( &inputStream, buffer, keyInfoLength );
		status = readKeyInfo( &inputStream, sessionKeyContext );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */
		sMemClose( &inputStream );
		}
	secureFree( ( void ** ) &buffer );

	/* Set the control vector from the information in the EncryptedKey record
	   and make sure the key cookie matches the one generated from the key */
	if( cryptStatusOK( status ) )
		{
		CRYPT_INFO *sessionKeyInfoPtr = CONTEXT_TO_INFO( *sessionKeyContext );

		sessionKeyInfoPtr->controlVector = cryptObjectInfo.controlVector;
		if( cryptObjectInfo.cookieSize && \
			memcmp( sessionKeyInfoPtr->keyCookie, cryptObjectInfo.cookie,
					KEY_COOKIE_SIZE ) )
			status = CRYPT_WRONGKEY;
		}

	return( status );
	}

/* Import a PKC-encrypted session key */

CRET cryptImportKey( void CPTR encryptedKey,
					 const CRYPT_CONTEXT cryptContext,
					 CRYPT_CONTEXT CPTR sessionKeyContext )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_ALGO cryptAlgo;
	STREAM stream;
	BYTE *buffer;
	int length, status;

	/* Perform basic error checking */
	if( encryptedKey == NULL )
		return( CRYPT_BADPARM1 );
	if( isBadCookie( cryptContext ) || \
		cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM2 );
	if( sessionKeyContext == NULL )
		return( CRYPT_BADPARM3 );
	if( !cryptInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* If it's a conventional encryption context, import it as such */
	if( !cryptInfoPtr->isPKCcontext )
		return( importConventionalKey( encryptedKey, cryptInfoPtr,
									   sessionKeyContext ) );

	/* We can't decrypt with a public key */
	if( cryptInfoPtr->isPublicKey )
		return( CRYPT_BADPARM2 );

	/* Initialise various things */
	if( ( status = secureMalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	length = bitsToBytes( cryptInfoPtr->keySizeBits );
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );

	/* Read the encrypted key record up to the start of the encrypted key */
	status = readPKCEncryptedKey( &stream, cryptInfoPtr, sessionKeyContext,
								  &cryptObjectInfo );
	if( cryptStatusError( status ) )
		goto endImportKey;

	/* Extract the encrypted key from the buffer and decrypt it */
	memcpy( buffer, ( BYTE * ) encryptedKey + sMemSize( &stream ), length );
	status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
													buffer, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		/* If it's a DH key object, the conventional encryption context will
		   already have been created so we need to delete it before we exit */
		if( cryptAlgo == CRYPT_ALGO_DH )
			cryptDestroyContext( *sessionKeyContext );
		goto endImportKey;
        }

	/* Diffie-Hellman and conventional PKC's are treated slightly differently
	   since DH can't embed information in the shared secret */
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		CRYPT_INFO *sessionKeyInfoPtr = CONTEXT_TO_INFO( *sessionKeyContext );
		CRYPT_QUERY_INFO cryptQueryInfo;
		int keyLength;

		/* Find out how much of the shared secret we can use for the key */
		cryptQueryContext( *sessionKeyContext, &cryptQueryInfo );
		keyLength = min( length, cryptQueryInfo.maxKeySize );
		zeroise( &cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) );

		/* Make sure the shared secret is cleared as soon as possible */
		sessionKeyInfoPtr->clearBuffer = TRUE;

		/* Diffie-Hellman merely establishes a shared secret (the crypt
		   context creation is done from the information stored in the
		   encrypted key record), so all that's left to do is to load the key
		   into the encryption context from the least-significant bytes of
		   the shared secret */
		status = cryptLoadContext( *sessionKeyContext,
								   buffer + length - keyLength, keyLength );
		if( cryptStatusError( status ) )
			cryptDestroyContext( *sessionKeyContext );
		sessionKeyInfoPtr->clearBuffer = FALSE;
		}
	else
		{
		STREAM inputStream;
		int ch, i;

		/* Undo the PKCS #1 padding.  The PKCS format for encrypted data is
		   [ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ] which is
		   checked for by the following code */
		sMemConnect( &inputStream, buffer, length );
		if( sgetc( &inputStream ) != 0 || sgetc( &inputStream ) != 2 )
			{
			status = CRYPT_BADDATA;
			goto endImportPKCKey;
			}
		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &inputStream ) ) == 0 )
				break;
		if( ch != 0 )
			{
			status = CRYPT_BADDATA;
			goto endImportPKCKey;
			}

		/* Create an encryption context loaded with keying information from
		   the decrypted buffer contents */
		status = readKeyInfo( &inputStream, sessionKeyContext );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* The readXXX() functions return a byte count */
endImportPKCKey:
		sMemClose( &inputStream );
		}

	/* Set the control vector from the information in the PKCEncryptedKey
	   record and make sure the key cookie matches the one generated from the
	   key */
	if( cryptStatusOK( status ) )
		{
		CRYPT_INFO *sessionKeyInfoPtr = CONTEXT_TO_INFO( *sessionKeyContext );

		sessionKeyInfoPtr = CONTEXT_TO_INFO( *sessionKeyContext );
		sessionKeyInfoPtr->controlVector = cryptObjectInfo.controlVector;
		if( cryptAlgo != CRYPT_ALGO_DH && cryptObjectInfo.cookieSize && \
			memcmp( sessionKeyInfoPtr->keyCookie, cryptObjectInfo.cookie,
					KEY_COOKIE_SIZE ) )
			status = CRYPT_WRONGKEY;
		}

	/* Clean up */
endImportKey:
	secureFree( ( void ** ) &buffer );
	sMemDisconnect( &stream );
	return( status );
	}
