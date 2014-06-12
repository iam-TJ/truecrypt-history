#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capi.h"

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */
#ifndef SEEK_SET
  #define SEEK_SET		0
  #define SEEK_CUR		1
  #define SEEK_END		2
#endif /* SEEK_SET */

/* The names of the test external public and private key files */

#define PGP_PUBKEY_FILE		"keymgmt/testpgp.pub"
#define PGP_PRIVKEY_FILE	"keymgmt/testpgp.prv"
#define X509_PUBKEY_FILE	"keymgmt/testx509.pub"
#define X509_PRIVKEY_FILE	"keymgmt/serverke.der"

/* The password for the test key */

#define KEY_PASSWORD		"test"

/* Various useful types */

typedef unsigned char	BYTE;

/* The encryption routines need to be careful about cleaning up allocated
   memory which contains sensitive information.  Ideally we would throw an
   exception which takes care of this, but we can't really do this without
   assuming a C++ compiler.  As a tradeoff the following macro, which just
   evaluates to a goto, is used to indicate that we'd do something nicer
   here if we could */

#define THROW( x )	goto x

/****************************************************************************
*																			*
*				Sample Application - Encrypt and Sign a File				*
*																			*
****************************************************************************/

/* Take an input file, sign it if necessary, encrypt it if necessary, and
   write the result to an output file.  This function can produce any of:

	- A raw data object
	- A signed data object
	- A conventionally encrypted data object
	- A public-key encrypted data object
	- A conventionally encrypted, signed data object
	- A public-key encrypted, signed data object

   depending on whether the signContext and cryptContext parameters are
   empty or contain valid signature/encryption contexts.

   This function makes extensive use of the cryptlib object management
   functions to ease the processing of the various objects */

int wrapFile( FILE *inFile, FILE *outFile, CRYPT_CONTEXT signContext,
			  CRYPT_CONTEXT cryptContext, CRYPT_ALGO cryptAlgo )
	{
	CRYPT_CONTEXT sessionKeyContext = 0, hashContext = 0;
	CRYPT_IOCTLINFO_COOKIE cryptIoctlInfo;
	BYTE *objectBuffer = NULL, *encryptedObject, *signedObject, *dataObject;
	BYTE *signature;
	int exportedKeySize = 0, encryptedObjectSize = 0, signedObjectSize = 0;
	int dataObjectSize, objectSize, signatureSize = 0, status = CRYPT_ERROR;
	long dataLength;

	/* Find out how big the input file is */
	fseek( inFile, 0, SEEK_END );
	dataLength = ftell( inFile );
	fseek( inFile, 0, SEEK_SET );

	/* Create an encryption context for the session key and a session key if
	   we want to encrypt and a hash context for the signature if we want to
	   sign the data */
	if( cryptContext )
		{
		status = cryptCreateContext( &sessionKeyContext, cryptAlgo, CRYPT_MODE_CFB );
		if( cryptStatusError( status ) )
			return( status );
		status = cryptGenerateContext( sessionKeyContext );
		if( cryptStatusError( status ) )
			THROW( exception );
		}
	if( signContext )
		{
		status = cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Since the Signature object directly follows the SignedData object
		   we don't bother exporting the signature cookie.  If we were using
		   a detached signature we would use the default behaviour of
		   exporting the cookie */
		cryptIoctlInfo.exportCookie = 0;
		cryptIoctl( CRYPT_IOCTL_SIGCOOKIE, &cryptIoctlInfo, hashContext );
		}

	/* Find out how big the various objects will be.  Note the way we
	   determine the size of the nested objects: First the inner RawData
	   object, then the SignedData object surrounding it, then the
	   EncryptedData object surrounding that */
	cryptExportObject( NULL, &dataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );
	if( signContext )
		{
		/* SignedData followed by the Signature */
		cryptExportObjectEx( NULL, &signedObjectSize, CRYPT_OBJECT_SIGNED_DATA,
							 dataObjectSize + dataLength, hashContext );
		cryptCreateSignature( NULL, &signatureSize, signContext, hashContext );
		}
	if( cryptContext )
		{
		/* EncryptedKey/PKCEncryptedKey followed by the EncryptedData */
		cryptExportKey( NULL, &exportedKeySize, cryptContext, sessionKeyContext );
		cryptExportObjectEx( NULL, &encryptedObjectSize,
							 CRYPT_OBJECT_ENCRYPTED_DATA, signedObjectSize +
							 dataObjectSize + dataLength + signatureSize,
							 sessionKeyContext );
		}

	/* Allocate a buffer for the various objects and find the locations of
	   each object in the buffer */
	if( ( objectBuffer = malloc( exportedKeySize + encryptedObjectSize +
								 signedObjectSize + dataObjectSize +
								 signatureSize ) ) == NULL )
		THROW( exception );
	encryptedObject = objectBuffer + exportedKeySize;
	signedObject = encryptedObject + encryptedObjectSize;
	dataObject = signedObject + signedObjectSize;
	signature = dataObject + dataObjectSize;

	/* Export the session key */
	if( cryptContext )
		{
		status = cryptExportKey( objectBuffer, &exportedKeySize, cryptContext,
								 sessionKeyContext );
		if( cryptStatusError( status ) )
			THROW( exception );
		}

	/* Assemble the EncryptedData, SignedData, and RawData objects */
	if( cryptContext )
		cryptExportObjectEx( encryptedObject, &encryptedObjectSize,
							 CRYPT_OBJECT_ENCRYPTED_DATA, signedObjectSize +
							 dataObjectSize + dataLength + signatureSize,
							 sessionKeyContext );
	if( signContext )
		cryptExportObjectEx( signedObject, &signedObjectSize,
							 CRYPT_OBJECT_SIGNED_DATA, dataObjectSize +
							 dataLength, hashContext );
	cryptExportObject( dataObject, &dataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );

	/* Hash the start of the RawData object and encrypt the start of the
	   SignedData object */
	if( signContext )
		cryptEncrypt( hashContext, dataObject, dataObjectSize );
	if( cryptContext )
		cryptEncrypt( sessionKeyContext, signedObject, signedObjectSize +
					  dataObjectSize );

	/* Write the objects to the output file */
	objectSize = exportedKeySize + encryptedObjectSize + signedObjectSize +
				 dataObjectSize;
	if( fwrite( objectBuffer, 1, objectSize, outFile ) != ( size_t ) objectSize )
		THROW( exception );

	/* Now process the input file which contains the payload portion of the
	   RawData object.  We just read the file in chunks, hash it, encrypt it,
	   and write the result to the output file */
	while( !feof( inFile ) )
		{
		BYTE buffer[ BUFSIZ * 4 ];
		int bufferLength;

		if( ( bufferLength = fread( buffer, 1, BUFSIZ * 4, inFile ) ) == 0 )
			break;
		if( signContext )
			cryptEncrypt( hashContext, buffer, bufferLength );
		if( cryptContext )
			cryptEncrypt( sessionKeyContext, buffer, bufferLength );
		if( fwrite( buffer, 1, bufferLength, outFile ) != ( size_t ) bufferLength )
			THROW( exception );
		}

	/* We've passed the last general exception point, set the return value to
	   OK */
	status = CRYPT_OK;

	/* Complete the hash and create the Signature object */
	if( signContext )
		{
		cryptEncrypt( hashContext, signature, 0 );
		status = cryptCreateSignature( signature, &signatureSize, signContext,
									   hashContext );
		cryptDestroyContext( hashContext );
		hashContext = 0;
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Encrypt the Signature object and write it to the output file */
		if( cryptContext )
			status = cryptEncrypt( sessionKeyContext, signature,
								   signatureSize );
		if( cryptStatusError( status ) )
			THROW( exception );
		if( fwrite( signature, 1, signatureSize, outFile ) != ( size_t ) signatureSize )
			status = CRYPT_ERROR;
		}
	cryptDestroyContext( sessionKeyContext );

	/* Clean up */
	free( objectBuffer );
	return( status );

	/* Exception handlers */
exception:
	if( hashContext )
		cryptDestroyContext( hashContext );
	if( sessionKeyContext )
		cryptDestroyContext( sessionKeyContext );
	if( objectBuffer != NULL )
		free( objectBuffer );
	return( status );
	}

/* Take an input file, unwrap the data objects, decrypt the data we need,
   check the signature, and write the result to an output file.

   This code can't unwrap a standalone raw data object (with no encryption or
   a signature), but this isn't worth fixing since it's been superseded by
   the cryptEnvelope() functions (which, however, aren't present in the 2.00
   release) */

int unwrapFile( FILE *inFile, FILE *outFile, const char *password )
	{
	CRYPT_CONTEXT signContext = 0, decryptContext = 0;
	CRYPT_CONTEXT sessionKeyContext = 0, hashContext = 0;
	CRYPT_OBJECT_INFO cryptObjectInfo;
	BYTE *objectBuffer, *ioBuffer, *dataPtr, *signature;
	int payloadStart, dataInBuffer, count, status = CRYPT_ERROR;
	long payloadSize, dataSize, signatureSize = 0;

	/* Allocate room for the objects and read them into memory */
	if( ( objectBuffer = malloc( 4096 ) ) == NULL )
		return( CRYPT_NOMEM );
	if( ( ioBuffer = malloc( 4096 ) ) == NULL )
		{
		free( objectBuffer );
		return( CRYPT_NOMEM );
		}
	if( ( dataInBuffer = fread( objectBuffer, 1, 4096, inFile ) ) < 50 )
		THROW( exception );
	dataPtr = objectBuffer;

	/* Find out what we've got */
	status = cryptQueryObject( objectBuffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		THROW( exception );

	/* Process an EncryptedData object preceded by an EncryptedKey or
	   PKCEncryptedKey object */
	if( cryptObjectInfo.type == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		cryptObjectInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		CRYPT_KEYSET cryptKeyset;

		/* Open the external key collection and try to read the required key */
		status = cryptExtKeysetOpen( &cryptKeyset, PGP_PRIVKEY_FILE,
									 CRYPT_KEYSET_PGP );
		if( cryptStatusError( status ) )
			THROW( exception );
		status = cryptGetKeyFromObjectEx( cryptKeyset, &decryptContext,
										  dataPtr, password );
		if( cryptStatusError( status ) )
			THROW( exception );
		cryptKeysetClose( cryptKeyset );

		/* Query the encrypted key object to find its size */
		status = cryptImportObject( dataPtr, &payloadStart, &payloadSize );
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Recreate the session key by importing the encrypted key */
		status = cryptImportKey( dataPtr, decryptContext,
								 &sessionKeyContext );
		cryptDestroyContext( decryptContext );
		decryptContext = 0;
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Set up the session key to decrypt the encrypted data (there's no
		   payload for an encrypted session key so we don't need to include
		   the payload size in the calculation) */
		dataPtr += payloadStart;
		status = cryptImportObjectEx( dataPtr, &payloadStart, &payloadSize,
									  &sessionKeyContext );
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Decrypt as much of the SignedData or RawData object as we have in
		   the buffer and remember how much we still have to process */
		dataPtr += payloadStart;
		dataInBuffer -= ( int ) ( dataPtr - objectBuffer );
		status = cryptDecrypt( sessionKeyContext, dataPtr, dataInBuffer );
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Adjust the total data size by the amount we've just decrypted */
		dataSize = payloadSize - dataInBuffer;

		/* Find out what's next */
		status = cryptQueryObject( dataPtr, &cryptObjectInfo );
		if( cryptStatusError( status ) )
			THROW( exception );
		}

	/* Process a SignedData object */
	if( cryptObjectInfo.type == CRYPT_OBJECT_SIGNED_DATA )
		{
		/* Import the signed data object */
		status = cryptImportObjectEx( dataPtr, &payloadStart, &payloadSize,
									  &hashContext );
		if( cryptStatusError( status ) )
			THROW( exception );

		/* Hash as much of the RawData object as we have in the buffer and
		   remember how much we still have to process */
		dataInBuffer -= payloadStart;
		dataPtr += payloadStart;
		dataSize = payloadSize - dataInBuffer;
		if( dataSize < 0 )
			{
			/* If we've got some of the Signature object in the buffer,
			   don't hash the signature itself and remember how much of the
			   signature is already present */
			signatureSize = -dataSize;
			signature = dataPtr + ( int ) payloadSize;
			dataSize = 0;
			cryptDecrypt( hashContext, dataPtr, dataInBuffer -
						  ( int ) signatureSize );
			}
		else
			{
			/* Everything in the buffer is SignedData, hash the whole thing */
			signatureSize = 0;
			cryptDecrypt( hashContext, dataPtr, dataInBuffer );
			}

		/* Find out what's next */
		status = cryptQueryObject( dataPtr, &cryptObjectInfo );
		if( cryptStatusError( status ) )
			THROW( exception );
		}

	/* Process a RawData object */
	if( cryptObjectInfo.type != CRYPT_OBJECT_RAW_DATA )
		THROW( exception );

	/* Import the raw data object and write as much of it as we have
	   available to disk */
	status = cryptImportObject( dataPtr, &payloadStart, &payloadSize );
	if( cryptStatusError( status ) )
		THROW( exception );
	count = ( int ) ( dataInBuffer - signatureSize - payloadStart );
	if( fwrite( dataPtr + payloadStart, 1, count, outFile ) != ( size_t ) count )
		THROW( exception );

	/* Now process the input file which contains the payload portion of the
	   RawData object.  We just read the file in chunks, decrypt it, and
	   write the result to the output file */
	while( dataSize )
		{
		int bufferLength = ( int ) ( ( dataSize > BUFSIZ * 4 ) ? \
						   BUFSIZ * 4 : dataSize );

		if( ( bufferLength = fread( ioBuffer, 1, bufferLength, inFile ) ) != bufferLength )
			THROW( exception );
		if( sessionKeyContext )
			cryptDecrypt( sessionKeyContext, ioBuffer, bufferLength );
		if( hashContext )
			cryptDecrypt( hashContext, ioBuffer, bufferLength );
		if( fwrite( ioBuffer, 1, bufferLength, outFile ) != ( size_t ) bufferLength )
			THROW( exception );
		dataSize -= bufferLength;
		}

	/* If the data is signed, read the Signature object which follows the
	   SignedData object and check the signature */
	if( hashContext )
		{
		CRYPT_KEYSET cryptKeyset;

		cryptDecrypt( hashContext, dataPtr, 0 );

		/* If we've already got some of the signature in the buffer, move it
		   to the start of the buffer so we can read in the rest */
		if( signatureSize )
			memmove( objectBuffer, signature, ( size_t ) signatureSize );

		/* Read the Signature object which follows the SignedData object.  We
		   may already have some or all of it in memory from previous reads.
		   The byte-by-byte read isn't terribly elegant, but much easier than
		   a cryptQueryObject() followed by a read of the payload */
		signature = objectBuffer;
		if( !feof( inFile ) )
			{
			int signatureIndex = ( int ) signatureSize;

			/* Read in the rest of the signature */
			while( !feof( inFile ) && signatureIndex < 1024 )
				signature[ signatureIndex++ ] = getc( inFile );
			signatureIndex--;	/* Don't include the EOF */

			/* Decrypt the signature or remainder of the signature */
			if( sessionKeyContext )
				{
				status = cryptDecrypt( sessionKeyContext,
									   signature + ( int ) signatureSize,
									   signatureIndex );
				if( cryptStatusError( status ) )
					THROW( exception );
				}
			}

		/* Open the external key collection and try to read the signature key */
		status = cryptExtKeysetOpen( &cryptKeyset, PGP_PUBKEY_FILE,
									 CRYPT_KEYSET_PGP );
		if( cryptStatusError( status ) )
			THROW( exception );
		status = cryptGetKeyFromObject( cryptKeyset, &signContext,
										signature );
		if( cryptStatusError( status ) )
			THROW( exception );
		cryptKeysetClose( cryptKeyset );

		/* Check the signature */
		status = cryptCheckSignature( signature, signContext, hashContext );
		cryptDestroyContext( hashContext );
		hashContext = 0;
		cryptDestroyContext( signContext );
		signContext = 0;
		if( cryptStatusError( status ) )
			THROW( exception );
		}
	cryptDestroyContext( sessionKeyContext );

	/* Clean up */
	free( objectBuffer );
	return( CRYPT_OK );

	/* Exception handlers */
exception:
	if( decryptContext )
		cryptDestroyContext( decryptContext );
	if( signContext )
		cryptDestroyContext( signContext );
	if( hashContext )
		cryptDestroyContext( hashContext );
	if( sessionKeyContext )
		cryptDestroyContext( sessionKeyContext );
	memset( objectBuffer, 0, 4096 );
	free( objectBuffer );
	memset( ioBuffer, 0, 4096 );
	free( ioBuffer );
	return( status );
	}

/* Despite the fact that the above is meant only as a cryptlib demo, it's
   probably going to appear in God knows how many pieces of production
   code... */

/****************************************************************************
*																			*
*							Test Routines for File Functions				*
*																			*
****************************************************************************/

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#ifdef __MSDOS__
  extern unsigned _stklen = 10240;
#endif /* __MSDOS__ */

/* The main program to exercise the encryption code */

#if defined( _WINDOWS ) || defined( _WIN32 ) || defined( WIN32 )
  #define __WINDOWS__
#endif /* _WINDOWS || _WIN32 || WIN32 */

void getPassword( const char *prompt, char *password )
	{
	printf( "Please enter %s: ", prompt );
	fflush( stdout );
	fgets( password, 200, stdin );
	password[ strlen( password ) - 1 ] = '\0';
	}

int main( int argc, char **argv )
	{
	CRYPT_CONTEXT cryptContext = 0, signContext = 0;
	CRYPT_KEYSET cryptKeyset;
	FILE *inFile, *outFile;
	char *encryptID = NULL, *signID = NULL;
	char password[ 200 ];
	int status, encrypt = 1;

	/* Process the input parameters */
	if( argc < 3 || argc > 5 )
		{
		puts( "Usage: testapp [-c] [-e<userID>] [-s<userID>] [-d]" );
		puts( "       <infile> <outfile>" );
		puts( "       -c = conventional encrypt" );
		puts( "       -e = encrypt with key for <userID>" );
		puts( "       -d = decrypt and/or check signature" );
		puts( "       -s = sign with key for <userID>" );
		puts( "" );
		puts( "       Example: testapp -c input cipher" );
		puts( "                - Conventionally encrypt input, write result to cipher." );
		puts( "       Example: testapp -eyourkey -smykey input cipher" );
		puts( "                - Encrypt + sign input, write result to cipher." );
		puts( "       Example: testapp -d cipher outfile" );
		puts( "                - Decrypt + sig check prev.file, write result to outfile." );
		return( EXIT_FAILURE );
		}

	/* Initialise the library (not necessary for a DLL) */
#ifndef __WINDOWS__
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		return( EXIT_FAILURE );
		}
#endif /* !__WINDOWS__ */

	/* Check for arguments */
	while( *argv[ 1 ] == '-' )
		{
		char *argPtr = argv[ 1 ] + 1;

		switch( toupper( *argPtr ) )
			{
			case 'C':
				/* Perform basic error checking */
				if( cryptContext )
					break;

				/* Get the passphrase and convert it to an encryption key */
				getPassword( "encryption password", password );
				cryptCreateContext( &cryptContext, CRYPT_ALGO_3DES,
									CRYPT_MODE_CFB );
				status = cryptDeriveKey( cryptContext, password,
										 strlen( password ) );
				memset( password, 0, 200 );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't build encryption key from password, "
							"error code %d\n", status );
					return( EXIT_FAILURE );
					}
				break;

			case 'E':
				/* Perform basic error checking */
				if( cryptContext )
					break;
				encryptID = argPtr + 1;
				if( !strlen( encryptID ) )
					{
					puts( "You must specify a user ID to encrypt the file." );
					return( EXIT_FAILURE );
					}

				/* Open the external key collection and try to read the
				   required key */
				status = cryptExtKeysetOpen( &cryptKeyset, PGP_PUBKEY_FILE,
											 CRYPT_KEYSET_PGP );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't open public key file %s, error code %d.\n",
							PGP_PUBKEY_FILE, status );
					return( EXIT_FAILURE );
					}
				status = cryptGetKey( cryptKeyset, &cryptContext, encryptID );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't get public key for %s, error code %d\n",
							encryptID, status );
					return( EXIT_FAILURE );
					}
				cryptKeysetClose( cryptKeyset );
				break;

			case 'D':
				/* Get the private key password.  This may not be necessary
				   if the data isn't encrypted, but at the moment there's no
				   clean mechanism for providing feedback at the unwrapfile
				   level */
				getPassword( "decryption key password", password );
				encrypt = 0;
				break;

			case 'S':
				/* Perform basic error checking */
				if( signContext )
					break;
				signID = argPtr + 1;
				if( !strlen( signID ) )
					{
					puts( "You must specify a user ID to sign the file." );
					return( EXIT_FAILURE );
					}

				/* Open the external key collection and try to read the
				   required key */
				status = cryptExtKeysetOpen( &cryptKeyset, PGP_PRIVKEY_FILE,
											 CRYPT_KEYSET_PGP );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't open private key file %s, error code %d.\n",
							PGP_PRIVKEY_FILE, status );
					return( EXIT_FAILURE );
					}
				status = cryptGetKeyEx( cryptKeyset, &signContext, signID, NULL );
				if( status == CRYPT_WRONGKEY )
					{
					/* We need a password for this private key, get it from
					   the user and get the key again */
					getPassword( "signature key password", password );
					status = cryptGetKeyEx( cryptKeyset, &signContext,
											signID, password );
					}
				memset( password, 0, 200 );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't get private key for %s, error code %d\n",
							signID, status );
					return( EXIT_FAILURE );
					}
				cryptKeysetClose( cryptKeyset );
				break;

			case 'T':
				/* Perform basic error checking */
				if( cryptContext )
					break;
				encryptID = argPtr + 1;
				if( !strlen( encryptID ) )
					{
					puts( "You must specify a user ID for the test key." );
					return( EXIT_FAILURE );
					}

				/* Undocumented test mode to check readability of various
				   unusual X.509-related key file formats */
#ifdef TEST_PUB
				status = cryptExtKeysetOpen( &cryptKeyset, X509_PUBKEY_FILE,
											 CRYPT_KEYSET_X509 );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't open public key file %s, error code %d.\n",
							X509_PUBKEY_FILE, status );
					return( EXIT_FAILURE );
					}
				status = cryptGetKey( cryptKeyset, &cryptContext, encryptID );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't get public key for %s, error code %d\n",
							encryptID, status );
					return( EXIT_FAILURE );
					}
#else
				status = cryptExtKeysetOpen( &cryptKeyset, X509_PRIVKEY_FILE,
											 CRYPT_KEYSET_X509 );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't open private key file %s, error code %d.\n",
							X509_PRIVKEY_FILE, status );
					return( EXIT_FAILURE );
					}
				status = cryptGetKeyEx( cryptKeyset, &cryptContext, encryptID,
										NULL );
				if( cryptStatusError( status ) )
					{
					printf( "Couldn't get private key for %s, error code %d\n",
							encryptID, status );
					return( EXIT_FAILURE );
					}
#endif /* TEST_PUB */
				cryptKeysetClose( cryptKeyset );
				break;

			default:
				printf( "Unknown arg '%c'.\n", argPtr );
				return( EXIT_FAILURE );
			}

		argv++;
		}

	/* Open the input and output files */
	if( ( inFile = fopen( argv[ 1 ], "rb" ) ) == NULL )
		{
		perror( argv[ 1 ] );
		return( EXIT_FAILURE );
		}
	if( ( outFile = fopen( argv[ 2 ], "wb" ) ) == NULL )
		{
		fclose( inFile );
		perror( argv[ 2 ] );
		return( EXIT_FAILURE );
		}

	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk - it doesn't
	   matter here because we're not worried about security, but should never
	   be done in production code */
	cryptAddRandom( "a", 1 );

	/* Encrypt or decrypt the data */
	if( encrypt )
		/* Wrap up the data */
#ifdef USE_ENVELOPES
		{
		cryptCreateEnvelope( &cryptEnvelope, fsize( inFile ), 16384 );
		if( signContext )
			cryptAddKey( cryptEnvelope, CRYPT_ENVKEY_SIGNATURE, signKey );
		if( cryptContext )
			cryptAddKey( cryptEnvelope, CRYPT_ENVKEY_PKCKEY, cryptContext );
		while( !feof( inFile ) )
			{
			if( ( bufferLength = fread( buffer, 1, 16384, inFile ) ) == 0 )
				break;
			cryptEnvelopePush( cryptEnvelope, buffer, bufferLength );
			cryptEnvelopePop( cryptEnvelope, buffer, bufferLength );
			fwrite( buffer, 1, bufferLength, outFile );
			}
		cryptDestroyEnvelope( cryptEnvelope );
		}
#else
		status = wrapFile( inFile, outFile, signContext, cryptContext,
						   CRYPT_ALGO_3DES );
#endif /* USE_ENVELOPES */
	else
		/* Unwrap the data */
		status = unwrapFile( inFile, outFile, password );

	/* Clean up */
	if( cryptContext )
		cryptDestroyContext( cryptContext );
	if( signContext )
		cryptDestroyContext( signContext );
	fclose( inFile );
	fclose( outFile );
	if( cryptStatusError( status ) )
		{
		printf( "%s failed with error code %d\n", ( encrypt ) ? \
				"wrapFile()" : "unwrapFile()", status );
		return( EXIT_FAILURE );
		}

	/* Clean up */
#ifndef __WINDOWS__
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "cryptEnd() failed with error code %d.\n", status );
		return( EXIT_FAILURE );
		}
#endif /* !__WINDOWS__ */
	if( encrypt )
		{
		if( signID )
			printf( "File was signed by %s.\n", signID );
		if( encryptID )
			printf( "File was encrypted for %s.\n", encryptID );
		if( !signID && !encryptID )
			puts( "File was encapsulated as raw data." );
		}
	else
		printf( "File decryption succeeded.\n" );
	return( EXIT_SUCCESS );
	}
