#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capi.h"

/* The key size to use for the PKC routines */

#define PKC_KEYSIZE			512

/* Various useful types */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* Prototypes for functions in testlib.c */

BOOLEAN loadRSAContexts( CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize );
void destroyContexts( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext );

/****************************************************************************
*																			*
*							High-level Routines Test						*
*																			*
****************************************************************************/

/* Print a cookie and key ID */

static void printCookie( CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int i;

	for( i = 0; i < cryptObjectInfo->cookieSize; i++ )
		printf( "%02X", cryptObjectInfo->cookie[ i ] );
	putchar( '\n' );
	}

static void printKeyID( CRYPT_OBJECT_INFO *cryptObjectInfo )
	{
	int i;

	for( i = 0; i < cryptObjectInfo->keyIDsize; i++ )
		printf( "%02X", cryptObjectInfo->keyID[ i ] );
	putchar( '\n' );
	}

/* Test the randomness gathering routines */

int testRandomRoutines( void )
	{
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing randomness routines.  This may take a few seconds..." );

	/* Create an encryption context to generate a key into */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );
	status = cryptGenerateContext( cryptContext );
	cryptDestroyContext( cryptContext );

	/* Check whether we got enough randomness */
	if( status == CRYPT_NORANDOM )
		{
		puts( "The randomness-gathering routines in the library can't acquire enough" );
		puts( "random information to allow key generation and public-key encryption to" );
		puts( "function.  You will need to change lib_rand.c or reconfigure your system" );
		puts( "to allow the randomness-gathering routines to function.\n" );
		return( FALSE );
		}

	puts( "Randomness-gathering self-test succeeded.\n" );
	return( TRUE );
	}

/* Test the high-level code to derive a fixed-length encryption key from a
   variable-length user key */

int testDeriveKey( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	BYTE buffer[ 8 ];
	int userKeyLength = strlen( ( char * ) userKey ), status;

	puts( "Testing key derivation..." );

	/* Create DES encryption and decryption contexts */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );
	cryptCreateContext( &decryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );

	/* Load a DES key derived from a user key into both contexts */
	status = cryptDeriveKey( cryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d\n", status );
		return( FALSE );
		}
	status = cryptDeriveKey( decryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d\n", status );
		return( FALSE );
		}

	/* Encrypt the data with one derived key and make sure it decrypts with
	   the other */
	memcpy( buffer, "12345678", 8 );
	status = cryptEncrypt( cryptContext, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "Encryption with derived key failed with error code %d\n",
				status );
		return( FALSE );
		}
	status = cryptDecrypt( decryptContext, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "Decryption with derived key failed with error code %d\n",
				status );
		return( FALSE );
		}
	destroyContexts( cryptContext, decryptContext );
	if( memcmp( buffer, "12345678", 8 ) )
		{
		puts( "Data decrypted with derived key != plaintext encrypted with "
			  "derived key." );
		return( FALSE );
		}

	puts( "Generation of key via cryptDeriveKey() succeeded.\n" );
	return( TRUE );
	}

/* Test the high-level code to export/import an encrypted key via
   conventional encryption.  This demonstrates the ability to use one context
   type to export another - we export a triple DES key using Blowfish.  We're
   not as picky with error-checking here since most of the functions have
   just executed successfully */

int testConventionalExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext;
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	BYTE *buffer;
	int userKeyLength = strlen( ( char * ) userKey );
	int status, length;

	puts( "Testing conventional key export/import..." );

	/* Create a triple-DES encryption context for the session key */
	cryptCreateContext( &sessionKeyContext, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptGenerateContext( sessionKeyContext );

	/* Create a Blowfish encryption context to export the session key */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB );
	cryptDeriveKey( cryptContext, userKey, userKeyLength );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes long\n",
			length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session information */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes,\n"
			"\talgorithm %d, mode %d, key derivation done with %d iterations of\n"
			"\talgorithm %d.\n", cryptObjectInfo.type,
			cryptObjectInfo.size, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode, cryptObjectInfo.keySetupIterations,
			cryptObjectInfo.keySetupAlgo );
#ifdef WRITE_OBJECTS
	fwrite( buffer, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */

	/* Destroy the session key encryption context, then recreate it by
	   importing the encrypted key */
	cryptDestroyContext( sessionKeyContext );
	status = cryptCreateContextEx( &decryptContext,
								   cryptObjectInfo.cryptAlgo,
								   cryptObjectInfo.cryptMode,
								   cryptObjectInfo.cryptContextExInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}
	cryptDeriveKeyEx( decryptContext, userKey, userKeyLength,
					  cryptObjectInfo.keySetupAlgo,
					  cryptObjectInfo.keySetupIterations );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	status = cryptImportKey( buffer, decryptContext, &sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( sessionKeyContext );
	destroyContexts( cryptContext, decryptContext );
	printf( "Export/import of Blowfish key via user-key-based triple DES "
			"conventional\n  encryption succeeded.\n\n" );
	free( buffer );
	return( TRUE );
	}

/* Test the high-level code to export/import an encrypted key.  We're not as
   picky with error-checking here since most of the functions have just
   executed successfully */

int testKeyExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext;
	BYTE *buffer;
	int status, length;

	puts( "Testing public-key export/import..." );

	/* Create a triple-DES encryption context for the session key */
	cryptCreateContext( &sessionKeyContext, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptGenerateContext( sessionKeyContext );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( &cryptContext, &decryptContext ) )
		return( FALSE );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes long\n",
			length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session key */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.type,
			cryptObjectInfo.size, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	printf( "Key ID for decryption is " );
	printKeyID( &cryptObjectInfo );
#ifdef WRITE_OBJECTS
	fwrite( buffer, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Destroy the session key encryption context, then recreate it by
	   importing the encrypted key */
	cryptDestroyContext( sessionKeyContext );
	status = cryptImportKey( buffer, decryptContext, &sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( sessionKeyContext );
	destroyContexts( cryptContext, decryptContext );
	printf( "Export/import of session key via %d-bit RSA-encrypted data "
			"block succeeded.\n\n", PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

/* Test the high-level code to sign data.  We're not as picky with
   error-checking here since most of the functions have just executed
   successfully */

int testSignData( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT signContext, checkContext;
	CRYPT_CONTEXT hashContext;
	BYTE *buffer, hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";
	int status, length;

	puts( "Testing digital signatures..." );

	/* Create an SHA hash context and hash the test buffer */
	cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	cryptEncrypt( hashContext, hashBuffer, 26 );
	cryptEncrypt( hashContext, hashBuffer, 0 );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( &checkContext, &signContext ) )
		return( FALSE );

	/* Find out how big the signature will be */
	status = cryptCreateSignature( NULL, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d\n", status );
		return( FALSE );
		}
	printf( "cryptCreateSignature() reports signature object will be %d bytes long\n",
			length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Sign the hashed data */
	status = cryptCreateSignature( buffer, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Query the signed object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.type,
			cryptObjectInfo.size, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	printf( "Key ID for signature check key is " );
	printKeyID( &cryptObjectInfo );
#ifdef WRITE_OBJECTS
	fwrite( buffer, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Check the signature on the hash */
	status = cryptCheckSignature( buffer, checkContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCheckSignature() failed with error code %d\n", status );
		free( buffer );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( hashContext );
	destroyContexts( checkContext, signContext );
	printf( "Generation and checking of RSA digital signature via %d-bit "
			"data block\n  succeeded.\n\n", PKC_KEYSIZE );
		free( buffer );
	return( TRUE );
	}

/* Test the high-level code to exchange a session key via Diffie-Hellman.
   We're not as picky with error-checking here since most of the functions
   have just executed successfully */

int testKeyExchange( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext1, cryptContext2;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer1, *buffer2;
	int length1, length2, status1, status2;

	puts( "Testing key agreement..." );

	/* Create the DH encryption contexts */
	if( !loadDHContexts( &cryptContext1, &cryptContext2, PKC_KEYSIZE ) )
		return( FALSE );

	/* Create the session key context */
	cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );

	/* Find out how big the exported key will be */
	status1 = cryptExportKey( NULL, &length1, cryptContext1, sessionKeyContext1 );
	if( cryptStatusError( status1 ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status1 );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes long\n",
			length1 );
	if( ( buffer1 = malloc( length1 ) ) == NULL || \
		( buffer2 = malloc( length1 ) ) == NULL )
		return( FALSE );

	/* Create the integer public values */
	status1 = cryptExportKey( buffer1, &length1, cryptContext1, sessionKeyContext1 );
	status2 = cryptExportKey( buffer2, &length2, cryptContext2, sessionKeyContext1 );
	cryptDestroyContext( sessionKeyContext1 );
	if( cryptStatusError( status1 ) )
		{
		printf( "cryptExportKey() #1 failed with error code %d\n", status1 );
		free( buffer1 );
		free( buffer2 );
		return( FALSE );
		}
	if( cryptStatusError( status2 ) )
		{
		printf( "cryptExportKey() #2 failed with error code %d\n", status2 );
		free( buffer1 );
		free( buffer2 );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status1 = cryptQueryObject( buffer1, &cryptObjectInfo );
	if( cryptStatusError( status1 ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status1 );
		free( buffer1 );
		free( buffer2 );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.type,
			cryptObjectInfo.size, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	printf( "Key ID for exchange key is " );
	printKeyID( &cryptObjectInfo );
#ifdef WRITE_OBJECTS
	fwrite( buffer1, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fwrite( buffer2, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Create the integer secret values */
	status1 = cryptImportKey( buffer2, cryptContext1, &sessionKeyContext1 );
	status2 = cryptImportKey( buffer1, cryptContext2, &sessionKeyContext2 );
	if( cryptStatusError( status1 ) )
		{
		printf( "cryptImportKey() #1 failed with error code %d\n", status1 );
		free( buffer1 );
		free( buffer2 );
		return( FALSE );
		}
	if( cryptStatusError( status2 ) )
		{
		printf( "cryptImportKey() #2 failed with error code %d\n", status2 );
		free( buffer1 );
		free( buffer2 );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( sessionKeyContext1 );
	cryptDestroyContext( sessionKeyContext2 );
	destroyContexts( cryptContext1, cryptContext2 );
	printf( "Exchange of session key via %d-bit Diffie-Hellman succeeded.\n\n",
			PKC_KEYSIZE );
	free( buffer1 );
	free( buffer2 );
	return( TRUE );
	}

/* Test the high-level code to encrypt an object via a PKC-encrypted session
   key.  We're not as picky with error-checking here since most of the
   functions have just executed successfully */

int testEncryptObject( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext;
	BYTE *exportedKey, *encryptedData, *payload;
	BYTE *data = ( BYTE * ) "This is a test string to encrypt";
	int encryptedDataObjectSize, rawDataObjectSize, payloadStart;
	int status, exportedKeyLength, dataLength = 33;
	long payloadSize;

	puts( "Testing encrypted object exchange..." );

	/* Create a triple-DES encryption context for the session key */
	cryptCreateContext( &sessionKeyContext, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptGenerateContext( sessionKeyContext );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( &cryptContext, &decryptContext ) )
		return( FALSE );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &exportedKeyLength, cryptContext,
							 sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes long\n",
			exportedKeyLength );
	if( ( exportedKey = malloc( exportedKeyLength ) ) == NULL )
		return( FALSE );

	/* Export the session key */
	status = cryptExportKey( exportedKey, &exportedKeyLength, cryptContext,
							 sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d\n", status );
		free( exportedKey );
		return( FALSE );
		}

	/* Find out how large the encrypted data object will be and allocate
	   room for it */
	cryptExportObject( NULL, &rawDataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );
	cryptExportObjectEx( NULL, &encryptedDataObjectSize,
						 CRYPT_OBJECT_ENCRYPTED_DATA, rawDataObjectSize +
						 dataLength, sessionKeyContext );
	if( ( encryptedData = malloc( encryptedDataObjectSize +
								  rawDataObjectSize + dataLength ) ) == NULL )
		{
		free( exportedKey );
		return( FALSE );
		}

	/* Wrap up the sample data inside the RawData object */
	cryptExportObject( encryptedData + encryptedDataObjectSize,
					   &rawDataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );
	memcpy( encryptedData + encryptedDataObjectSize + rawDataObjectSize,
			data, dataLength );

	/* Then wrap it up in the EncryptedData object and encrypt the
	   encapsulated part */
	cryptExportObjectEx( encryptedData, &encryptedDataObjectSize,
						 CRYPT_OBJECT_ENCRYPTED_DATA, rawDataObjectSize +
						 dataLength, sessionKeyContext );
	cryptEncrypt( sessionKeyContext, encryptedData + encryptedDataObjectSize,
				  rawDataObjectSize + dataLength );

	/* We're done, destroy the session key context */
	cryptDestroyContext( sessionKeyContext );

	/* Query the encrypted key object */
	status = cryptQueryObject( exportedKey, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( exportedKey );
        free( encryptedData );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.type,
			cryptObjectInfo.size, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	printf( "Key ID for decryption is " );
	printKeyID( &cryptObjectInfo );
	printf( "Session key cookie is " );
	printCookie( &cryptObjectInfo );
#ifdef WRITE_OBJECTS
	fwrite( exportedKey, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Query the encrypted data object */
	status = cryptQueryObject( encryptedData, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( exportedKey );
		free( encryptedData );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes.\n",
			cryptObjectInfo.type, cryptObjectInfo.size );
	printf( "Decryption key cookie is " );
	printCookie( &cryptObjectInfo );
#ifdef WRITE_OBJECTS
	fwrite( encryptedData, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */

	/* Recreate the session key by importing the encrypted key */
	status = cryptImportKey( exportedKey, decryptContext, &sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d\n", status );
		free( exportedKey );
		free( encryptedData );
		return( FALSE );
		}

	/* Set up the session key to decrypt the encrypted data */
	status = cryptImportObjectEx( encryptedData, &payloadStart, &payloadSize,
								  &sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportObjectEx() failed with error code %d\n", status );
		free( exportedKey );
		free( encryptedData );
		return( FALSE );
		}

	/* Decrypt the encrypted data */
	payload = encryptedData + payloadStart;
	cryptDecrypt( sessionKeyContext, payload, ( int ) payloadSize );

	/* Query the raw data object */
	status = cryptQueryObject( payload, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d\n", status );
		free( exportedKey );
		free( encryptedData );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %ld bytes.\n",
			cryptObjectInfo.type, cryptObjectInfo.size );
#ifdef WRITE_OBJECTS
	fwrite( payload, ( size_t ) cryptObjectInfo.size, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */

	/* Make sure the data matches what we originally encrypted */
	if( memcmp( data, payload + cryptObjectInfo.headerSize,
				( size_t ) cryptObjectInfo.payloadSize ) )
		puts( "Decrypted data != original plaintext." );

	/* Clean up */
	cryptDestroyContext( sessionKeyContext );
	destroyContexts( cryptContext, decryptContext );
	printf( "Exchange of encrypted data via RSA-encrypted session key "
			"succeeded.\n\n" );
	free( exportedKey );
	free( encryptedData );
	return( TRUE );
	}

/****************************************************************************
*																			*
*			Sample Mini-application - Encrypt and Sign a Memory Buffer		*
*																			*
****************************************************************************/

/* Create an encrypted, signed data object preceded by an exported key
   object.  This looks like:

	[ PKCEncryptedKey|EncryptedKey ]
	[ EncryptedData( SignedData( RawData ), Signature ) ] */

static int encryptSignBuffer( BYTE **outBuffer, int *outLength, BYTE *data,
							  int dataLength, CRYPT_CONTEXT signContext,
							  CRYPT_CONTEXT cryptContext,
							  CRYPT_ALGO cryptAlgo )
	{
	CRYPT_CONTEXT sessionKeyContext, hashContext;
	CRYPT_IOCTLINFO_COOKIE cryptIoctlInfo;
	BYTE *objectBuffer, *encryptedObject, *signedObject, *dataObject, *signature;
	int signatureSize, exportedKeySize;
	int encryptedObjectSize, signedObjectSize, dataObjectSize;
	int status;

	/* Ensure that if something goes wrong the caller won't try to use the
	   output data */
	*outBuffer = NULL;
	*outLength = 0;

	/* Create an encryption context for the session key and a hash context
	   for the signature.  Since the Signature object directly follows the
	   SignedData object we don't bother exporting the signature cookie */
	status = cryptCreateContext( &sessionKeyContext, cryptAlgo, CRYPT_MODE_CFB );
	if( cryptStatusError( status ) )
		return( status );
	cryptGenerateContext( sessionKeyContext );
	status = cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( sessionKeyContext );
		return( status );
		}
	cryptIoctlInfo.exportCookie = 0;
	cryptIoctl( CRYPT_IOCTL_SIGCOOKIE, &cryptIoctlInfo, hashContext );

	/* Find out how big the various objects will be.  Note the way we
	   determine the size of the nested objects: First the inner RawData
	   object, then the SignedData object surrounding it, then the
	   EncryptedData object surrounding that */
	cryptExportKey( NULL, &exportedKeySize, cryptContext, sessionKeyContext );
	cryptCreateSignature( NULL, &signatureSize, signContext, hashContext );
	cryptExportObject( NULL, &dataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );
	cryptExportObjectEx( NULL, &signedObjectSize, CRYPT_OBJECT_SIGNED_DATA,
						 dataObjectSize + dataLength, hashContext );
	cryptExportObjectEx( NULL, &encryptedObjectSize,
						 CRYPT_OBJECT_ENCRYPTED_DATA, signedObjectSize +
						 dataObjectSize + dataLength + signatureSize,
						 sessionKeyContext );

	/* Allocate a buffer for them and find the locations of each object in
	   the buffer */
	if( ( objectBuffer = malloc( exportedKeySize + encryptedObjectSize +
								 signedObjectSize + dataObjectSize +
								 dataLength + signatureSize ) ) == NULL )
		{
		cryptDestroyContext( sessionKeyContext );
		cryptDestroyContext( hashContext );
		return( CRYPT_NOMEM );
		}
	encryptedObject = objectBuffer + exportedKeySize;
	signedObject = encryptedObject + encryptedObjectSize;
	dataObject = signedObject + signedObjectSize;
	signature = dataObject + dataObjectSize + dataLength;

	/* Export the session key */
	status = cryptExportKey( objectBuffer, &exportedKeySize, cryptContext,
							 sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( sessionKeyContext );
		cryptDestroyContext( hashContext );
		free( objectBuffer );
		return( status );
		}

	/* Assemble the EncryptedData, SignedData, and RawData objects */
	cryptExportObjectEx( encryptedObject, &encryptedObjectSize,
						 CRYPT_OBJECT_ENCRYPTED_DATA, signedObjectSize +
						 dataObjectSize + dataLength + signatureSize,
						 sessionKeyContext );
	cryptExportObjectEx( signedObject, &signedObjectSize,
						 CRYPT_OBJECT_SIGNED_DATA, dataObjectSize +
						 dataLength, hashContext );
	cryptExportObject( dataObject, &dataObjectSize, CRYPT_OBJECT_RAW_DATA,
					   dataLength );
	memcpy( dataObject + dataObjectSize, data, dataLength );

	/* Hash the RawData object, sign the hash, and store the result in the
	   SignedData object */
	cryptEncrypt( hashContext, dataObject, dataLength +  dataObjectSize );
	cryptEncrypt( hashContext, dataObject, 0 );
	status = cryptCreateSignature( signature, &signatureSize, signContext,
								   hashContext );
	cryptDestroyContext( hashContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( sessionKeyContext );
		free( objectBuffer );
		return( status );
		}

	/* Encrypt the SignedData and Signature objects */
	status = cryptEncrypt( sessionKeyContext, signedObject, signedObjectSize
						   + dataObjectSize + dataLength + signatureSize );
	cryptDestroyContext( sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		free( objectBuffer );
		return( status );
		}

	/* Clean up */
	*outBuffer = objectBuffer;
	*outLength = exportedKeySize + encryptedObjectSize + signedObjectSize +
				 dataObjectSize + dataLength + signatureSize;
	return( CRYPT_OK );
	}

/* Unwrap the data objects, decrypt the data we need, and check the
   signature */

static int decryptSignBuffer( BYTE **outBuffer, int *outLength, BYTE *data,
							  CRYPT_CONTEXT signContext,
							  CRYPT_CONTEXT decryptContext )
	{
	CRYPT_CONTEXT sessionKeyContext, hashContext;
	BYTE *exportedKey = data, *encryptedData, *signedData, *payload, *signature;
	int payloadStart, status;
	long payloadSize;

	/* Ensure that if something goes wrong the caller won't try to use the
	   output data */
	*outBuffer = NULL;
	*outLength = 0;

	/* Query the encrypted key object to find its size */
	status = cryptImportObject( exportedKey, &payloadStart, &payloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Recreate the session key by importing the encrypted key */
	status = cryptImportKey( exportedKey, decryptContext, &sessionKeyContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the session key to decrypt the encrypted data */
	encryptedData = exportedKey + payloadStart + ( int ) payloadSize;
	status = cryptImportObjectEx( encryptedData, &payloadStart, &payloadSize,
								  &sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( sessionKeyContext );
		return( status );
		}

	/* Decrypt the encrypted data */
	signedData = encryptedData + payloadStart;
	status = cryptDecrypt( sessionKeyContext, signedData, ( int ) payloadSize );
	cryptDestroyContext( sessionKeyContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the signed data object */
	status = cryptImportObjectEx( signedData, &payloadStart, &payloadSize,
								  &hashContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the signed data */
	payload = signedData + payloadStart;
	cryptEncrypt( hashContext, payload, ( int ) payloadSize );
	cryptEncrypt( hashContext, payload, 0 );

	/* Check the signature */
	signature = signedData + payloadStart + ( int ) payloadSize;
	status = cryptCheckSignature( signature, signContext, hashContext );
	cryptDestroyContext( hashContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the raw data object */
	status = cryptImportObject( payload, &payloadStart, &payloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Clean up */
	*outBuffer = payload + payloadStart;
	*outLength = ( int ) payloadSize;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Sample Application Test Code					*
*																			*
****************************************************************************/

/* Code to test the sample app to sign and encrypt a memory buffer.  This
   uses a PKC-encrypted session key, although there's no reason you can't
   use a conventionally-encrypted one */

int testSampleApp( void )
	{
	CRYPT_CONTEXT pkcContext, signContext;
	BYTE *data = ( BYTE * ) "This is some sample plaintext to export";
	BYTE *cipherText, *plainText;
	int length = strlen( ( char * ) data ) + 1, outLength, status;

	/* Load the encryption and signature keys */
	if( !loadRSAContexts( &pkcContext, &signContext ) )
		return( FALSE );

	/* Encrypt and wrap the data */
	status = encryptSignBuffer( &cipherText, &outLength, data, length,
								signContext, pkcContext, CRYPT_ALGO_3DES );
	cryptDestroyContext( pkcContext );
	cryptDestroyContext( signContext );
	if( cryptStatusError( status ) )
		{
		if( cipherText != NULL )
			free( cipherText );
		printf( "encryptSignBuffer() function failed with error code %d\n", status );
		return( FALSE );
		}
#ifdef WRITE_OBJECTS
	fwrite( cipherText, outLength, 1, objectFile );
	fflush( objectFile );
#endif /* WRITE_OBJECTS */

	/* Load the decryption and signature-check keys */
	if( !loadRSAContexts( &signContext, &pkcContext ) )
		{
		free( cipherText );
		return( FALSE );
		}

	/* Unwrap and decrypt the data */
	status = decryptSignBuffer( &plainText, &outLength, cipherText,
								signContext, pkcContext );
	cryptDestroyContext( pkcContext );
	cryptDestroyContext( signContext );
	if( cryptStatusError( status ) )
		{
		free( cipherText );
		printf( "decryptSignBuffer() function failed with error code %d\n", status );
		return( FALSE );
		}

	/* Make sure everything went OK */
	if( outLength != length || \
		memcmp( plainText, data, length ) )
		{
		free( cipherText );
		puts( "Recovered plaintext != original plaintext" );
		return( FALSE );
		}

	/* Clean up */
	printf( "Exchange of signed and encrypted data using object-management "
			"API's succeeded.\n\n" );
	free( cipherText );
	return( TRUE );
	}

