#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capi.h"

/* Define the following to enable/disable various blocks of tests */

#define TEST_LOWLEVEL		/* Test low-level functions */
#define TEST_HIGHLEVEL		/* Test high-level functions */
#define TEST_RANDOM			/* Test randomness functions */

/* Define the following to write the ASN.1-encoded cryptlib objects to disk
   for analysis */

/*#define WRITE_OBJECTS	/**/

/* Various useful types.  These are also declared/defined in crypt.h, so we
   use #defines in place of typedefs so we can undefine them before we
   include crypt.h */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

/* The key size to use for the PKC routines */

#define PKC_KEYSIZE			512

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* The output stream for the ASN.1-encoded cryptlib objects */

#ifdef WRITE_OBJECTS
  static FILE *objectFile;
#endif /* WRITE_OBJECTS */

/* Prototypes for functions in testhl.c */

int testDeriveKey( void );
int testRandomRoutines( void );
int testConventionalExportImport( void );
int testKeyExportImport( void );
int testSignData( void );
int testKeyExchange( void );
int testEncryptObject( void );
int testSampleApp( void );

/* The key for testing the RSA implementation. This is the same 512-bit key
   as the one used for the lib_rsa.c self-test.

   It would be nicer if we had a fixed encoded public key which we read in
   via the keyset routines rather than using this messy indirect-loading,
   but that would defeat the purpose of the self-test somewhat since it could
   fail in the (rather complex) keyset access routines rather than in the RSA
   code which is what we're really trying to test */

typedef struct {
	int nLen; BYTE n[ 64 ];
	int eLen; BYTE e[ 1 ];
	int dLen; BYTE d[ 64 ];
	int pLen; BYTE p[ 32 ];
	int qLen; BYTE q[ 32 ];
	int uLen; BYTE u[ 32 ];
	int e1Len; BYTE e1[ 32 ];
	int e2Len; BYTE e2[ 32 ];
	} RSA_KEY;

static RSA_KEY rsaTestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F,
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20,
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54,
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2, 
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x68, 0x45, 0x00, 0x64, 0x32, 0x9D, 0x09, 0x6E,
	  0x0A, 0xD3, 0xF3, 0x8A, 0xFE, 0x15, 0x8C, 0x79,
	  0xAD, 0x84, 0x35, 0x05, 0x19, 0x2C, 0x19, 0x51,
	  0xAB, 0x83, 0xC7, 0xE8, 0x5C, 0xAC, 0xAD, 0x7A },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#ifdef __MSDOS__
  extern unsigned _stklen = 16384;
#endif /* __MSDOS__ */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Work routines: Set a pair of encrypt/decrypt buffers to a known state,
   and make sure they're still in that known state */

static void initTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Set the buffers to a known state */
	memset( buffer1, '*', TESTBUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );		/* For endianness check */
	memcpy( buffer2, buffer1, TESTBUFFER_SIZE );
	}

static void checkTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Make sure everything went OK */
	if( memcmp( buffer1, buffer2, TESTBUFFER_SIZE ) )
		{
		puts( "Error: Decrypted data != original plaintext." );

		/* Try and guess at block chaining problems */
		if( !memcmp( buffer1, "12345678****", 12 ) )
			puts( "\t\bIt looks like there's a problem with block chaining." );
		else
			/* Try and guess at endianness problems - we want "1234" */
			if( !memcmp( buffer1, "4321", 4 ) )
				puts( "\t\bIt looks like the 32-bit word endianness is "
					  "reversed." );
			else
				if( !memcmp( buffer1, "2143", 4 ) )
					puts( "\t\bIt looks like the 16-bit word endianness is "
						  "reversed." );
			else
				if( buffer1[ 0 ] >= '1' && buffer1[ 0 ] <= '9' )
					puts( "\t\bIt looks like there's some sort of endianness "
						  "problem which is\n\t more complex than just a "
						  "reversal." );
				else
					puts( "\t\bIt's probably more than just an endianness "
						  "problem." );
		}
	}

/* Report information on the encryption algorithm */

static void reportAlgorithmInformation( CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	char speedFactor[ 50 ];

	/* Determine the speed factor relative to a block copy */
	if( cryptQueryInfo->speed == CRYPT_ERROR )
		strcpy( speedFactor, "unknown speed factor" );
	else
		sprintf( speedFactor, "0.%03d times the speed of a block copy",
				 cryptQueryInfo->speed );

	printf( "algorithm %s/%s is available with\n",
			cryptQueryInfo->algoName, cryptQueryInfo->modeName );
	printf(	"  name `%s', block size %d bits, %s,\n"
			"  min keysize %d bits, recommended keysize %d bits, "
				"max keysize %d bits,\n"
			"  min IV size %d bits, recommended IV size %d bits, "
				"max IV size %d bits.\n",
			cryptQueryInfo->algoName,
			bytesToBits( cryptQueryInfo->blockSize ), speedFactor,
			bytesToBits( cryptQueryInfo->minKeySize ),
			bytesToBits( cryptQueryInfo->keySize ),
			bytesToBits( cryptQueryInfo->maxKeySize ),
			bytesToBits( cryptQueryInfo->minIVsize ),
			bytesToBits( cryptQueryInfo->ivSize ),
			bytesToBits( cryptQueryInfo->maxIVsize ) );
	}

/* Check the library for an algorithm/mode */

static BOOLEAN checkLibraryInfo( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	int status;

	status = cryptModeAvailable( cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "cryptModeAvailable() reports algorithm %d, mode %d is not "
				"available: Code %d.\n", cryptAlgo, cryptMode, status );
		return( FALSE );
		}
	status = cryptQueryAlgoMode( cryptAlgo, cryptMode, &cryptQueryInfo );
	printf( "cryptQueryMode() reports " );
	if( cryptStatusOK( status ) )
		reportAlgorithmInformation( &cryptQueryInfo );
	else
		{
		printf( "no information available on algorithm %d, mode %d: Code %d.\n",
				cryptAlgo, cryptMode, status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load the encryption contexts */

static BOOLEAN loadContexts( CRYPT_CONTEXT *cryptContext, CRYPT_CONTEXT *decryptContext,
							 CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode,
							 BYTE *key, int length )
	{
	int status;

	/* Create the encryption context */
	status = cryptCreateContext( cryptContext, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptMode != CRYPT_MODE_NONE )
		{
		status = cryptLoadContext( *cryptContext, key, length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadContext() failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptMode != CRYPT_MODE_NONE )
		{
		status = cryptLoadContext( *decryptContext, key, length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadContext() failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Load RSA PKC encrytion contexts */

BOOLEAN loadRSAContexts( CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the encryption context */
	status = cryptCreateContext( cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKey->n, rsaTestKey.n, rsaTestKey.nLen );
	cryptSetComponent( rsaKey->e, rsaTestKey.e, rsaTestKey.eLen );
	status = cryptLoadContext( *cryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		cryptDestroyContext( *cryptContext );
		printf( "cryptLoadContext() failed with error code %d.\n", status );
		return( FALSE );
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		cryptDestroyContext( *cryptContext );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsaTestKey.n, rsaTestKey.nLen );
	cryptSetComponent( rsaKey->e, rsaTestKey.e, rsaTestKey.eLen );
	cryptSetComponent( rsaKey->d, rsaTestKey.d, rsaTestKey.dLen );
	cryptSetComponent( rsaKey->p, rsaTestKey.p, rsaTestKey.pLen );
	cryptSetComponent( rsaKey->q, rsaTestKey.q, rsaTestKey.qLen );
	cryptSetComponent( rsaKey->u, rsaTestKey.u, rsaTestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsaTestKey.e1, rsaTestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsaTestKey.e2, rsaTestKey.e2Len );
	status = cryptLoadContext( *decryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "cryptLoadContext() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load Diffie-Hellman encrytion contexts */

BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize )
	{
	CRYPT_PKCINFO_DH *dhKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DH * ) malloc( sizeof( CRYPT_PKCINFO_DH ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the first encryption context */
	status = cryptCreateContext( cryptContext1, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( dhKey, keySize, CRYPT_UNUSED );
	status = cryptLoadContext( *cryptContext1, dhKey, CRYPT_UNUSED );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptLoadContext() failed with error code %d.\n", status );
		return( FALSE );
		}

	/* Create the second encryption context */
	status = cryptCreateContext( cryptContext2, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( dhKey, keySize, CRYPT_UNUSED );
	status = cryptLoadContext( *cryptContext2, dhKey, CRYPT_UNUSED );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptLoadContext() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Low-level Routines Test							*
*																			*
****************************************************************************/

/* Perform a test en/decryption */

static void testCrypt( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext,
					   BYTE *buffer )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	int status;

	/* Find out about the algorithm we're using */
	cryptQueryContext( cryptContext, &cryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_CFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_OFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_STREAM )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 79 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 79, TESTBUFFER_SIZE - 79 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_STREAM )
			{
			status = cryptRetrieveIV( cryptContext, iv );
			if( cryptStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = cryptLoadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( cryptStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 125 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + 125, TESTBUFFER_SIZE - 125 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_ECB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_CBC ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_PCBC )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_ECB )
			{
			status = cryptRetrieveIV( cryptContext, iv );
			if( cryptStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = cryptLoadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( cryptStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_PKC )
		{
		/* To ensure that the magnitude of the integer corresponding to the
		   data to be encrypted is less than the modulus, we set the first
		   byte of the buffer to 0.  This is only necessary for this test code
		   which uses a set pattern for its test data and wouldn't normally be
		   necessary */
		int ch = buffer[ 0 ];

		/* Since the PKC algorithms only handle a single block, we only
		   perform a single encrypt and decrypt operation */
		buffer[ 0 ] = 0;
		status = cryptEncrypt( cryptContext, buffer, CRYPT_USE_DEFAULT );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer, CRYPT_USE_DEFAULT );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		buffer[ 0 ] = ch;
		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
		{
		/* Hash the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Hash the buffer in different odd-size chunks */
		status = cryptEncrypt( decryptContext, buffer, 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}

	puts( "Unknown encryption mode found in test code." );
	}

/* Destroy the encryption contexts */

void destroyContexts( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext )
	{
	int status;

	status = cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	status = cryptDestroyContext( decryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	}

/* Sample code to test an algorithm/mode implementation */

static int testLibrary( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
	{
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_INFO_MDCSHS cryptInfoEx;
	CRYPT_QUERY_INFO cryptQueryInfo, decryptQueryInfo;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer );

	/* Check the capabilities of the library */
	if( !checkLibraryInfo( cryptAlgo, cryptMode ) )
		return( FALSE );

	/* Since DH only performs a key agreement rather than a true key
	   exchange and DSA is a bit unusual (it returns a struct with two
	   bignums rather than encrypting a buffer), we can't test their
	   encryption capabilities */
	if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_DSA )
		return( TRUE );

	/* Set up an encryption context, load a user key into it, and perform a
	   key setup */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_MDCSHS:
			/* We use an extended setup with reduced iteration count for
			   people who have to run this thing 2000 times while debugging */
			cryptInfoEx.keySetupIterations = 10;
			status = cryptCreateContextEx( &cryptContext, cryptAlgo, cryptMode,
										   &cryptInfoEx );
			if( cryptStatusError( status ) )
				{
				printf( "cryptCreateContext() failed with error code %d.\n",
						status );
				return( FALSE );
				}
			status = cryptLoadContext( cryptContext, "Test key", 8 );
			if( cryptStatusError( status ) )
				{
				printf( "cryptLoadContext() failed with error code %d.\n",
						status );
				return( FALSE );
				}

			/* Create another crypt context for decryption.  The error
			   checking here is a bit less picky to save space */
			cryptInfoEx.keySetupIterations = 10;
			cryptCreateContextEx( &decryptContext, cryptAlgo, cryptMode,
								  &cryptInfoEx );
			status = cryptLoadContext( decryptContext, "Test key", 8 );
			if( cryptStatusError( status ) )
				{
				printf( "cryptLoadContext() failed with error code %d.\n",
						status );
				return( FALSE );
				}
			break;

		case CRYPT_ALGO_DES:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "12345678", 8 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_3DES:
		case CRYPT_ALGO_IDEA:
		case CRYPT_ALGO_SAFER:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567887654321", 16 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_RC2:
		case CRYPT_ALGO_RC4:
		case CRYPT_ALGO_RC5:
		case CRYPT_ALGO_BLOWFISH:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567890098765432112345678900987654321", 40 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_MD2:
		case CRYPT_ALGO_MD4:
		case CRYPT_ALGO_MD5:
		case CRYPT_ALGO_RIPEMD160:
		case CRYPT_ALGO_SHA:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "", 0 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_RSA:
			if( !loadRSAContexts( &cryptContext, &decryptContext ) )
				return( FALSE );
			break;

		default:
			printf( "Unknown encryption algorithm = ID %d, cannot perform "
					"encryption test\n", cryptAlgo );
			return( FALSE );
		}

	/* Perform a test en/decryption */
	testCrypt( cryptContext, decryptContext, buffer );

	/* Make sure everything went OK */
	if( ( status = cryptQueryContext( cryptContext, &cryptQueryInfo ) ) == CRYPT_OK )
		status = cryptQueryContext( decryptContext, &decryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
		{
		if( cryptStatusError( status ) )
			printf( "Couldn't get hash information: Code %d\n", status );
		else
			if( memcmp( cryptQueryInfo.hashValue, decryptQueryInfo.hashValue, \
						cryptQueryInfo.blockSize ) )
				puts( "Error: Hash value of identical buffers differs." );
		}
	else
		checkTestBuffers( buffer, testBuffer );

	/* Clean up */
	destroyContexts( cryptContext, decryptContext );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define __WINDOWS__
  #define INC_CHILD
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* Exercise various aspects of the encryption library */

int main( int argc, char **argv )
	{
#ifdef TEST_LOWLEVEL
	CRYPT_ALGO cryptAlgo;
#endif /* TEST_LOWLEVEL */
#ifndef __WINDOWS__
	int status;
#endif /* !__WINDOWS__ */
	void testSystemSpecific( void );

	/* Get rid of compiler warnings */
	if( argc || argv );

	/* Make sure various system-specific features are set right */
	testSystemSpecific();

	/* Initialise the library (not necessary for a DLL) */
#ifndef __WINDOWS__
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}
#endif /* !__WINDOWS__ */

#ifdef TEST_LOWLEVEL
	/* Test the conventional encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptAlgoAvailable( cryptAlgo ) ) )
			{
			CRYPT_MODE cryptMode;

			for( cryptMode = CRYPT_MODE_FIRST_CONVENTIONAL;
				 cryptMode <= CRYPT_MODE_LAST_CONVENTIONAL; cryptMode++ )
				if( cryptStatusOK( cryptModeAvailable( cryptAlgo, cryptMode ) ) && \
					!testLibrary( cryptAlgo, cryptMode ) )
					goto errorExit;
			}

	/* Test the public-key encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		if( cryptStatusOK( cryptAlgoAvailable( cryptAlgo ) ) && \
			!testLibrary( cryptAlgo, CRYPT_MODE_PKC ) )
				goto errorExit;

	/* Test the hash routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptAlgoAvailable( cryptAlgo ) ) && \
			!testLibrary( cryptAlgo, CRYPT_MODE_NONE ) )
			goto errorExit;

	putchar( '\n' );
#else
	puts( "Skipping test of low-level encryption routines...\n" );
#endif /* TEST_LOWLEVEL */

	/* Test the randomness-gathering routines in the library */
#ifdef TEST_RANDOM
	if( !testRandomRoutines() )
		{
		puts( "The self-test will proceed without using a strong random "
			  "number source.\n" );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "a", 1 );
		}
#else
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk - it doesn't
	   matter here because we're not worried about security, but should never
	   be done in production code */
	cryptAddRandom( "a", 1 );
#endif /* TEST_RANDOM */

	/* Test the high-level routines contained in the library.  This is
	   implemented as a series of separate function calls rather than a
	   monolithic if( a || b || c || ... ) block to make testing easier */
#ifdef WRITE_OBJECTS
	if( ( objectFile = fopen( "asn1objs.dat", "wb" ) ) == NULL )
		{
		puts( "Couldn't open output file to write cryptlib objects to." );
		exit( EXIT_FAILURE );
		}
#endif /* WRITE_OBJECTS */
#ifdef TEST_HIGHLEVEL
	if( !testDeriveKey() )
		goto errorExit;
	if( !testConventionalExportImport() )
		goto errorExit;
	if( !testKeyExportImport() )
		goto errorExit;
	if( !testSignData() )
		goto errorExit;
	if( !testKeyExchange() )
		goto errorExit;
	if( !testEncryptObject() )
		goto errorExit;
	if( !testSampleApp() )
		goto errorExit;
#else
	puts( "Skipping test of high-level encryption routines...\n" );
#endif /* TEST_HIGHLEVEL */
#ifdef WRITE_OBJECTS
	fclose( objectFile );
#endif /* WRITE_OBJECTS */

	/* Shut down the library (not necessary for a DLL) */
#ifndef __WINDOWS__
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "cryptEnd() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}
#endif /* !__WINDOWS__ */

	return( EXIT_SUCCESS );

	/* All errors end up here */
errorExit:
	cryptEnd();
	puts( "Tests aborted due to encryption library error." );
	return( EXIT_FAILURE );
	}

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with 
   the rest of the test.c code.

   The following include is need only so we can check whether the defines are
   set right.  crypt.h should not normally be included in a cryptlib program */

#undef __WINDOWS__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#include "crypt.h"

void testSystemSpecific( void )
	{
	int bigEndian;

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for
	   things like middle-endianness without knowing the size of the data
	   types */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef LITTLE_ENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild the library." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild the library." );
		exit( EXIT_FAILURE );
		}
#endif /* LITTLE_ENDIAN */

	/* If we're compiling under Windoze, make sure that this weeks version
	   of Visual C gets the LONG type right */
#ifdef __WINDOWS__
	{
	LONG test = 0x80000000L;

	if( test < 0 )
		{
		puts( "typeof( LONG ) is incorrect.  It evaluates to a signed 32-bit "
			  "value rather\nthan an unsigned 32-bit value.  You need to edit "
			  "crypt.h and recompile the\nencryption library" );
		exit( EXIT_FAILURE );
		}
	}
#endif /* __WINDOWS__ */
	}
