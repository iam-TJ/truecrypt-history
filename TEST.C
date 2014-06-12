#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* We include CRYPT.H here rather than CAPI.H since we need to test a number
   of settings and defines from CRYPT.H.  Normally user programs won't see
   CRYPT.H */

#include "crypt.h"

/* A table of all the functions we want to test */

static struct {
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	char *name;
	char *longName;
	} testInfo[] = {
#if 0	/* Disable sections of the code to speed up testing */
#endif /* 0 */
	{ CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB, "MDC/SHS", "MDC/SHS-CFB" },
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, "DES", "DES-ECB" },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, "DES", "DES-CBC" },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, "DES", "DES-CFB" },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, "DES", "DES-OFB" },
	{ CRYPT_ALGO_DES, CRYPT_MODE_PCBC, "DES", "DES-PCBC" },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, "3DES", "3DES-ECB" },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, "3DES", "3DES-CBC" },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, "3DES", "3DES-CFB" },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, "3DES", "3DES-OFB" },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_PCBC, "3DES", "3DES-PCBC" },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, "IDEA", "IDEA-ECB" },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, "IDEA", "IDEA-CBC" },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, "IDEA", "IDEA-CFB" },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, "IDEA", "IDEA-OFB" },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_PCBC, "IDEA", "IDEA-PCBC" },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB, "RC2", "RC2-ECB" },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC, "RC2", "RC2-CBC" },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CFB, "RC2", "RC2-CFB" },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_OFB, "RC2", "RC2-OFB" },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_PCBC, "RC2", "RC2-PCBC" },
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, "RC4", "RC4" },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_ECB, "RC5", "RC5-ECB" },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC, "RC5", "RC5-CBC" },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CFB, "RC5", "RC5-CFB" },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_OFB, "RC5", "RC5-OFB" },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_PCBC, "RC5", "RC5-PCBC" },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_ECB, "SAFER", "SAFER-ECB" },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CBC, "SAFER", "SAFER-CBC" },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CFB, "SAFER", "SAFER-CFB" },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_OFB, "SAFER", "SAFER-OFB" },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_PCBC, "SAFER", "SAFER-PCBC" },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB, "Blowfish", "Blowfish-ECB" },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC, "Blowfish", "Blowfish-CBC" },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB, "Blowfish", "Blowfish-CFB" },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB, "Blowfish", "Blowfish-OFB" },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_PCBC, "Blowfish", "Blowfish-PCBC" },
	{ CRYPT_ALGO_MD4, CRYPT_MODE_NONE, "MD4", "MD4 hash function" },
	{ CRYPT_ALGO_MD5, CRYPT_MODE_NONE, "MD5", "MD5 hash function" },
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, "SHA", "SHA hash function" },
#if 0	/* Disabled in this release */
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PUBKEY, "RSA", "RSA public-key operation" },
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PRIVKEY, "RSA", "RSA private-key operation" },
#endif /* 0 */
	{ CRYPT_ERROR, CRYPT_ERROR, "", "" }
	};

/* There are some sizeable (for DOS) test buffers used, so we increase the
   stack size */

#ifdef __MSDOS__
  extern unsigned _stklen = 8192;
#endif /* __MSDOS__ */

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

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

static void reportAlgorithmInformation( char *algorithmName,
										CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	char speedFactor[ 50 ];

	/* Determine the speed factor relative to a block copy */
	if( cryptQueryInfo->speed == CRYPT_ERROR )
		strcpy( speedFactor, "unknown speed factor" );
	else
		sprintf( speedFactor, "0.%03d times the speed of a block copy",
				 cryptQueryInfo->speed );

	printf( "%s algorithm is available with\n"
				"  name `%s', block size %d bits, %s,\n"
				"  min key size %d bits, recommended key size %d bits, "
					"max key size %d bits,\n"
				"  min IV size %d bits, recommended IV size %d bits, "
					"max IV size %d bits.\n",
				algorithmName, cryptQueryInfo->algoName,
				bytesToBits( cryptQueryInfo->blockSize ), speedFactor,
				bytesToBits( cryptQueryInfo->minKeySize ),
				bytesToBits( cryptQueryInfo->keySize ),
				bytesToBits( cryptQueryInfo->maxKeySize ),
				bytesToBits( cryptQueryInfo->minIVsize ),
				bytesToBits( cryptQueryInfo->ivSize ),
				bytesToBits( cryptQueryInfo->maxIVsize ) );
	}

/* Check the library for an algorithm/mode */

static BOOLEAN checkLibraryInfo( char *name, char *longName,
								 CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	int status;

	status = queryAlgoAvailability( cryptAlgo );
	if( isStatusError( status ) )
		{
		printf( "queryAlgoAvailability() reports %s is not available: "
				"Code %d.\n", name, status );
		return( FALSE );
		}
	status = queryModeAvailability( cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "queryModeAvailability() reports %s is not available: "
				"Code %d.\n", longName, status );
		return( FALSE );
		}
	status = queryAlgoModeInformation( cryptAlgo, cryptMode, &cryptQueryInfo );
	printf( "queryModeAvailability() reports " );
	if( isStatusOK( status ) )
		reportAlgorithmInformation( longName, &cryptQueryInfo );
	else
		{
		printf( "no information available on %s algorithm: Code %d.\n",
				name, status );
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
	status = initCryptContext( cryptContext, cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "initCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptMode != CRYPT_MODE_NONE )
		{
		status = loadCryptContext( *cryptContext, key, length );
		if( isStatusError( status ) )
			{
			printf( "loadCryptContext(): Failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	/* Create the decryption context */
	status = initCryptContext( decryptContext, cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "initCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptMode != CRYPT_MODE_NONE )
		{
		status = loadCryptContext( *decryptContext, key, length );
		if( isStatusError( status ) )
			{
			printf( "loadCryptContext(): Failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Perform a test en/decryption */

static void testCrypt( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext,
					   BYTE *buffer )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	BYTE iv[ 100 ];
	int status;

	/* Find out about the algorithm we're using */
	queryContextInformation( cryptContext, &cryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_CFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_OFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_STREAM )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = encryptBuffer( cryptContext, buffer, 79 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptContext, buffer + 79, TESTBUFFER_SIZE - 79 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_STREAM )
			{
			status = retrieveIV( cryptContext, iv );
			if( isStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = loadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( isStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = decryptBuffer( decryptContext, buffer, 125 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = decryptBuffer( decryptContext, buffer + 125, TESTBUFFER_SIZE - 125 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_ECB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_CBC ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_PCBC )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = encryptBuffer( cryptContext, buffer, 80 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_ECB )
			{
			status = retrieveIV( cryptContext, iv );
			if( isStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = loadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( isStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			status = encryptBuffer( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = decryptBuffer( decryptContext, buffer, 128 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = decryptBuffer( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = decryptBuffer( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
		{
		/* Hash the buffer in two odd-sized chunks */
		status = encryptBuffer( cryptContext, buffer, 80 );
		if( isStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = encryptBuffer( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( isStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = encryptBuffer( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Hash the buffer in different odd-size chunks */
		status = encryptBuffer( decryptContext, buffer, 128 );
		if( isStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = encryptBuffer( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( isStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = encryptBuffer( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}

	puts( "Unknown encryption mode found in test code." );
	}

/* Destroy the encryption contexts */

static void destroyContexts( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext )
	{
	int status;

	status = destroyCryptContext( cryptContext );
	if( isStatusError( status ) )
		printf( "destroyCryptContext(): Failed with error code %d.\n", status );
	status = destroyCryptContext( decryptContext );
	if( isStatusError( status ) )
		printf( "destroyCryptContext(): Failed with error code %d.\n", status );
	}

/* Sample code to test an algorithm/mode implementation */

static int testLibrary( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode,
						char *name, char *longName )
	{
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_INFO_MDCSHS cryptInfoEx;
	CRYPT_QUERY_INFO cryptQueryInfo, decryptQueryInfo;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer );

	/* Check the capabilities of the library */
	putchar( '\n' );
	if( !checkLibraryInfo( name, longName, cryptAlgo, cryptMode ) )
		return( FALSE );

	/* Set up an encryption context, load a user key into it, and perform a
	   key setup */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_MDCSHS:
			/* We use an extended setup with reduced iteration count for
			   people who have to run this thing 2000 times while debugging */
			cryptInfoEx.keySetupIterations = 10;
			status = initCryptContextEx( &cryptContext, cryptAlgo, cryptMode,
										 &cryptInfoEx );
			if( isStatusError( status ) )
				{
				printf( "initCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}
			status = loadCryptContext( cryptContext, "Test key", 8 );
			if( isStatusError( status ) )
				{
				printf( "loadCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}

			/* Create another crypt context for decryption.  The error
			   checking here is a bit less picky to save space */
			cryptInfoEx.keySetupIterations = 10;
			initCryptContextEx( &decryptContext, cryptAlgo, cryptMode,
								&cryptInfoEx );
			status = loadCryptContext( decryptContext, "Test key", 8 );
			if( isStatusError( status ) )
				{
				printf( "loadCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}
			break;

		case CRYPT_ALGO_DES:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567", 7 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_3DES:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "12345677654321", 14 ) )
				return( FALSE );
			break;

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

		case CRYPT_ALGO_MD4:
		case CRYPT_ALGO_MD5:
		case CRYPT_ALGO_SHA:
			if( !loadContexts( &cryptContext, &decryptContext, cryptAlgo, cryptMode,
							   ( BYTE * ) "", 0 ) )
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
	if( ( status = queryContextInformation( cryptContext, &cryptQueryInfo ) ) == CRYPT_OK )
		status = queryContextInformation( decryptContext, &decryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
		{
		if( status != CRYPT_OK )
			printf( "Couldn't get hash information: Code %d\n", status );
		else
			if( memcmp( cryptQueryInfo.hashValue, decryptQueryInfo.hashValue, \
						cryptQueryInfo.blockSize ) )
				puts( "Error: Hash value of identical buffers differs." );
		}
	else
		checkTestBuffers( buffer, testBuffer );

	/* Destroy the encryption contexts */
	destroyContexts( cryptContext, decryptContext );

	return( TRUE );
	}

/* Exercise various aspects of the encryption library */

int main( int argc, char **argv )
	{
	int status, bigEndian, i;

	/* Get rid of compiler warning */
	if( argc || argv );

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

	/* Initialise the library */
	status = initLibrary();
	if( isStatusError( status ) )
		{
		printf( "Couldn't init library, code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	/* Test the encryption routines contained in the library */
	for( i = 0; testInfo[ i ].cryptAlgo != CRYPT_ERROR; i++ )
		if( !testLibrary( testInfo[ i ].cryptAlgo, testInfo[ i ].cryptMode,
						  testInfo[ i ].name, testInfo[ i ].longName ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}

	/* Shut down the library */
	status = endLibrary();
	if( isStatusError( status ) )
		{
		printf( "endLibrary(): Failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	return( EXIT_SUCCESS );
	}
