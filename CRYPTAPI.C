/****************************************************************************
*																			*
*						cryptlib Internal API Routines						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "md2.h"
  #include "md4.h"
  #include "md5.h"
  #include "ripemd.h"
  #include "sha.h"
  #include "asn1objs.h"
#else
  #include "hash/md2.h"
  #include "hash/md4.h"
  #include "hash/md5.h"
  #include "hash/ripemd.h"
  #include "hash/sha.h"
  #include "keymgmt/asn1objs.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Library-Wide Config Options						*
*																			*
****************************************************************************/

/* Various default settings */

#define DEFAULT_MEMLOCK_MODE		CRYPT_MEMORY_LOCK
#define DEFAULT_EXPORT_KEYCOOKIES	TRUE
#define DEFAULT_EXPORT_SIGCOOKIES	FALSE
#define DEFAULT_USE_OAEP			FALSE
#define DEFAULT_KEYSET_USERID		"Name"
#define DEFAULT_KEYSET_KEYID		"Key ID"
#define DEFAULT_KEYSET_PUBLICKEY	"Public Key"
#define DEFAULT_KEYSET_PRIVATEKEY	"Private Key"

/* Whether to not lock pages, lock pages and fail silently, or lock pages and
   fail with an error code */

static int memoryLockType = DEFAULT_MEMLOCK_MODE;

/* Whether key and signature cookies should be exported */

static BOOLEAN exportKeyCookies = DEFAULT_EXPORT_KEYCOOKIES;
static BOOLEAN exportSigCookies = DEFAULT_EXPORT_SIGCOOKIES;

/* Whether to use Bellare-Rogaway optimal asymmetric encryption padding */

static BOOLEAN useOAEP = DEFAULT_USE_OAEP;

/* The names of the tables in the key database */

static char *keysetUserID = NULL;
static char *keysetKeyID = NULL;
static char *keysetPublicKey = NULL;
static char *keysetPrivateKey = NULL;

/* Functions to set/query the config options */

void setOptionExportKeyCookie( const BOOLEAN option )
	{
	exportKeyCookies = option;
	}

BOOLEAN getOptionExportKeyCookie( void )
	{
	return( exportKeyCookies );
	}

void setOptionExportSigCookie( const BOOLEAN option )
	{
	exportSigCookies = option;
	}

BOOLEAN getOptionExportSigCookie( void )
	{
	return( exportSigCookies );
	}

void setOptionUseOAEP( const BOOLEAN option )
	{
	useOAEP = option;
	}

BOOLEAN getOptionUseOAEP( void )
	{
	return( useOAEP );
	}

void setOptionKeysetNames( const CRYPT_IOCTLINFO_KEYSETNAMES *keysetNames )
	{
	/* Set the appropriate table name to the default (if the input value is
	   CRYPT_USE_DEFAULT) or the given string if otherwise */
	if( keysetNames->userID != ( char * ) CRYPT_UNUSED )
		{
		if( keysetUserID !=  NULL )
			free( keysetUserID );
		keysetUserID = ( keysetNames->userID == ( char * ) CRYPT_USE_DEFAULT ) ? \
					   NULL : keysetNames->userID;
		}
	if( keysetNames->keyID != ( char * ) CRYPT_UNUSED )
		{
		if( keysetKeyID !=  NULL )
			free( keysetKeyID );
		keysetKeyID = ( keysetNames->keyID == ( char * ) CRYPT_USE_DEFAULT ) ? \
					   NULL : keysetNames->keyID;
		}
	if( keysetNames->publicKey != ( char * ) CRYPT_UNUSED )
		{
		if( keysetPublicKey !=  NULL )
			free( keysetPublicKey );
		keysetKeyID = ( keysetNames->publicKey == ( char * ) CRYPT_USE_DEFAULT ) ? \
					   NULL : keysetNames->publicKey;
		}
	if( keysetNames->privateKey != ( char * ) CRYPT_UNUSED )
		{
		if( keysetPrivateKey !=  NULL )
			free( keysetPrivateKey );
		keysetKeyID = ( keysetNames->privateKey == ( char * ) CRYPT_USE_DEFAULT ) ? \
					   NULL : keysetNames->privateKey;
		}
	}

void getOptionKeysetNames( CRYPT_IOCTLINFO_KEYSETNAMES *keysetNames )
	{
	keysetNames->userID = ( keysetUserID == NULL ) ? \
							DEFAULT_KEYSET_USERID : keysetUserID;
	keysetNames->keyID = ( keysetKeyID == NULL ) ? \
							DEFAULT_KEYSET_KEYID : keysetKeyID;
	keysetNames->publicKey = ( keysetPublicKey == NULL ) ? \
							DEFAULT_KEYSET_PUBLICKEY : keysetPublicKey;
	keysetNames->privateKey = ( keysetPrivateKey == NULL ) ? \
							DEFAULT_KEYSET_PRIVATEKEY : keysetPrivateKey;
	}

int getOptionHashAlgo( void )
	{
	return( CRYPT_ALGO_SHA );
	}

int getOptionPKCAlgo( void )
	{
	return( CRYPT_ALGO_RSA );
	}

int getOptionCryptAlgo( void )
	{
	return( CRYPT_ALGO_3DES );
	}

int getOptionCryptMode( void )
	{
	return( CRYPT_MODE_CFB );
	}

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Get a nonce  It doesn't matter much what it is, as long as it's completely
   different for each call */

void getNonce( void *nonce, int nonceLength )
	{
	static BOOLEAN initialised = FALSE;
	static BYTE nonceBuffer[ CRYPT_MAX_HASHSIZE ];
	int hashInfoSize, hashInputSize, hashOutputSize;
	HASHFUNCTION hashFunction;
	BYTE *noncePtr = nonce;

	if( !initialised )
		{
		/* Seed the data with a value which is guaranteed to be different
		   each time (unless the entire program is rerun more than twice a
		   second, which is doubtful) */
		memset( nonceBuffer, 0, CRYPT_MAX_HASHSIZE );
		time( ( time_t * ) nonceBuffer );
		initialised = TRUE;
		}

	/* Get the hash algorithm information and repeatedly shuffle the bits and
	   copy them to the output buffer until it's full */
	if( !getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		{
		memset( nonce, '?', nonceLength );
		return;						/* API error, should never occur */
		}
	while( nonceLength )
		{
		int count = ( nonceLength > hashOutputSize ) ? hashOutputSize : nonceLength;

		/* Hash the nonce and copy the appropriate amount to the output
		   buffer */
		hashFunction( NULL, nonceBuffer, nonceBuffer, hashOutputSize, HASH_ALL );
		memcpy( noncePtr, nonceBuffer, count );

		/* Move on to the next block of the output buffer */
		noncePtr += count;
		nonceLength -= count;
		}
	}

/* Determine the parameters for a particular hash algorithm */

BOOLEAN getHashParameters( const CRYPT_ALGO hashAlgorithm,
						   HASHFUNCTION *hashFunction, int *hashInputSize,
						   int *hashOutputSize, int *hashInfoSize )
	{
	void nullHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void md2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void md4HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void md5HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void ripemd160HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
							  int length, const HASH_STATE hashState );
	void shaHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );

	switch( hashAlgorithm )
		{
		case CRYPT_ALGO_NONE:
			*hashFunction = nullHashBuffer;
			*hashInputSize = 1000;
			*hashOutputSize = CRYPT_MAX_HASHSIZE;
			*hashInfoSize = 0;
			break;

		case CRYPT_ALGO_MD2:
			*hashFunction = md2HashBuffer;
			*hashInputSize = MD2_DATASIZE;
			*hashOutputSize = MD2_DIGESTSIZE;
			*hashInfoSize = sizeof( MD2_INFO );
			break;

		case CRYPT_ALGO_MD4:
			*hashFunction = md4HashBuffer;
			*hashInputSize = MD4_DATASIZE;
			*hashOutputSize = MD4_DIGESTSIZE;
			*hashInfoSize = sizeof( MD4_INFO );
			break;

		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			*hashInputSize = MD5_DATASIZE;
			*hashOutputSize = MD5_DIGESTSIZE;
			*hashInfoSize = sizeof( MD5_INFO );
			break;

		case CRYPT_ALGO_RIPEMD160:
			*hashFunction = ripemd160HashBuffer;
			*hashInputSize = RIPEMD160_DATASIZE;
			*hashOutputSize = RIPEMD160_DIGESTSIZE;
			*hashInfoSize = sizeof( RIPEMD160_INFO );
			break;

		case CRYPT_ALGO_SHA:
			*hashFunction = shaHashBuffer;
			*hashInputSize = SHA_DATASIZE;
			*hashOutputSize = SHA_DIGESTSIZE;
			*hashInfoSize = sizeof( SHA_INFO );
			break;

		default:
			return( FALSE );	/* API error, should never occur */
		}

	return( TRUE );
	}

/* Byte-reverse an array of 16- and 32-bit words to/from network byte order
   to account for processor endianness.  These routines assume the given
   count is a multiple of 16 or 32 bits.  They are safe even for CPU's with
   a word size > 32 bits since on a little-endian CPU the important 32 bits
   are stored first, so that by zeroizing the first 32 bits and oring the
   reversed value back in we don't need to rely on the processor only writing
   32 bits into memory */

void longReverse( LONG *buffer, int count )
	{
#if defined( _BIG_WORDS )
	BYTE *bufPtr = ( BYTE * ) buffer, temp;

	count /= 4;		/* sizeof( LONG ) != 4 */
	while( count-- )
		{
  #if 0
		LONG temp;

		/* This code is cursed */
		temp = value = *buffer & 0xFFFFFFFFUL;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		value = ( ( value << 16 ) | ( value >> 16 ) ) ^ temp;
		*buffer ^= value;
		buffer = ( LONG * ) ( ( BYTE * ) buffer + 4 );
  #endif /* 0 */
		/* There's really no nice way to do this - the above code generates
		   misaligned accesses on processors with a word size > 32 bits, so
		   we have to work at the byte level (either that or turn misaligned
		   access warnings off by trapping the signal the access corresponds
		   to.  However a context switch per memory access is probably
		   somewhat slower than the current byte-twiddling mess) */
		temp = bufPtr[ 3 ];
		bufPtr[ 3 ] = bufPtr[ 0 ];
		bufPtr[ 0 ] = temp;
		temp = bufPtr[ 2 ];
		bufPtr[ 2 ] = bufPtr[ 1 ];
		bufPtr[ 1 ] = temp;
		bufPtr += 4;
		}
#elif defined( __WIN32__ )
	/* The following code which makes use of bswap is significantly faster
	   than what the compiler would otherwise generate.  This code is used
	   such a lot that it's worth the effort */
__asm {
	mov ecx, count
	mov edx, buffer
	shr ecx, 2
swapLoop:
	mov eax, [edx]
	bswap eax
	mov [edx], eax
	add edx, 4
	dec ecx
	jnz swapLoop
	}
#else
	LONG value;

	count /= sizeof( LONG );
	while( count-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
#endif /* _BIG_WORDS */
	}

void wordReverse( WORD *buffer, int count )
	{
	WORD value;

	count /= sizeof( WORD );
	while( count-- )
		{
		value = *buffer;
		*buffer++ = ( value << 8 ) | ( value >> 8 );
		}
	}

/* Load an IV into a CRYPT_INFO structure */

int loadIV( CRYPT_INFO *cryptInfo, const BYTE *iv, const int ivLength )
	{
	/* Load the IV of the required length.  If the required IV size is less
	   than the maximum possible IV size, we pad it to the right with
	   zeroes */
	cryptInfo->ivLength = ivLength;
	cryptInfo->ivCount = 0;
	memset( cryptInfo->iv, 0, CRYPT_MAX_IVSIZE );
	memcpy( cryptInfo->iv, iv, cryptInfo->ivLength );
	memcpy( cryptInfo->currentIV, cryptInfo->iv, CRYPT_MAX_IVSIZE );
	cryptInfo->ivSet = TRUE;
	if( cryptInfo->capabilityInfo->initIVFunction != NULL )
		{
		int status;

		status = cryptInfo->capabilityInfo->initIVFunction( cryptInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Match a given substring against a string in a case-insensitive manner */

#if !defined( __WINDOWS__ ) && !defined( __MSDOS__ )

static int strnicmp( const char *src, const char *dest, int length )
	{
	char srcCh, destCh;

	while( length-- )
		{
		/* Need to be careful with toupper() side-effects */
		srcCh = *src++;
		srcCh = toupper( srcCh );
		destCh = *dest++;
		destCh = toupper( destCh );

		if( srcCh != destCh )
			return( srcCh - destCh );
		}

	return( 0 );
	}
#endif /* !( __WINDOWS__ || __MSDOS__ ) */

BOOLEAN matchSubstring( const char *subString, const char *string )
	{
	char firstChar = toupper( subString[ 0 ] );
	int subStringlength = strlen( subString ), i;

	/* Check trivial cases */
	if( subString == NULL || string == NULL )
		return( FALSE );
	if( strlen( string ) < ( size_t ) subStringlength )
		return( FALSE );

	/* Perform a case-insensitive match for the required substring in the
	   user ID */
	for( i = 0; string[ i ]; i++ )
		if( ( toupper( string[ i ] ) == firstChar ) &&
			!strnicmp( subString, string + i, subStringlength ) )
				return( TRUE );

	return( FALSE );
	}

/****************************************************************************
*																			*
*							Secure malloc/free Routines						*
*																			*
****************************************************************************/

/* To support page locking we need to store some additional information with
   the memory block.  We do this by reserving an extra 16 bytes at the start
   of the block and saving the information there (the 16-byte size is to
   preserve alignment on most systems) */

typedef struct {
	BOOLEAN isLocked;				/* Whether this block is locked */
	int size;						/* Size of the block */
	} MEMLOCK_INFO;

#ifdef __UNIX__

/* Since the function prototypes for the SYSV/POSIX mlock() call are stored
   all over the place depending on the Unix version, we prototype it
   ourselves here rather than try to guess its location */

#if defined( __osf__ )
  #include <sys/mman.h>
#elif defined( sun )
  #include <sys/types.h>
#else
  int mlock( void *address, size_t length );
  int munlock( void *address, size_t length );
#endif /* Unix-variant-specific includes */

#endif /* __UNIX__ */

/* Set the memory lock type */

void setOptionMemoryLockType( int lockType )
	{
	memoryLockType = lockType;
	}

/* A secure version of malloc() and free() which perform page locking if
   necessary and zeroise memory before it is freed */

int secureMalloc( void **pointer, int size )
	{
	MEMLOCK_INFO *memLockPtr;
	BYTE *memPtr;

	/* Try and allocate the memory */		/* Shadu yu liktumkunushi */
	if( ( memPtr = malloc( size + 16 ) ) == NULL )
		{									/* Shadu yu liklakunushi */
		*pointer = NULL;					/* Shadu yu lini yix kunushi */
		return( CRYPT_NOMEM );				/* Shadu yu li yixsi kunushi */
		}									/* Shadu yu lite kunushi */
	memset( memPtr, 0, size + 16 );			/* Shadu yu lini kunushi */
	memLockPtr = ( MEMLOCK_INFO * ) memPtr;	/* Shadu yu linir kunushi */
	memLockPtr->isLocked = FALSE;			/* Shadu yu likattin kunushi */
	memLockPtr->size = size + 16;			/* Shadu yu dannu elikunu limqut */
	*pointer = memPtr + 16;					/* Ina zumri ya lu yu tapparrasama! */

	/* If the OS supports it, try to lock the pages in memory */
#ifdef __WIN16__
	/* Under Windows 3.x there's no support for memory locking, so we simply
	   return an error code for a forced lock */
	if( memoryLockType == CRYPT_MEMORY_FORCELOCK )
		{
		free( memPtr );
		*pointer = NULL;
		return( CRYPT_NOLOCK );
		}
#endif /* __WIN16__ */

#ifdef __WIN32__
	/* Under Win95 the VirtualLock() function appears to be implemented as
	   `return( TRUE )' ("Thank Microsoft kids" - "Thaaaanks Bill").  Under
	   NT the function does actually work */
	if( VirtualLock( memPtr, size ) )
		memLockPtr->isLocked = TRUE;
	else
		if( memoryLockType == CRYPT_MEMORY_FORCELOCK )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOLOCK );
			}
#endif /* __WIN32__ */

#ifdef __UNIX__
	/* Under many Unix variants the SYSV/POSIX mlock() call can be used, but
	   only by the superuser.  OSF/1 has mlock(), but this is defined to the
	   nonexistant memlk() so we need to special-case it out.  Aches and PHUX
	   don't even pretend to have mlock().  Many systems also have plock(),
	   but this is pretty crude since it locks all data, and also has various
	   other shortcomings.  Finally, PHUX has datalock(), which is just a
	   plock() variant */
  #if !( defined( __osf__ ) || defined( _AIX ) || defined( __hpux ) || \
		 defined( _M_XENIX ) )
	if( !mlock( memPtr, size ) )
		memLockPtr->isLocked = TRUE;
	else
  #endif /* !( __osf__ || _AIX || __hpux || _M_XENIX ) */
		if( memoryLockType == CRYPT_MEMORY_FORCELOCK )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOLOCK );
			}
#endif /* __UNIX__ */

	return( CRYPT_OK );
	}

/* A safe free function which scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

void secureFree( void **pointer )
	{
	MEMLOCK_INFO *memLockPtr;
	BYTE *memPtr = ( BYTE * ) *pointer;

	/* Make sure we're not trying to free unallocated memory */
	if( memPtr == NULL )
		return;

	/* If the memory is locked, unlock it now */
	memPtr -= 16;
	memLockPtr = ( MEMLOCK_INFO * ) memPtr;
#if defined( __UNIX__ ) && !( defined( __osf__ ) || defined( _AIX ) || \
							  defined( __hpux ) || defined _M_XENIX )
	if( memLockPtr->isLocked )
		munlock( memPtr, memLockPtr->size );
#endif /* __UNIX__ && !( __osf__ || _AIX || __hpux || _M_XENIX ) */
#ifdef __WIN32__
	if( memLockPtr->isLocked )
		VirtualUnlock( memPtr, memLockPtr->size );
#endif /* __WIN32__ */

	/* Zeroise the memory, free it, and zero the pointer */
	zeroise( memPtr, memLockPtr->size );
	free( memPtr );
	*pointer = NULL;
	}

/* An alternative version of secureFree() which doesn't work with locked
   memory blocks.  This is mainly a convenience function for low-security
   memory areas */

void cleanFree( void **pointer, int size )
	{
	if( *pointer != NULL )
		{
		zeroise( *pointer, size );
		free( *pointer );
		*pointer = NULL;
		}
	}

/****************************************************************************
*																			*
*		Reduce a Variable-length User Key to a Fixed Encryption Key			*
*																			*
****************************************************************************/

/* Derive an encryption key from a variable-length user key (the simpler
   cryptDeriveKey() form is just a macro which expands to
   cryptDeriveKeyEx()).  This function works as follows:

   key[] = { 0 };
   state = hash( algorithm, mode, parameters, userKey );

   for count = 1 to iterations
	 for length = 1 to keyLength
	   state = hash( state );
	   key[ length ] = hash( state, userKey );

   The state acts as an RNG which ensures that the user key hashing is
   serialized (ie that any form of parallelization or precomputation isn't
   possible) */

CRET cryptDeriveKeyEx( CRYPT_CONTEXT cryptContext, const void CPTR userKey,
					   const int userKeyLength, const CRYPT_ALGO algorithm,
					   const int iterations )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CRYPT_ALGO hashAlgorithm = algorithm;
	BYTE *hashInfo, *keyBuffer, *state, *temp, *userKeyPtr = ( BYTE * ) userKey;
	BYTE buffer[ 50 ];
	int keyLength, keySetupIterations = iterations, iterationCount;
	int hashInfoSize, hashInputSize, hashOutputSize, status;
	HASHFUNCTION hashFunction;
	STREAM stream;

	/* Perform basic error checking.  We check for the availability of the
	   hash algorithm and whether the iteration count has a sane value
	   because it may have come from a high-level object query function which
	   read corrupted data */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( userKey == NULL )
		return( CRYPT_BADPARM2 );
	if( userKeyLength <= 0 )
		return( CRYPT_BADPARM3 );
	if( keySetupIterations == CRYPT_USE_DEFAULT )
		keySetupIterations = DEFAULT_KEYSETUP_ITERATIONS;
	if( hashAlgorithm == CRYPT_USE_DEFAULT )
		hashAlgorithm = DEFAULT_KEYSETUP_ALGO;
	if( cryptStatusError( cryptModeAvailable( hashAlgorithm, CRYPT_MODE_NONE ) ) )
		return( CRYPT_BADPARM4 );
	if( keySetupIterations < 1 || keySetupIterations > 20000 )
		return( CRYPT_BADPARM5 );

	/* If it's a hash function or PKC, the derive key operation is
	   meaningless */
	if( cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE || \
		cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );

	/* Get the hash algorithm information */
	if( !getHashParameters( hashAlgorithm, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );	/* API error, should never occur */

	/* Allocate storage for the hash information, the RNG state information,
	   the hash output temporary storage which is used to build up the key,
	   and the encryption key itself.  Since the memory is pagelocked, we
	   pack it all into a single block of memory from which we suballocate
	   the required chunks (this should all fit into a 4K page.  Even if it's
	   not locked it's being constantly touched so shouldn't ever get paged) */
	keyLength = cryptInfoPtr->capabilityInfo->keySize;
	if( ( status = secureMalloc( ( void ** ) &hashInfo, hashInfoSize + \
								 hashOutputSize + hashOutputSize + \
								 keyLength ) ) != CRYPT_OK )
		return( status );
	state = hashInfo + hashInfoSize;
	temp = state + hashOutputSize;
	keyBuffer = temp + hashOutputSize;

	/* Generate the initial state information from the user key.  If we
	   hashed the key directly and then used it for a number of algorithms
	   then someone who could recover the key for one algorithm could
	   compromise it if used for other algorithms (for example recovering a
	   DES key would also recover half an IDEA key), so we hash the
	   contents of a KeyInformation record so that all the information
	   about the algorithm and mode being used influences the state.  This
	   means that a successful attack one an algorithm, mode, or
	   configuration won't allow the key for any other algorithm, mode, or
	   configuration to be recovered */
	sMemOpen( &stream, buffer, 50 );
	status = writeKeyInfoHeader( &stream, cryptInfoPtr, userKeyLength );
	if( cryptStatusError( status ) )
		{
		secureFree( ( void ** ) &hashInfo );
		return( status );
		}
	hashFunction( hashInfo, NULL, buffer, sMemSize( &stream ), HASH_START );
	hashFunction( hashInfo, state, userKeyPtr, userKeyLength, HASH_END );
	sMemClose( &stream );

	/* Hash the variable-length input to a fixed-length output */
	memset( keyBuffer, 0, keyLength );
	for( iterationCount = 0; iterationCount < keySetupIterations; iterationCount++ )
		{
		int keyIndex, length;

		for( keyIndex = 0; keyIndex < keyLength; keyIndex += hashOutputSize )
			{
			int i;

			/* state = hash( state ); key[ n ] = hash( state, userKey ) */
			hashFunction( hashInfo, state, state, hashOutputSize, HASH_ALL );
			hashFunction( hashInfo, NULL, state, hashOutputSize, HASH_START );
			hashFunction( hashInfo, temp, userKeyPtr, userKeyLength, HASH_END );

			/* Copy as much of the hashed data as required to the output */
			length = ( keyLength - keyIndex ) % hashOutputSize;
			for( i = 0; i < length; i++ )
				keyBuffer[ i ] ^= temp[ i ];
			}
		}

	/* Copy the result into the encryption context */
	status = cryptLoadContext( cryptContext, keyBuffer, keyLength );
	if( cryptStatusOK( status ) )
		{
		/* Remember the setup parameters */
		cryptInfoPtr->keySetupIterations = keySetupIterations;
		cryptInfoPtr->keySetupAlgorithm = hashAlgorithm;
		}

	/* Clean up */
	secureFree( ( void ** ) &hashInfo );
	return( status );
	}
