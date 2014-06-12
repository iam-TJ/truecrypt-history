/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* Various compilers handle includes in subdirectories differently.  Most
   will work with paths from a root directory.  Macintoshes don't recognise
   '/'s as path delimiters, but work around it by scanning all 
   subdirectories and treating the files as if they were in the same
   directory (INC_ALL).  Microsoft C, in a braindamaged exception to all
   other compilers, treats the subdirectory as the root (INC_CHILD) */

#if ( defined( __MWERKS__ ) || defined( SYMANTEC_C ) ) && !defined( INC_ALL )
  #error You need to predefine INC_ALL in your project file
#elif defined( _MSC_VER ) && !defined( INC_CHILD )
  #error You need to predefine INC_CHILD in your project/make file
#endif /* Checks for various compiler/OS-dependant include paths */

/* If the global crypt API header hasn't been included yet, include it now */

#ifndef _CAPI_DEFINED
  #include "capi.h"
#endif /* _CAPI_DEFINED */

/* If the BigNum header hasn't been included yet, include it now.  This is a
   bit of a waste since it isn't used in most files, but we need it to
   declare various members of the encryption context structure */

#ifndef BN_H
  #if defined( INC_ALL )
	#include "bn.h"
  #else
	#include "bnlib/bn.h"
  #endif /* Compiler-specific includes */
#endif /* BN_H */

/****************************************************************************
*																			*
*								OS-Specific Defines							*
*																			*
****************************************************************************/

/* Try and figure out if we're running under Windows and/or Win32.  We have
   to jump through all sorts of hoops later on, not helped by the fact that
   the method of detecting Windows at compile time changes with different
   versions of Visual C (it's different for each of VC 2.0, 2.1, 4.0, and
   4.1.  They probably change it again in 4.2 but I don't have a copy to
   test) */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* !__WINDOWS__ && ( _Windows || _WINDOWS ) */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
	#define __WINDOWS__
  #endif /* __WINDOWS__ */
  #define __WIN32__
#endif /* !__WIN32__ && ( WIN32 || _WIN32 ) */
#if defined( __WINDOWS__ ) && !defined( __WIN32__ )
  #define __WIN16__
#endif /* __WINDOWS__ && !__WIN32__ */

/* Fix up a type clash with a Windows predefined type - for some reason BYTE
   and WORD are unsigned, but LONG is signed (actually DWORD is the Windows
   unsigned type, the counterpoint CHAR, SHORT and LONG types are all signed,
   but DWORD is a Windows-ism which all the Unix types will LART me for if I
   start using it) */

#if defined( __WINDOWS__ )
  #undef LONG
#endif /* __WINDOWS__ */

/* Some encryption algorithms which rely on longints having 32 bits won't
   work on 64- or 128-bit machines due to problems with sign extension and
   whatnot.  The following define can be used to enable special handling for
   processors with a > 32 bit word size */

#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define _BIG_WORDS
#endif /* LONG > 32 bits */

/* Some useful types.  We have to jump through all sorts of hoops for
   Windoze */

#ifndef __WIN32__
  typedef int				BOOLEAN;
#endif /* __WIN32__ */
typedef unsigned char		BYTE;
#if !defined( __WINDOWS__ ) || defined( __WIN32__ )
  typedef unsigned short	WORD;
#endif /* !__WINDOWS__ || __WIN32__ */
#ifdef __WIN32__
  #pragma warning( disable : 4142 )
  typedef unsigned long		LONG;
  #pragma warning( default : 4142 )
  #ifdef _WIN32
	/* Visual C 2.1+ doesn't seem to like LONG being typedef'd to unsigned
	   no matter what you do, so we rely on the preprocessor to get rid of
	   the problem.  Visual C 2.1+ defined _WIN32 whereas 2.0 defined WIN32,
	   so we can use this to tell the two apart */
	#define LONG	unsigned long
  #endif /* _WIN32 */
#else
  typedef unsigned long		LONG;
#endif  /* __WIN32__ */

/* Boolean constants */

#ifndef TRUE
  #define FALSE			0
  #define TRUE			!FALSE
#endif /* TRUE */

/* If the endianness is not defined and the compiler can tell us what
   endianness we've got, use this in preference to all other methods.  This
   is only really necessary on non-Unix systems since the makefile kludge
   will tell us the endianness under Unix */

#if !defined( LITTLE_ENDIAN ) && !defined( BIG_ENDIAN )
  #if defined( _M_I86 ) || defined( _M_IX86 ) || defined( __TURBOC__ )
	#define LITTLE_ENDIAN		/* Intel architecture always little-endian */
  #elif defined( AMIGA ) || defined( __MWERKS__ ) || defined( SYMANTEC_C )
	#define BIG_ENDIAN			/* Motorola architecture always big-endian */
  #elif defined( VMS ) || defined( __VMS )
	#define LITTLE_ENDIAN		/* VAX architecture always little-endian */
  #elif defined __GNUC__
	#ifdef BYTES_BIG_ENDIAN
	  #define BIG_ENDIAN		/* Big-endian byte order */
	#else
	  #define LITTLE_ENDIAN		/* Undefined = little-endian byte order */
	#endif /* __GNUC__ */
  #endif /* Compiler-specific endianness checks */
#endif /* !( LITTLE_ENDIAN || BIG_ENDIAN ) */

/* The last-resort method.  Thanks to Shawn Clifford
   <sysop@robot.nuceng.ufl.edu> for this trick.

   NB: A number of compilers aren't tough enough for this test */

#if !defined( LITTLE_ENDIAN ) && !defined( BIG_ENDIAN )
  #if ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'B' )
	#define LITTLE_ENDIAN
  #elif ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'A' )
	#define BIG_ENDIAN
  #else
	#error Cannot determine processor endianness - edit crypt.h and recompile
  #endif /* Endianness test */
#endif /* !( LITTLE_ENDIAN || BIG_ENDIAN ) */

/* Some systems define both BIG_ENDIAN and LITTLE_ENDIAN, then define
   BYTE_ORDER to the appropriate one, so we check this and undefine the
   appropriate one */

#if defined( BIG_ENDIAN ) && defined( LITTLE_ENDIAN )
  #ifdef BYTE_ORDER
	#if BYTE_ORDER == BIG_ENDIAN
	  #undef LITTLE_ENDIAN
	#else
	  #undef BIG_ENDIAN
	#endif /* BYTE_ORDER-specific undef */
  #else
	#error Both LITTLE_ENDIAN and BIG_ENDIAN are defined in crypt.h - edit the settings and recompile
  #endif /* BYTE_ORDER */
#endif /* LITTLE_ENDIAN && BIG_ENDIAN */

/* Some C routines can be replaced with faster assembly-language equivalents
   for some systems.  These should really be defined in a makefile, but
   smegging Visual C will silently truncate all command-line defines when
   the line goes over 127 characters, so we define them here instead and
   save the makefile command line for other things */

#if defined( __MSDOS__ ) || defined( __WIN16__ )
  #define ASM_SAFER
#endif /* __MSDOS__ || __WIN16__ */

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* If we're running on a 64-bit CPU we often need to mask values off to 32
   bits.  The following define enables this if the CPU word size is
   > 64 bits */

#ifdef _BIG_WORDS
  #define MASK32( x )	( ( x ) & 0xFFFFFFFFUL )
#else
  #define MASK32( x )	x
#endif /* _BIG_WORDS */

/* The odd algorithm needs masking to 16 bits */

#if UINT_MAX > 0xFFFFUL
  #define MASK16( x )	( ( x ) & 0xFFFFUL )
#else
  #define MASK16( x )	x
#endif /* > 16-bit ints */

/* If we're running on a machine with > 32 bit wordsize we need to jump
   through all sorts of hoops to convert data from arrays of bytes to arrays
   of longints.  The following macros pull bytes out of memory and assemble
   them into a longword, and deposit a longword into memory as a series of
   bytes.  This code really blows on any processors which need to use it */

#ifdef BIG_ENDIAN
	#define mgetLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ] << 16 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( ( LONG ) memPtr[ 3 ] ) ); \
		memPtr += 4

	#define mputLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4
#else
	#define mgetLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] ) | ( ( LONG ) memPtr[ 1 ] << 8 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 16 ) | ( ( LONG ) memPtr[ 3 ] << 24 ) ); \
		memPtr += 4

	#define mputLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr += 4
#endif /* BIG_ENDIAN */

/* Copy an array of bytes to an array of 32-bit words.  We need to take
   special precautions when the machine word size is > 32 bits because we
   can't just assume BYTE[] == LONG[] */

#ifdef _BIG_WORDS
  #define copyToLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetLong( srcPtr ); \
						} \
					}
#else
  #define copyToLong(dest,src,count) \
					memcpy( dest, src, count )
#endif /* _BIG_WORDS */

/* Versions of the above which are guaranteed to always be big or
   little-endian (these are needed for some algorithms where the external
   data format is always little-endian, eg anything designed by Ron
   Rivest) */

#define mgetBWord(memPtr)		\
		( ( WORD ) memPtr[ 0 ] << 0 ) | ( ( WORD ) memPtr[ 1 ] ); \
		memPtr += 2

#define mputBWord(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 2

#define mgetBLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ] << 16 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( LONG ) memPtr[ 3 ] ); \
		memPtr += 4

#define mputBLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4

#define mgetLWord(memPtr)		\
		( ( WORD ) memPtr[ 0 ] ) | ( ( WORD ) memPtr[ 1 ] << 8 ); \
		memPtr += 2

#define mputLWord(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr += 2

#define mgetLLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] ) | ( ( LONG ) memPtr[ 1 ] << 8 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 16 ) | ( ( LONG ) memPtr[ 3 ] << 24 ) ); \
		memPtr += 4

#define mputLLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr += 4

#ifdef _BIG_WORDS
  #define copyToLLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetLLong( srcPtr ); \
						} \
					}

  #define copyToBLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetBLong( srcPtr ); \
						} \
					}
#endif /* _BIG_WORDS */

/* Functions to convert the endianness from the canonical form to the
   internal form.  bigToLittle() convert from big-endian in-memory to
   little-endian in-CPU, littleToBig() convert from little-endian in-memory
   to big-endian in-CPU */

void longReverse( LONG *buffer, int count );
void wordReverse( WORD *buffer, int count );

#ifdef LITTLE_ENDIAN
  #define bigToLittleLong( x, y )	longReverse(x,y)
  #define bigToLittleWord( x, y )	wordReverse(x,y)
  #define littleToBigLong( x, y )
  #define littleToBigWord( x, y )
#else
  #define bigToLittleLong( x, y )
  #define bigToLittleWord( x, y )
  #define littleToBigLong( x, y )	longReverse(x,y)
  #define littleToBigWord( x, y )	wordReverse(x,y)
#endif /* LITTLE_ENDIAN */

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* The size of the key cookie for session keys and signature cookie for
   signed data */

#define KEY_COOKIE_SIZE			4
#define SIGNATURE_COOKIE_SIZE	8

#define MAX_COOKIE_SIZE			SIGNATURE_COOKIE_SIZE

/* The maximum possible IV size.  Although CRYPT_MAX_IVSIZE is standardised
   at 64 bits to hide the details of the algorithm being used when the
   algorithm is decided via a high-level function, some algorithms have
   larger block sizes which require more than 64 bits of IV.  The MAX_IVSIZE
   define is provided to declare storage space for these internal IV's */

#define MAX_IVSIZE			32

/* The quantization level for KeyInfo records.  Records which are visible
   to outsiders are padded out to a multiple of this size to obscure the
   nature of their contents */

#define KEYINFO_PADSIZE		64

/* Declare a BigNum type to save having to use `struct BigNum' all over the
   place */

typedef struct BigNum	BIGNUM;

/* A forward declaration for the parameter type passed to functions in the
   CAPABILITY_INFO struct */

struct CI;

/* The structure used to store internal information about the crypto library
   capabilities.  This information is used internally by the library and is
   not available to users */

typedef struct CA {
	/* Basic identification information for the algorithm */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */
	int blockSize;					/* The basic block size of the algorithm */
	char *algoName;					/* Algorithm name */
	char *modeName;					/* Mode name */
	int speed;						/* Speed relative to block copy */

	/* Keying information.  Note that the maximum sizes may vary (for
	   example for two-key triple DES vs three-key triple DES) so the
	   crypt query functions should be used to determine the actual size
	   for a particular context rather than just using maxKeySize */
	int minKeySize;					/* Minimum key size in bytes */
	int keySize;					/* Recommended key size in bytes */
	int maxKeySize;					/* Maximum key size in bytes */

	/* IV information */
	int minIVsize;					/* Minimum IV size in bytes */
	int ivSize;						/* Recommended IV size in bytes */
	int maxIVsize;					/* Maximum IV size in bytes */

	/* The functions for implementing the algorithm */
	int ( *selfTestFunction )( void );
	int ( *initFunction )( struct CI CPTR cryptInfo );
	int ( *initExFunction )( struct CI CPTR cryptInfo, const void CPTR cryptInfoEx );
	int ( *endFunction )( struct CI CPTR cryptInfo );
	int ( *initKeyFunction )( struct CI CPTR cryptInfo );
	int ( *initIVFunction )( struct CI CPTR cryptInfo );
	int ( *getKeysizeFunction )( struct CI CPTR cryptInfo );
	int ( *getDataFunction )( struct CI CPTR cryptInfo, void CPTR buffer );
	int ( *encryptFunction )( struct CI CPTR cryptInfo, void CPTR buffer, int length );
	int ( *decryptFunction )( struct CI CPTR cryptInfo, void CPTR buffer, int length );

	/* The results of the self-test for this algorithm */
	int selfTestStatus;

	/* The next record in the list */
	struct CA *next;				/* Pointer to the next record */
	} CAPABILITY_INFO;

/* An encryption context.  Note the order of the BYTE[] fields in this
   structure, which ensures they're aligned to the machine word size */

typedef struct CI {
	/* Whether this is a conventional or PKC context */
	BOOLEAN isPKCcontext;			/* Whether this is a PKC context */

	/* Basic information on the encryption we're using */
	CAPABILITY_INFO *capabilityInfo;/* The encryption capability data */

	/* User keying information.  The user key is the key as entered by the
	   user, the IV is the initial IV stored in canonical form */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];		/* User encryption key */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* Initial IV */
	int userKeyLength;				/* User encryption key length in bytes */
	int ivLength;					/* IV length in bytes */
	BOOLEAN keySet;					/* Whether the key is set up */
	BOOLEAN ivSet;					/* Whether the IV is set up */

	/* Control information for the key.  The key control vector is applied
	   in the standard IBM-designed way, and may also be used to control
	   hardware-based encryption systems.  The key cookie is the first
	   KEY_COOKIE_SIZE bytes of the hash of the DER-encoded key information
	   record */
	long controlVector;				/* User key control vector */
	BYTE keyCookie[ KEY_COOKIE_SIZE ];	/* Key cookie for this algo/mode/key */
	int exportKeyCookie;			/* Whether to export the key cookie */

	/* Information obtained when a key suitable for use by this algorithm
	   is derived from a longer user key */
	int keySetupIterations;			/* Number of times setup was iterated */
	CRYPT_ALGO keySetupAlgorithm;	/* Algorithm used for key setup */

	/* Conventional encryption keying information.  The key is the raw
	   encryption key stored in whatever form is required by the algorithm.
	   This may be simply an endianness-adjusted form of the transformed key
	   (in the case of algorithms like MDC/SHS) or a processed form of the
	   user key (in the case of algorithms like DES or IDEA).  The IV is the
	   current working IV stored in an endianness-adjusted form.  The ivCount
	   is the number of bytes of IV in use, and may be used for various
	   chaining modes.  These fields may be unused if the algorithm is
	   implemented in hardware */
	void *key;						/* Internal working key */
	BYTE currentIV[ MAX_IVSIZE ];	/* Internal working IV */
	int keyLength;					/* Internal key length in bytes */
	int ivCount;					/* Internal IV count for chaining modes */

	/* Public-key encryption keying information.  The key component pointer
	   is a generic pointer to the structure containing the various PKC key
	   components.  The BigNums are the key components which are loaded from
	   the key component pointer when loadCryptContext() is called.  Since
	   each algorithm has its own unique parameters, they are given generic
	   names here.  The actual algorithm implementations refer to them by
	   their actual names, which are implemented as symbolic defines of the
	   form <algo>Param_<param_name>, eg rsaParam_e */
	void *keyComponentPtr;			/* Key components in external form */
	BOOLEAN keyComponentsLittleEndian;	/* Whether key components are l/e */
	BOOLEAN isPublicKey;			/* Whether key is a public key */
	int keySizeBits;				/* Nominal key size in bits */
	BIGNUM pkcParam1;
	BIGNUM pkcParam2;
	BIGNUM pkcParam3;
	BIGNUM pkcParam4;
	BIGNUM pkcParam5;
	BIGNUM pkcParam6;
	BIGNUM pkcParam7;
	BIGNUM pkcParam8;				/* The PKC key components */
	BYTE keyID[ CRYPT_MAX_KEYIDSIZE ];	/* Encoded key ID for this key */
	int keyIDlength;				/* Length of key ID data */
	int exportSigCookie;			/* Whether to export the sig.cookie */
	BYTE sigCookie[ SIGNATURE_COOKIE_SIZE ];	/* Sig.cookie for this sig.*/
	BOOLEAN useOAEP;				/* Whether to use Bellare-Rogaway
									   optimal asymmetric encryption padding */
	char *userID;					/* User ID for this key when stored
									   externally */

	/* Once the key components are stored in the internal form, retrieving
	   them from the algorithm-dependant BigNum storage is somewhat complex,
	   so we keep a copy of the components in the original external form
	   alongside the data in BigNum form.  The following field is used as a
	   pointer to the appropriate CRYPT_PKCINFO_xxx structure */
	void *pkcInfo;

	/* Private data needed by the algorithm.  We also keep track of whether
	   we're using default values for the private data settings */
	void *privateData;				/* For private use */
	BOOLEAN privateUseDefaults;		/* Whether priv.data vals.are defaults */

	/* Some of the high-level library routines call the lower-level ones with
	   preformatted data to process in the buffer passed to the routine.  If
	   this is sensitive, it should be cleared as soon as it is no longer
	   used.  However if the lower-level routine is called directly by the
	   user, the input buffer shouldn't be modified.  The following flag
	   determines whether the buffer should be cleared.  The use of this flag
	   isn't necessary for the PKC functions which always clear the buffer
	   while the data in it is stored in a bignum */
	BOOLEAN clearBuffer;

	/* A check value so we can determine whether the crypt context has been
	   initialised or not.  This is needed because passing in an
	   uninitialised block of memory as a crypt context can lead to problems
	   when we try to dereference wild pointers */
	LONG checkValue;

	/* The next and previous encryption context in the linked list of
	   contexts */
	struct CI *next, *prev;
	} CRYPT_INFO;

/* Symbolic defines for the various PKC components for different PKC
   algorithms */

#define rsaParam_n			pkcParam1
#define rsaParam_e			pkcParam2
#define rsaParam_d			pkcParam3
#define rsaParam_p			pkcParam4
#define rsaParam_q			pkcParam5
#define rsaParam_u			pkcParam6
#define rsaParam_exponent1	pkcParam7
#define rsaParam_exponent2	pkcParam8

#define dsaParam_p			pkcParam1
#define dsaParam_q			pkcParam2
#define dsaParam_g			pkcParam3
#define dsaParam_x			pkcParam4
#define dsaParam_y			pkcParam5

#define dhParam_p			pkcParam1
#define dhParam_g			pkcParam2
#define dhParam_x			pkcParam3
#define dhParam_y			pkcParam4

/* Because there's no really clean way to throw an exception in C and the
   bnlib routines don't carry around state information like the stream
   library does, we need to perform an error check for most of the routines
   we call.  To make this slightly less ugly we define the following macro
   which performs the check for us by updating a variable called `status'
   with the result of a bnlib call */

#define CK( x )	status |= x

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner */

#define UNUSED( arg )	( ( arg ) = ( arg ) )

/* Although min() and max() aren't in the ANSI standard, most stdlib.h's have
   them anyway for historical reasons.  Just in case they're not defined
   there by some pedantic compiler (some versions of Borland C do this), we
   define them here */

#ifndef max
  #define max( a, b )	( ( ( a ) > ( b ) ) ? ( a ) : ( b ) )
#endif /* !max */
#ifndef min
  #define min( a, b )	( ( ( a ) < ( b ) ) ? ( a ) : ( b ) )
#endif /* !min */

/* Whether an encryption mode needs an IV or not */

#define needsIV( mode )	( mode == CRYPT_MODE_CBC || \
						  mode == CRYPT_MODE_CFB || \
						  mode == CRYPT_MODE_OFB || \
						  mode == CRYPT_MODE_PCBC )

/* Whether an algorithm is a PKC algorithm */

#define isPKCalgorithm( algorithm )	\
	( algorithm >= CRYPT_ALGO_RSA && algorithm <= CRYPT_ALGO_DSS )

/* To convert from the external cookies which are used to reference internal
   data structures to the internal structure itself, we subtract an offset
   from the external cookie to obtain a pointer to the internal structure.
   The use of the conversion offset means programs outside the library
   security perimeter will generate a protection violation if they try to
   treat the cookie as a pointer to anything unless they go to some lengths
   to determine the conversion value.  To this end makeCookie() forces an odd
   address which gives an address error on many architectures */

extern int cryptContextConversionOffset;

#define CONTEXT_TO_INFO( x )	( CRYPT_INFO * ) ( ( BYTE * ) x - cryptContextConversionOffset )
#define INFO_TO_CONTEXT( x )	( CRYPT_CONTEXT ) ( ( BYTE * ) x + cryptContextConversionOffset )

#define makeCookie( cookie )	( cookie | 1 )
#define isBadCookie( cookie )	( cookie == NULL || !( ( int ) ( ( long ) cookie ) & 1 ) )

/* A magic value to detect whether an internal structure has been
   initialised yet */

#define CRYPT_MAGIC		0xC0EDBABEUL

/* The default number of setup iterations and hash algorithm for
   cryptDeriveKey() */

#define DEFAULT_KEYSETUP_ITERATIONS	100
#define DEFAULT_KEYSETUP_ALGO		CRYPT_ALGO_SHA

/* The precise type of the key file or database we're working with.  This is
   used for type checking to make sure we don't try to find private keys in
   a collection of public-key certificates or whatever */

typedef enum {
	KEYSET_SUBTYPE_NONE,			/* Unknown */
	KEYSET_SUBTYPE_ERROR,			/* Bad keyset format */
	KEYSET_SUBTYPE_PUBLIC,			/* Public keys */
	KEYSET_SUBTYPE_PRIVATE			/* Private keys */
	} KEYSET_SUBTYPE;

/* Secure and lower-security memory handling functions */

int secureMalloc( void **pointer, int size );
void secureFree( void **pointer );
void cleanFree( void **pointer, int count );

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter 0 all the time, and
   makes it obvious where sensitive data is being erased */

#define zeroise( memory, size )		memset( memory, 0, size )

/* Routines to get/set algorithm-specific information.  These should really
   be implemented as capabilityInfo function pointers but this makes type
   checking difficult */

BOOLEAN getDESinfo( const CRYPT_INFO *cryptInfo );
void setDESinfo( CRYPT_INFO *cryptInfo, const BOOLEAN isDESX );
BOOLEAN get3DESinfo( const CRYPT_INFO *cryptInfo );
void set3DESinfo( CRYPT_INFO *cryptInfo, const BOOLEAN isThreeKey );
int getMDCSHSinfo( const CRYPT_INFO *cryptInfo );
void setMDCSHSinfo( CRYPT_INFO *cryptInfo, const int keySetupIterations );
int getRC5info( const CRYPT_INFO *cryptInfo );
void setRC5info( CRYPT_INFO *cryptInfo, const int rounds );
int getSaferInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useSaferSK );
void setSaferInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useSaferSK,
				   const int rounds );
int getBlowfishInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useBlowfishSK );
void setBlowfishInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useBlowfishSK,
					  const int keySetupIterations );
BOOLEAN getSHAinfo( const CRYPT_INFO *cryptInfo );
void setSHAinfo( CRYPT_INFO *cryptInfo, const BOOLEAN isSHA );

/* Random data management routines */

int getRandomByte( void );
void endRandom( void );
void getNonce( void *nonce, int nonceLength );

/* Key management routines */

BOOLEAN matchSubstring( const char *subString, const char *string );
int generateKeyID( CRYPT_ALGO algorithm, BYTE *keyID, int *keyIDlength, \
				   void *pkcInfo );
int generateKeyCookie( CRYPT_INFO *cryptInfo );
int loadIV( CRYPT_INFO *cryptInfo, const BYTE *iv, const int ivLength );

/* Key database routines.  These are handled internally by cryptdbx.c since
   the involve manipulation of KEYSET_INFO structures which aren't exported
   to the library as a whole */

int setKeysetNames( void *keySet, CRYPT_IOCTLINFO_KEYSETNAMES *ioctlInfo );

/* Hash state information.  We can either call the hash function with
   HASH_ALL to process an entire buffer at a time, or HASH_START/
   HASH_CONTINUE/HASH_END to process it in parts */

typedef enum { HASH_START, HASH_CONTINUE, HASH_END, HASH_ALL } HASH_STATE;

/* The hash functions are used quite a bit by the library so we provide an
   internal API for them to avoid the overhead of having to set up an
   encryption context every time they're needed.  These take a block of
   input data and hash it, leaving the result in the output buffer.  If the
   hashState parameter is HASH_ALL the the hashInfo parameter may be NULL,
   in which case the function will use its own memory for the hashInfo */

#define MAX_HASHINFO_SIZE	200

typedef void ( *HASHFUNCTION )( void *hashInfo, BYTE *outBuffer, \
								BYTE *inBuffer, int length, \
								const HASH_STATE hashState );

BOOLEAN getHashParameters( const CRYPT_ALGO hashAlgorithm,
						   HASHFUNCTION *hashFunction, int *hashInputSize,
						   int *hashOutputSize, int *hashInfoSize );

/* Query library config options.  Note that the return values have to be
   int's rather than BOOLEAN's because they can be CRYPT_USE_DEFAULT as well
   as TRUE or FALSE */

void setOptionMemoryLockType( int memoryLockType );
void setOptionExportKeyCookie( const BOOLEAN option );
BOOLEAN getOptionExportKeyCookie( void );
void setOptionExportSigCookie( const BOOLEAN option );
BOOLEAN getOptionExportSigCookie( void );
void setOptionUseOAEP( const BOOLEAN option );
BOOLEAN getOptionUseOAEP( void );
void setOptionKeysetNames( const CRYPT_IOCTLINFO_KEYSETNAMES *keysetNames );
void getOptionKeysetNames( CRYPT_IOCTLINFO_KEYSETNAMES *keysetNames );
int getOptionHashAlgo( void );
int getOptionPKCAlgo( void );
int getOptionCryptAlgo( void );
int getOptionCryptMode( void );

#endif /* _CRYPT_DEFINED */
