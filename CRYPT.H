#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* If the global crypt API header hasn't been included yet, include it now */

#ifndef _CAPI_DEFINED
  #include "capi.h"
#endif /* _CAPI_DEFINED */

/* If the BigNum header hasn't been included yet, include it now.  This is a
   bit of a waste since it isn't used in most files, but we need it to
   declare various members of the encryption context structure */

#ifndef BN_H
  #include "bnlib/bn.h"
#endif /* BN_H */

/****************************************************************************
*																			*
*								OS-Specific Defines							*
*																			*
****************************************************************************/

/* Try and figure out if we're running under Windoze and/or Win32.  We have
   to jump through all sorts of hoops later on, not helped by the fact that
   the method of detecting Windoze at compile time changes with different
   versions of Visual C */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* !__WINDOWS__ && ( _Windows || _WINDOWS ) */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
    #define __WINDOWS__
  #endif /* __WINDOWS__ */
  #define __WIN32__
#endif /* !__WIN32__ && ( WIN32 || _WIN32 ) */

/* Fixup for Windoze support.  We need to include windows.h for various types
   and prototypes needed for DLL's, and then fix up a type clash with a
   Windows predefined type - for some bizarre reason BYTE and WORD are
   unsigned, but LONG is signed */

#if defined( __WINDOWS__ )
  #include <windows.h>
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
#endif /* !__WIN32__ */
typedef unsigned char		BYTE;
#ifndef __WINDOWS__
  typedef unsigned short	WORD;
#endif /* __WINDOWS__ */
#ifdef __WIN32__
  #pragma warning( disable : 4142 )
  typedef unsigned long		LONG;
  #pragma warning( default : 4142 )
  #ifdef _WIN32
	/* Visual C 2.1 doesn't seem to like LONG being typedef'd to unsigned
	   no matter what you do, so we rely on the preprocessor to get rid of
	   the problem.  Visual C 2.1 defined _WIN32 whereas 2.0 defined WIN32,
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

/* Machine-dependent types to allow use in special library types such as
   DLL's */

#if defined( __WINDOWS__ ) && !defined( __WIN32__ )
  #define CPTR	FAR *						/* DLL pointer */
  #define CRET	int FAR PASCAL _export		/* DLL return value */
#else
  #define CPTR	*							/* General pointer */
  #define CRET	int							/* General return value */
#endif /* __WINDOWS__ && !__WIN32__ */

/* Some systems have machine-specific include files which define the
   endianness.

   The braindamaged Visual C makefile generator will see these extra files as
   dependencies and try to reference them when compiling.  The only
   workaround is to create a series of 0-byte files in a phantom sys
   directory somewhere in the include file path */

#ifdef _AIX
  /* ACHES defines LITTLE_ENDIAN and BIG_ENDIAN, then defines BYTE_ORDER to
	 the appropriate one of the two, we we check which one it is and
	 undefine the other one */
  #include <sys/machine.h>

  #if BYTE_ORDER == LITTLE_ENDIAN
	#undef BIG_ENDIAN
  #else
	#undef LITTLE_ENDIAN
  #endif
#endif /* _AIX */

#ifdef sun
  /* Slowaris defines _LITTLE_ENDIAN or _BIG_ENDIAN */
  #include <sys/isa_defs.h>

  #ifdef _LITTLE_ENDIAN
	#define LITTLE_ENDIAN
  #else
	#define BIG_ENDIAN
  #endif /* _LITTLE_ENDIAN */
#endif /* sun */

/* Determine the processor endianness.  Thanks to Shawn Clifford
   <sysop@robot.nuceng.ufl.edu> for this trick.

   NB: A number of compilers aren't tough enough for this test */

#if !defined( LITTLE_ENDIAN ) && !defined( BIG_ENDIAN )
  #if defined( _M_I86 ) || defined( _M_IX86 ) || defined( __TURBOC__ )
	#define LITTLE_ENDIAN		/* Intel architecture always little-endian */
  #elif defined( AMIGA )
	#define BIG_ENDIAN			/* Motorola architecture always big-endian */
  #elif defined __GNUC__
	#ifdef BYTES_BIG_ENDIAN
	  #define BIG_ENDIAN		/* Big-endian byte order */
	#else
	  #define LITTLE_ENDIAN		/* Undefined = little-endian byte order */
	#endif /* __GNUC__ */
  #elif ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'B' )
	#define LITTLE_ENDIAN
  #elif ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'A' )
	#define BIG_ENDIAN
  #else
	#error Cannot determine processor endianness - edit crypt.h and recompile
  #endif /* Endianness test */
#endif /* !( LITTLE_ENDIAN || BIG_ENDIAN ) */

/* Now do a sanity check just in case endianness is set somewhere else */

#if defined( LITTLE_ENDIAN ) && defined( BIG_ENDIAN )
  #error Both LITTLE_ENDIAN and BIG_ENDIAN are set in crypt.h - edit the settings and recompile
#endif /* LITTLE_ENDIAN && BIG_ENDIAN */

/* Declare a BigNum type to save having to use `struct BigNum' all over the
   place */

typedef struct BigNum	BIGNUM;

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner */

#define UNUSED(arg)	( ( arg ) = ( arg ) )

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

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
	char *name;						/* Algorithm name */
	int speed;						/* Speed relative to block copy */

	/* Keying information */
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
	   user, the transformed user key is (for those algoriths which do
	   this) the user key transformed by whatever key preprocessing method
	   is used, stored in canonical form.  The IV is the initial IV stored
	   in canonical form */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];		/* User encryption key */
	BYTE transUserKey[ CRYPT_MAX_KEYSIZE ];	/* Transformed user key */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* Initial IV */
	int userKeyLength;				/* User encryption key length in bytes */
	int ivLength;					/* IV length in bytes */
	BOOLEAN keySet;					/* Whether the key is set up */
	BOOLEAN ivSet;					/* Whether the IV is set up */

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
	BYTE currentIV[ CRYPT_MAX_IVSIZE ];		/* Internal working IV */
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
	int keySizeBits;				/* Nominal key size in bits */
	BIGNUM pkcParam1;
	BIGNUM pkcParam2;
	BIGNUM pkcParam3;
	BIGNUM pkcParam4;
	BIGNUM pkcParam5;
	BIGNUM pkcParam6;
	BIGNUM pkcParam7;
	BIGNUM pkcParam8;				/* The PKC key components */

	/* Private data needed by the algorithm */
	void *privateData;				/* For private use */
	int privateDataLength;			/* Length of private data */

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

#define dssParam_p			pkcParam1
#define dssParam_q			pkcParam1
#define dssParam_x			pkcParam1
#define dssParam_y			pkcParam1

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
#endif /* _BIG_WORDS */

/****************************************************************************
*																			*
*								Private Functions							*
*																			*
****************************************************************************/

/* If we're running on a 64-bit CPU we often need to mask values off to 32
   bits.  The following define enables this if the CPU word size is
   > 64 bits */

#ifdef _BIG_WORDS
  #define MASK32(x)		( ( x ) & 0xFFFFFFFFUL )
#else
  #define MASK32(x)		x
#endif /* _BIG_WORDS */

/* The odd algorithm needs masking to 16 bits */

#if UINT_MAX > 0xFFFFUL
  #define MASK16(x)		( ( x ) & 0xFFFFUL )
#else
  #define MASK16(x)		x
#endif /* > 16-bit ints */

/* Whether an encryption mode needs an IV or not */

#define needsIV(mode)	( mode == CRYPT_MODE_CBC || \
						  mode == CRYPT_MODE_CFB || \
						  mode == CRYPT_MODE_OFB || \
						  mode == CRYPT_MODE_PCBC )

/* Functions to convert the endianness from the canonical form to the
   internal form.  bigToLittle() convert from big-endian in-memory to
   little-endian in-CPU, littleToBig() convert from little-endian in-memory
   to big-endian in-CPU */

void longReverse( LONG *buffer, int count );
void wordReverse( WORD *buffer, int count );

#ifdef LITTLE_ENDIAN
  #define bigToLittleLong(x,y)	longReverse(x,y)
  #define bigToLittleWord(x,y)	wordReverse(x,y)
  #define littleToBigLong(x,y)
  #define littleToBigWord(x,y)
#else
  #define bigToLittleLong(x,y)
  #define bigToLittleWord(x,y)
  #define littleToBigLong(x,y)	longReverse(x,y)
  #define littleToBigWord(x,y)	wordReverse(x,y)
#endif /* LITTLE_ENDIAN */

/* To convert from the external CRYPT_CONTEXT cookie which is used to
   reference encryption contexts to the internal CRYPT_INFO structure, we
   subtract an offset from the CRYPT_CONTEXT value to obtain a pointer to
   the CRYPT_INFO struct.  The use of the conversion offset means programs
   outside the library security perimeter will generate a protection
   violation if they try to treat the CRYPT_CONTEXT as a pointer to
   anything unless they go to some lengths to determine the conversion
   value */

extern int cryptContextConversionOffset;

#define CONTEXT_TO_INFO(x)	( CRYPT_INFO * ) ( ( BYTE * ) x - cryptContextConversionOffset )
#define INFO_TO_CONTEXT(x)	( CRYPT_CONTEXT ) ( ( BYTE * ) x + cryptContextConversionOffset )

/* A magic value to detect whether an encryption context has been
   initialised yet */

#define CRYPT_MAGIC		0xC0EDBABEUL

/* A free() which zeroises the memory before it frees it */

void secureFree( void **pointer, int count );

#endif /* _CRYPT_DEFINED */
