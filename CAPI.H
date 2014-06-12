#ifndef _CAPI_DEFINED

#define _CAPI_DEFINED

/* Fixup for Windoze support.  We need to include windows.h for various types
   and prototypes needed for DLL's */

#if defined( __WINDOWS__ )
  #include <windows.h>
#endif /* __WINDOWS__ */

/* Machine-dependant types to allow use in special library types such as
   DLL's */

#if defined( __WINDOWS__ ) && !( defined( WIN32 ) || defined( _WIN32 ) )
  #define CPTR	FAR *						/* DLL pointer */
  #define CRET	int FAR PASCAL _export		/* DLL return value */
#else
  #define CPTR	*							/* General pointer */
  #define CRET	int							/* General return value */
#endif /* __WINDOWS__ && !( WIN32 || _WIN32 ) */

/****************************************************************************
*																			*
*						Encryption Algorithm Types/Modes					*
*																			*
****************************************************************************/

/* The encryption algorithms we can use */

typedef enum {
	/* No encryption */
	CRYPT_ALGO_NONE,				/* No encryption */

	/* Conventional encryption */
	CRYPT_ALGO_MDCSHS,				/* MDC/SHS */
	CRYPT_ALGO_DES,					/* DES */
	CRYPT_ALGO_3DES,				/* Triple DES */
	CRYPT_ALGO_IDEA,				/* IDEA */
	CRYPT_ALGO_RC2,					/* RC2 */
	CRYPT_ALGO_RC4,					/* RC4 */
	CRYPT_ALGO_RC5,					/* RC5 */
	CRYPT_ALGO_SAFER,				/* SAFER/SAFER-SK */
	CRYPT_ALGO_BLOWFISH,			/* Blowfish/Blowfish-SK */
	CRYPT_ALGO_SKIPJACK,			/* It's only a matter of time... */

	/* Public-key encryption */
	CRYPT_ALGO_RSA = 100,			/* RSA */
	CRYPT_ALGO_DSS,					/* DSS */

	/* Hash/MAC algorithms */
	CRYPT_ALGO_MD2 = 200,			/* MD2 */
	CRYPT_ALGO_MD4,					/* MD4 */
	CRYPT_ALGO_MD5,					/* MD5 */
	CRYPT_ALGO_SHA,					/* SHA/SHA1 */

	CRYPT_ALGO_LAST					/* Last possible crypt algo value */
	} CRYPT_ALGO;

/* The encryption modes we can use */

typedef enum {
	/* No encryption */
	CRYPT_MODE_NONE,				/* No encryption */

	/* Stream cipher modes */
	CRYPT_MODE_STREAM,				/* Stream cipher */

	/* Block cipher modes */
	CRYPT_MODE_ECB,					/* ECB */
	CRYPT_MODE_CBC,					/* CBC */
	CRYPT_MODE_CFB,					/* CFB */
	CRYPT_MODE_OFB,					/* OFB */
	CRYPT_MODE_PCBC,				/* PCBC */
	CRYPT_MODE_COUNTER,				/* KSG/counter */

	/* Public-key cipher modes */
	CRYPT_MODE_PUBKEY = 100,		/* Public-key operation */
	CRYPT_MODE_PRIVKEY,				/* Private-key operation */

	CRYPT_MODE_LAST					/* Last possible crypt mode value */
	} CRYPT_MODE;

/****************************************************************************
*																			*
*					Library-Wide Constants and Definitions					*
*																			*
****************************************************************************/

/* The maximum user key size - 2048 bits */

#define CRYPT_MAX_KEYSIZE	256

/* The maximum IV size - 256 bits */

#define CRYPT_MAX_IVSIZE	64

/* The maximum public-key component size - 4096 bits */

#define CRYPT_MAX_PKCSIZE	512

/* The maximum hash size - 256 bits */

#define CRYPT_MAX_HASHSIZE	64

/* The maximum speed ratio for an encryption algorithm */

#define CRYPT_MAX_SPEED		1000

/* A magic value indicating that the default setting for this parameter
   should be used */

#define CRYPT_USE_DEFAULT	-1

/* A magic value for unused parameters */

#define CRYPT_UNUSED		0

/* The endianness of the external components of the PKC key */

#define CRYPT_COMPONENTS_LITTLENDIAN	0
#define CRYPT_COMPONENTS_BIGENDIAN		1

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes(bits)	( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits(bytes)	( ( bytes ) << 3 )

/* Macros to initialise and destroy the structure which stores the components
   of a public key */

#define initComponents(componentInfo,componentEndianness) \
	{ memset( &componentInfo, 0, sizeof( componentInfo ) ); \
	  componentInfo##.endianness = componentEndianness; }

#define destroyComponents(componentInfo) \
	memset( &componentInfo, 0, sizeof( componentInfo ) )

/* Macros to set and get a component of the public key */

#define setComponent(destination,source,length) \
	{ memcpy( destination, source, bitsToBytes( length ) ); \
	  destination##Len = length; }

#define getComponent(destination,source,length) \
	{ memcpy( source, destination, bitsToBytes( destination##Len ) ); \
	  length = destination##Len; }

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Extra algorithm-specific information for the conventional encryption
   algorithms, stored within a crypt context.  Set the parameter values to
   CRYPT_USE_DEFAULT to use the default values for this algorithm */

typedef struct {
	int isThreeKey;				/* Whether to use three-key variant */
	} CRYPT_INFO_3DES;

typedef struct {
	int keySetupIterations;		/* No.iterations for user key setup */
	} CRYPT_INFO_MDCSHS;

typedef struct {
	int rounds;					/* Number of encryption rounds */
	} CRYPT_INFO_RC5;

typedef struct {
	int rounds;					/* Number of encryption rounds */
	int currentRounds;			/* Internal number of rounds for this key */
	int useSaferSK;				/* Whether to use strengthened-key version */
	} CRYPT_INFO_SAFER;

typedef struct {
	int keySetupIterations;		/* No.iterations for SK user key setup */
	int useBlowfishSK;			/* Whether to use strengthened-key version */
	} CRYPT_INFO_BLOWFISH;

/* Key information for the public-key encryption algorithms.  These fields
   are not accessed directly, but can be manipulated with the init/set/get/
   destroyComponents() macros */

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */

	/* Public components */
	unsigned char n[ CRYPT_MAX_PKCSIZE ];	/* Modulus */
	int nLen;					/* Length of modulus in bits */
	unsigned char e[ CRYPT_MAX_PKCSIZE ];	/* Public exponent */
	int eLen;					/* Length of public exponent in bits */

	/* Private components */
	unsigned char d[ CRYPT_MAX_PKCSIZE ];	/* Private exponent */
	int dLen;					/* Length of private exponent in bits */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 1 */
	int pLen;					/* Length of prime factor 1 in bits */
	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 2 */
	int qLen;					/* Length of prime factor 2 in bits */
	unsigned char u[ CRYPT_MAX_PKCSIZE ];	/* Mult.inverse of q, mod p */
	int uLen;					/* Length of private exponent in bits */
	unsigned char e1[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 1 (PKCS) */
	int e1Len;					/* Length of private exponent in bits */
	unsigned char e2[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 2 (PKCS) */
	int e2Len;					/* Length of private exponent in bits */

	/* The key ID, defined as the hash of the DER-encoded public fields */
	int keyIDset;				/* Whether the key ID has been set */
	CRYPT_ALGO keyHashAlgo;		/* Hash algorithm */
	unsigned char keyID[ CRYPT_MAX_HASHSIZE ];	/* Key ID data */
	int keyIDlength;			/* Length of key ID */
	} CRYPT_PKCINFO_RSA;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime modulus */
	int pLen;					/* Length of prime modulus in bits */
	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime divisor */
	int qLen;					/* Length of prime divisor in bits */
	unsigned char x[ CRYPT_MAX_PKCSIZE ];	/* Public random integer */
	int xLen;					/* Length of public integer in bits */

	/* Private components */
	unsigned char y[ CRYPT_MAX_PKCSIZE ];	/* Private random integer */
	int yLen;					/* Length of private integer in bits */

	/* The key ID, defined as the hash of the DER-encoded public fields */
	int keyIDset;				/* Whether the key ID has been set */
	CRYPT_ALGO keyHashAlgo;		/* Hash algorithm */
	unsigned char keyID[ CRYPT_MAX_HASHSIZE ];	/* Key ID data */
	int keyIDlength;			/* Length of key ID */
	} CRYPT_PKCINFO_DSS;

/* Results returned from the encryption capability query */

typedef struct {
	/* The algorithm, encryption mode, and algorithm name */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */
	char *algoName;					/* The algorithm name */

	/* The algorithm parameters */
	int blockSize;					/* The basic block size of the algorithm */
	int minKeySize;					/* Minimum key size in bytes */
	int keySize;					/* Recommended key size in bytes */
	int maxKeySize;					/* Maximum key size in bytes */
	int minIVsize;					/* Minimum IV size in bytes */
	int ivSize;						/* Recommended IV size in bytes */
	int maxIVsize;					/* Maximum IV size in bytes */

	/* Various algorithm characteristics */
	int speed;						/* Speed relative to block copy */

	/* Current state information (only used by some algorithms) */
	unsigned char hashValue[ CRYPT_MAX_HASHSIZE ];
									/* Current hash value */
	
	/* Padding in case a newer version of the library which adds new fields
	   tries to write data to them */
	unsigned char dummy[ 256 ];
	} CRYPT_QUERY_INFO;

/* An encryption context.  This is an opaque data type used internally by the
   library.  Although declared as a char *, it doesn't point to anything and
   should not be treated as a pointer (the use of char * rather than the more
   logical void * allows for better type checking by the compiler) */

typedef char CPTR CRYPT_CONTEXT;

/****************************************************************************
*																			*
*								Status Codes								*
*																			*
****************************************************************************/

/* No error in function call */

#define CRYPT_OK			0		/* No error */

/* Internal errors */

#define CRYPT_ERROR			-1		/* Nonspecific error */
#define CRYPT_SELFTEST		-2		/* Failed self-test */

/* Error in parameters passed to function */

#define CRYPT_BADPARM		-10		/* Generic bad argument to function */
#define CRYPT_BADPARM1		-11		/* Bad argument, parameter 1 */
#define CRYPT_BADPARM2		-12		/* Bad argument, parameter 2 */
#define CRYPT_BADPARM3		-13		/* Bad argument, parameter 3 */
#define CRYPT_BADPARM4		-14		/* Bad argument, parameter 4 */
#define CRYPT_BADPARM5		-15		/* Bad argument, parameter 5 */
#define CRYPT_BADPARM6		-16		/* Bad argument, parameter 6 */
#define CRYPT_BADPARM7		-17		/* Bad argument, parameter 7 */
#define CRYPT_BADPARM8		-18		/* Bad argument, parameter 8 */
#define CRYPT_BADPARM9		-19		/* Bad argument, parameter 9 */
#define CRYPT_BADPARM10		-20		/* Bad argument, parameter 10 */
#define CRYPT_BADPARM11		-21		/* Bad argument, parameter 11 */
#define CRYPT_BADPARM12		-22		/* Bad argument, parameter 12 */
#define CRYPT_BADPARM13		-23		/* Bad argument, parameter 13 */
#define CRYPT_BADPARM14		-24		/* Bad argument, parameter 14 */
#define CRYPT_BADPARM15		-25		/* Bad argument, parameter 15 */

/* Errors due to insufficient resources */

#define CRYPT_NOMEM			-30		/* Out of memory */
#define CRYPT_NOTINITED		-31		/* Data has not been initialised */
#define CRYPT_INITED		-32		/* Data has already been initialised */
#define CRYPT_NOALGO		-33		/* Algorithm unavailable */
#define CRYPT_NOMODE		-34		/* Encryption mode unavailable */
#define CRYPT_NOKEY			-35		/* Key not initialised */
#define CRYPT_NOIV			-36		/* IV not initialised */

/* CAPI security violations */

#define CRYPT_NOTAVAIL		-50		/* Operation not available for this algo/mode */
#define CRYPT_WRONGKEY		-51		/* Wrong key type for this operation */
#define CRYPT_INCOMPLETE	-52		/* Operation incomplete/still in progress */
#define CRYPT_COMPLETE		-53		/* Operation complete/can't continue */
#define CRYPT_ORPHAN		-54		/* Encryption contexts remained allocated */

/* Higher-level CAPI interface */

#define CRYPT_BADSIG		-70		/* Bad signature on data */

/* A macro to detect an error return value */

#define isStatusError(status)		( ( status ) < CRYPT_OK )
#define isStatusOK(status)			( ( status ) == CRYPT_OK )

/****************************************************************************
*																			*
*								Public Functions							*
*																			*
****************************************************************************/

/* Initialise and shut down the encryption library */

CRET initLibrary( void );
CRET endLibrary( void );

/* Query the capabilities of the encryption library */

CRET queryModeAvailability( const CRYPT_ALGO cryptAlgo, \
							const CRYPT_MODE cryptMode );
CRET queryAlgoAvailability( const CRYPT_ALGO cryptAlgo );
CRET queryAlgoModeInformation( const CRYPT_ALGO cryptAlgo, \
							   const CRYPT_MODE cryptMode, \
							   CRYPT_QUERY_INFO CPTR cryptQueryInfo );
CRET queryContextInformation( const CRYPT_CONTEXT cryptContext, \
							  CRYPT_QUERY_INFO CPTR cryptQueryInfo );

/* Initialise and destroy an encryption context */

CRET initCryptContext( CRYPT_CONTEXT CPTR cryptContext, \
					   const CRYPT_ALGO cryptAlgo, \
					   const CRYPT_MODE cryptMode );
CRET initCryptContextEx( CRYPT_CONTEXT CPTR cryptContext, \
						 const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode, \
						 const void *cryptContextEx );
CRET destroyCryptContext( CRYPT_CONTEXT cryptContext );

/* Load a user key or generate a session key into an encryption context */

CRET loadCryptContext( CRYPT_CONTEXT cryptContext, const void CPTR key, \
					   const int keyLength );
CRET generateCryptContext( CRYPT_CONTEXT cryptContext, const int keyLength );

/* Load/retrieve an IV into/from an encryption context */

CRET loadIV( CRYPT_CONTEXT cryptContext, const void CPTR iv, const int length );
CRET retrieveIV( CRYPT_CONTEXT cryptContext, void CPTR iv );

/* Encrypt/decrypt/hash a block of memory */

CRET encryptBuffer( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
					const int length );
CRET decryptBuffer( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
					const int length );

/* High-level interface to PKC routines */

CRET createSignature( const CRYPT_CONTEXT hashContext, \
					  const CRYPT_CONTEXT pkcContext, \
					  void CPTR signedData );
CRET checkSignature( const CRYPT_CONTEXT hashContext, \
					 const CRYPT_CONTEXT pkcContext, \
					 const void CPTR signedData );

#endif /* _CAPI_DEFINED */
