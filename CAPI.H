#ifndef _CAPI_DEFINED

#define _CAPI_DEFINED

/* Fixup for Windows support.  We need to include windows.h for various types
   and prototypes needed for DLL's */

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define WIN32_LEAN_AND_MEAN		/* Skip RPC, OLE, Multimedia, etc */
  #include <windows.h>
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* Machine-dependant types to allow use in special library types such as
   DLL's.  Under Win32 we need to use the dllimport and dllexport directives 
   for the DLL version of the library, so we define the type used for 
   functions depending on whether we're being included via crypt.h or not */

#if ( defined( WIN32 ) || defined( _WIN32 ) )
  #define CPTR	*					/* General pointer */
  #ifdef _CRYPT_DEFINED
	#define CRET	__declspec( dllexport ) int	/* DLL export return value */
  #else
	#define CRET	__declspec( dllimport ) int	/* DLL import return value */
  #endif /* CRYPT_DEFINED */
#elif defined( _WINDOWS )
  #define CPTR	FAR *				/* DLL pointer */
  #define CRET	int FAR PASCAL _export	/* DLL return value */
#else
  #define CPTR	*					/* General pointer */
  #define CRET	int					/* General return value */
#endif /* _WINDOWS && !( WIN32 || _WIN32 ) */

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
	CRYPT_ALGO_DES,					/* DES */
	CRYPT_ALGO_3DES,				/* Triple DES */
	CRYPT_ALGO_IDEA,				/* IDEA */
	CRYPT_ALGO_MDCSHS,				/* MDC/SHS */
	CRYPT_ALGO_RC2,					/* RC2 */
	CRYPT_ALGO_RC4,					/* RC4 */
	CRYPT_ALGO_RC5,					/* RC5 */
	CRYPT_ALGO_SAFER,				/* SAFER/SAFER-SK */
	CRYPT_ALGO_BLOWFISH,			/* Blowfish/Blowfish-SK */
	CRYPT_ALGO_GOST,				/* GOST 28147 */
	CRYPT_ALGO_SKIPJACK,			/* It's only a matter of time... */

	/* Public-key encryption */
	CRYPT_ALGO_DH = 100,			/* Diffie-Hellman */
	CRYPT_ALGO_RSA,					/* RSA */
	CRYPT_ALGO_DSA,					/* DSA */

	/* Hash/MAC algorithms */
	CRYPT_ALGO_MD2 = 200,			/* MD2 */
	CRYPT_ALGO_MD4,					/* MD4 */
	CRYPT_ALGO_MD5,					/* MD5 */
	CRYPT_ALGO_SHA,					/* SHA/SHA1 */
	CRYPT_ALGO_RIPEMD160,			/* RIPE-MD 160 */

	CRYPT_ALGO_LAST,				/* Last possible crypt algo value */

	/* In order that we can scan through a range of algorithms with
	   cryptAlgoAvailable(), we define the following boundary points for each
	   algorithm class */
	CRYPT_ALGO_FIRST_CONVENTIONAL = CRYPT_ALGO_DES,
	CRYPT_ALGO_LAST_CONVENTIONAL = CRYPT_ALGO_DH - 1,
	CRYPT_ALGO_FIRST_PKC = CRYPT_ALGO_DH,
	CRYPT_ALGO_LAST_PKC = CRYPT_ALGO_MD2 - 1,
	CRYPT_ALGO_FIRST_HASH = CRYPT_ALGO_MD2,
	CRYPT_ALGO_LAST_HASH = CRYPT_ALGO_MD2 + 99	/* End of hash algo.range */
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
	CRYPT_MODE_PKC = 100,			/* PKC */

	CRYPT_MODE_LAST,				/* Last possible crypt mode value */

	/* In order that we can scan through a range of modes with
	   cryptAlgoModeAvailable(), we define the following boundary points for
	   the conventional encryption modes */
	CRYPT_MODE_FIRST_CONVENTIONAL = CRYPT_MODE_STREAM,
	CRYPT_MODE_LAST_CONVENTIONAL = CRYPT_MODE_PKC - 1
	} CRYPT_MODE;

/* The encryption object types we recognise */

typedef enum {
	CRYPT_OBJECT_NONE,				/* No object type */
	CRYPT_OBJECT_ENCRYPTED_KEY,		/* Conventional-encrypted key */
	CRYPT_OBJECT_PKCENCRYPTED_KEY,	/* PKC-encrypted key */
	CRYPT_OBJECT_SIGNATURE,			/* Signature */
	CRYPT_OBJECT_ENCRYPTED_DATA,	/* Encrypted data */
	CRYPT_OBJECT_COMPRESSED_DATA,	/* Compressed data */
	CRYPT_OBJECT_SIGNED_DATA,		/* Signed data */
	CRYPT_OBJECT_RAW_DATA,			/* Raw data */
	CRYPT_OBJECT_NONDATA,			/* Non-data (used for padding) */
	CRYPT_OBJECT_LAST				/* Last possible object type */
	} CRYPT_OBJECT_TYPE;

/* The keyset types */

typedef enum {
	CRYPT_KEYSET_NONE,				/* No keyset type */
	CRYPT_KEYSET_PGP,				/* PGP key ring */
	CRYPT_KEYSET_X509,				/* X.509/SET key certificate */
	CRYPT_KEYSET_LAST				/* Last possible keyset type */
	} CRYPT_KEYSET_TYPE;

/* The certificate information types */

typedef enum {
	/* No information */
	CRYPT_CERTINFO_NONE,			/* No certificate information */

	/* General certificate information */
	CRYPT_CERTINFO_SERIALNUMBER,	/* serialNumber */
	CRYPT_CERTINFO_VALIDITY,		/* validity */
	CRYPT_CERTINFO_UNIQUEIDENTIFIER,/* uniqueIdentifier (deprecated) */

	/* X.520 Distinguished Name components */
	CRYPT_CERTINFO_COUNTRYNAME = 100,	/* countryName */
	CRYPT_CERTINFO_ORGANIZATIONNAME,	/* organizationName */
	CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,	/* organizationalUnitName */
	CRYPT_CERTINFO_COMMONNAME,		/* commonName */

	/* X.509v3 GeneralName extensions */
	CRYPT_CERTINFO_OTHERNAME = 200,	/* OTHER-NAME */
	CRYPT_CERTINFO_RFC822NAME,		/* rfc822Name */
	CRYPT_CERTINFO_DNSNAME,			/* dNSName */
	CRYPT_CERTINFO_X400ADDRESS,		/* x400Address */
	CRYPT_CERTINFO_DIRECTORYNAME,	/* directoryName */
	CRYPT_CERTINFO_EDIPARTYNAME,	/* ediPartyName */
	CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,	/* uniformResourceIdentifier */
	CRYPT_CERTINFO_IPADDRESS,		/* iPAddress */
	CRYPT_CERTINFO_REGISTEREDID,	/* registeredID */

	/* SET extensions */
	CRYPT_CERTINFO_ACCOUNTALIAS = 300,	/* accountAlias */
	CRYPT_CERTINFO_HASHEDROOTKEY,	/* hashedRootKey */
	CRYPT_CERTINFO_CERTIFICATETYPE,	/* certificateType */
	CRYPT_CERTINFO_MERCHANTDATA		/* merchantData */
	} CRYPT_CERTINFO_TYPE;

/****************************************************************************
*																			*
*					Library-Wide Constants and Definitions					*
*																			*
****************************************************************************/

/* The maximum user key size - 2048 bits */

#define CRYPT_MAX_KEYSIZE		256

/* The maximum IV size - 64 bits */

#define CRYPT_MAX_IVSIZE		8

/* The maximum public-key component size - 4096 bits */

#define CRYPT_MAX_PKCSIZE		512

/* The maximum hash size - 256 bits */

#define CRYPT_MAX_HASHSIZE		64

/* The maximum size of a text string */

#define CRYPT_MAX_TEXTSIZE		128

/* The maximum size of a key ID */

#define CRYPT_MAX_KEYIDSIZE		80

/* The maximum speed ratio for an encryption algorithm */

#define CRYPT_MAX_SPEED			1000

/* A magic value indicating that the default setting for this parameter
   should be used */

#define CRYPT_USE_DEFAULT		-1

/* A magic value for unused parameters */

#define CRYPT_UNUSED			-2

/* The endianness of the external components of the PKC key */

#define CRYPT_COMPONENTS_BIGENDIAN		0
#define CRYPT_COMPONENTS_LITTLENDIAN	1

/* Whether the PKC key is a public or private key */

#define CRYPT_KEYTYPE_PRIVATE	0
#define CRYPT_KEYTYPE_PUBLIC	1

/* The type of information polling to perform to get random seed information */

#define CRYPT_RANDOM_FASTPOLL	-1
#define CRYPT_RANDOM_SLOWPOLL	-2

/* The keyset access modes */

#define CRYPT_ACCESS_READ		1
#define CRYPT_ACCESS_WRITE		2
#define CRYPT_ACCESS_CREATE		4

/* Special userID's for getFirst()/getNext() functionality in keysets */

#define CRYPT_KEYSET_GETFIRST	( ( void CPTR ) -10 )
#define CRYPT_KEYSET_GETNEXT	( ( void CPTR ) -11 )

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes(bits)	( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits(bytes)	( ( bytes ) << 3 )

/* The encryption context, public/private key collection, certificate, and
   envelope.  These are opaque data types used internally by the library.
   Although declared as a char *, they don't point to anything and should not
   be treated as a pointer (the use of char * rather than the more logical
   void * allows for better type checking by the compiler.
   "The way is void" - Musashi) */

typedef char CPTR CRYPT_CONTEXT;
typedef char CPTR CRYPT_KEYSET;
typedef char CPTR CRYPT_CERT;
typedef char CPTR CRYPT_ENVELOPE;

/****************************************************************************
*																			*
*							Encryption Data Structures						*
*																			*
****************************************************************************/

/* Results returned from the encryption capability query */

typedef struct {
	/* The algorithm, encryption mode, and algorithm and mode names */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */
	char *algoName;					/* The algorithm name */
	char *modeName;					/* The mode name */

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

	/* Miscellaneous information (only used by some algorithms) */
	unsigned char hashValue[ CRYPT_MAX_HASHSIZE ];
									/* Hash algoriithm hash value */
	unsigned char keyID[ CRYPT_MAX_KEYIDSIZE ];	/* PKC key ID */
	int keyIDsize;					/* PKC key ID length */
	long controlVector;				/* Conventional key control vector */
	} CRYPT_QUERY_INFO;

/* Results returned from the encryption object query */

typedef struct {
	/* The object type and size information */
	CRYPT_OBJECT_TYPE type;			/* The object type */
	long size;						/* The object size */
	int headerSize;					/* Size of the objects header */
	long payloadSize;				/* Size of the objects payload */

	/* The encryption algorithm and mode for EncryptedKey, PKCEncryptedKey,
	   Signature, and SignedData objects */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */

	/* The key ID for PKCEncryptedKey and Signature objects */
	unsigned char keyID[ CRYPT_MAX_KEYIDSIZE ];	/* PKC key ID */
	unsigned char keyIDsize;		/* PKC key ID length */

	/* The key derivation algorithm and iteration count for EncryptedKey
	   objects */
	CRYPT_ALGO keySetupAlgo;		/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */

	/* The control vector and algorithm-specific information for
	   EncryptedKey objects.  The algorithm-specific information can be
	   passed directly to cryptCreateContextEx() for any algorithm (even
	   those which would normally use cryptCreateContext()) */
	long controlVector;				/* Conventional key control vector */
	void *cryptContextExInfo;		/* Algo-specific information */

	/* The cookie for EncryptedKey, PKCEncryptedKey, EncryptedData, and
	   SignedData objects */
	unsigned char cookie[ CRYPT_MAX_HASHSIZE ];
	int cookieSize;

	/* The IV for EncryptedData objects */
	unsigned char iv[ CRYPT_MAX_IVSIZE ];	/* IV */
	int ivSize;						/* Length of the IV */
	} CRYPT_OBJECT_INFO;

/* Extra algorithm-specific information for the hash algorithms, stored
   within a crypt context.  Set the parameter values to CRYPT_USE_DEFAULT
   to use the default values for this algorithm */

typedef struct {
	int isSHA;					/* Whether to use SHA rather than SHA1 */
	} CRYPT_INFO_SHA;

/* Extra algorithm-specific information for the conventional encryption
   algorithms, stored within a crypt context.  Set the parameter values to
   CRYPT_USE_DEFAULT to use the default values for this algorithm */

typedef struct {
	int isDESX;					/* Whether to use the DESX variant */
	} CRYPT_INFO_DES;

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
	int useSaferSK;				/* Whether to use strengthened-key version */
	int rounds;					/* Number of encryption rounds */
	} CRYPT_INFO_SAFER;

typedef struct {
	int useBlowfishSK;			/* Whether to use strengthened-key version */
	int keySetupIterations;		/* No.iterations for SK user key setup */
	} CRYPT_INFO_BLOWFISH;

/* Key information for the public-key encryption algorithms.  These fields
   are not accessed directly, but can be manipulated with the init/set/get/
   destroyComponents() macros */

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime */
	int pLen;					/* Length of prime in bits */
	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* Base */
	int gLen;					/* Length of base in bits */
	} CRYPT_PKCINFO_DH;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

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
	} CRYPT_PKCINFO_RSA;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime modulus */
	int pLen;					/* Length of prime modulus in bits */
	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime divisor */
	int qLen;					/* Length of prime divisor in bits */
	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* h^( ( p - 1 ) / q ) mod p */
	int gLen;					/* Length of g in bits */
	unsigned char x[ CRYPT_MAX_PKCSIZE ];	/* Public random integer */
	int xLen;					/* Length of public integer in bits */

	/* Private components */
	unsigned char y[ CRYPT_MAX_PKCSIZE ];	/* Private random integer */
	int yLen;					/* Length of private integer in bits */
	} CRYPT_PKCINFO_DSA;

/* Macros to initialise and destroy the structure which stores the components
   of a public key */

#define cryptInitComponents( componentInfo, componentEndianness, componentKeyType ) \
	{ memset( componentInfo, 0, sizeof( *componentInfo ) ); \
	  componentInfo##->endianness = componentEndianness; \
	  componentInfo##->isPublicKey = componentKeyType; }

#define cryptDestroyComponents( componentInfo ) \
	memset( componentInfo, 0, sizeof( *componentInfo ) )

/* Macros to set and get a component of the public key */

#define cryptSetComponent( destination, source, length ) \
	{ memcpy( destination, source, bitsToBytes( length ) ); \
	  destination##Len = length; }

#define cryptGetComponent( destination, source, length ) \
	{ memcpy( source, destination, bitsToBytes( destination##Len ) ); \
	  length = destination##Len; }

/****************************************************************************
*																			*
*						Crypt IOCTL Structures and Constants				*
*																			*
****************************************************************************/

/* The various IOCTL types */

typedef enum {
	CRYPT_IOCTL_NONE,				/* Null IOCTL */
	CRYPT_IOCTL_MEMORY,				/* Control page locking */
	CRYPT_IOCTL_KEYCOOKIE,			/* Control key cookie export */
	CRYPT_IOCTL_SIGCOOKIE,			/* Control signature cookie export */
	CRYPT_IOCTL_PKCPADDING,			/* Control PKC encryption padding type */
	CRYPT_IOCTL_KEYSETNAMES,		/* Control keyset table names */
	CRYPT_IOCTL_LAST				/* Last possible IOCTL type */
	} CRYPT_IOCTL;

/* The data structure and constants for CRYPT_IOCTL_MEMORY */

enum { CRYPT_MEMORY_NOLOCK, CRYPT_MEMORY_LOCK, CRYPT_MEMORY_FORCELOCK };

typedef struct {
	int memoryLockType;				/* What to do with memory blocks */
	} CRYPT_IOCTLINFO_MEMORY;

/* The data structure for CRYPT_IOCTL_KEYCOOKIE and CRYPT_IOCTL_SIGCOOKIE */

typedef struct {
	int exportCookie;				/* Whether to export cookies or not */
	} CRYPT_IOCTLINFO_COOKIE;

/* The data structure for CRYPT_IOCTL_PKCPADDING */

typedef struct {
	int useOAEP;					/* Whether to use optimal asymmetric
									   encryption padding */
	} CRYPT_IOCTLINFO_PKCPADDING;

/* The data structure for CRYPT_IOCTL_KEYSETNAMES */

typedef struct {
	char *userID;					/* Name of user ID table */
	char *keyID;					/* Name of key ID table */
	char *publicKey;				/* Name of public key table */
	char *privateKey;				/* Name of private key table */
	} CRYPT_IOCTLINFO_KEYSETNAMES;

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

#define CRYPT_NOMEM			-50		/* Out of memory */
#define CRYPT_NOTINITED		-51		/* Data has not been initialised */
#define CRYPT_INITED		-52		/* Data has already been initialised */
#define CRYPT_NOALGO		-53		/* Algorithm unavailable */
#define CRYPT_NOMODE		-54		/* Encryption mode unavailable */
#define CRYPT_NOKEY			-55		/* Key not initialised */
#define CRYPT_NOIV			-56		/* IV not initialised */
#define CRYPT_NOLOCK		-57		/* Unable to lock pages in memory */
#define CRYPT_NORANDOM		-58		/* No reliable random data available */

/* CAPI security violations */

#define CRYPT_NOTAVAIL		-100	/* Operation not available for this algo/mode */
#define CRYPT_KEYPERM		-101	/* No key permissions for this operation */
#define CRYPT_WRONGKEY		-102	/* Incorrect key used to decrypt data */
#define CRYPT_INCOMPLETE	-103	/* Operation incomplete/still in progress */
#define CRYPT_COMPLETE		-104	/* Operation complete/can't continue */
#define CRYPT_ORPHAN		-105	/* Encryption contexts remained allocated */

/* High-level function errors */

#define CRYPT_DATASIZE		-150	/* Too much data supplied to function */
#define CRYPT_PKCCRYPT		-151	/* PKC en/decryption failed */
#define CRYPT_BADDATA		-152	/* Bad data format in object */
#define CRYPT_BADSIG		-153	/* Bad signature on data */

/* Key collection errors */

#define CRYPT_KEYSET_OPEN		-200	/* Cannot open key set */
#define CRYPT_KEYSET_NOTFOUND	-201	/* Key or key info not found in key set */
#define CRYPT_KEYSET_DUPLICATE	-202	/* Key already present in key set */
#define CRYPT_KEYSET_UPDATE		-203	/* Cannot update key set */

/* Certificate errors */

#define CRYPT_CERT_NONE		-250	/* No errors defined yet */

/* Macros to examine return values */

#define cryptStatusError( status )	( ( status ) < CRYPT_OK )
#define cryptStatusOK( status )		( ( status ) == CRYPT_OK )
#define cryptIsParamError( status )	( ( status ) >= CRYPT_BADPARM && \
									  ( status ) < CRYPT_NOMEM )
#define cryptIsResourceError( status ) \
									( ( status ) >= CRYPT_NOMEM && \
									  ( status ) < CRYPT_NOTAVAIL )
#define cryptIsSecurityError( status ) \
									( ( status ) >= CRYPT_NOTAVAIL && \
									  ( status ) < CRYPT_DATASIZE )
#define cryptIsHighlevelError( status ) \
									( ( status ) >= CRYPT_DATASIZE && \
									  ( status ) < CRYPT_KEYSET_ORPHAN )
#define cryptIsKeysetError( status ) \
									( ( status ) >= CRYPT_KEYSET_OPEN && \
									  ( status ) < CRYPT_CERT_NONE )
#define cryptIsCertError( status ) \
									( ( status ) >= CRYPT_CERT_NONE && \
									  ( status ) <= CRYPT_CERT_NONE )

/****************************************************************************
*																			*
*								Encryption Functions						*
*																			*
****************************************************************************/

/* Initialise and shut down the encryption library */

CRET cryptInit( void );
CRET cryptEnd( void );

/* Query the capabilities of the encryption library */

CRET cryptModeAvailable( const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode );
CRET cryptAlgoAvailable( const CRYPT_ALGO cryptAlgo );
CRET cryptQueryAlgoMode( const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode, \
						 CRYPT_QUERY_INFO CPTR cryptQueryInfo );
CRET cryptQueryContext( const CRYPT_CONTEXT cryptContext, \
						CRYPT_QUERY_INFO CPTR cryptQueryInfo );

/* Initialise and destroy an encryption context */

CRET cryptCreateContextEx( CRYPT_CONTEXT CPTR cryptContext, \
						   const CRYPT_ALGO cryptAlgo, \
						   const CRYPT_MODE cryptMode, \
						   const void CPTR cryptContextEx );
CRET cryptDestroyContext( CRYPT_CONTEXT cryptContext );

#define cryptCreateContext( cryptContext, cryptAlgo, cryptMode ) \
		cryptCreateContextEx( cryptContext, cryptAlgo, cryptMode, \
							  ( void * ) CRYPT_UNUSED )

/* Load a user key into an encryption context, add random data to the random
   pool, generate a session key from the random pool into a context, or
   derive an encryption key from a variable-length user key */

CRET cryptLoadContext( CRYPT_CONTEXT cryptContext, void CPTR key, \
					   const int keyLength );
CRET cryptAddRandom( void CPTR randomData, int randomDataLength );
CRET cryptGenerateContextEx( CRYPT_CONTEXT cryptContext, const int keyLength );
CRET cryptDeriveKeyEx( CRYPT_CONTEXT cryptContext, const void CPTR userKey, \
					   const int userKeyLength, const CRYPT_ALGO algorithm, \
					   const int iterations );

#define cryptGenerateContext( cryptContext ) \
		cryptGenerateContextEx( cryptContext, CRYPT_USE_DEFAULT )
#define cryptDeriveKey( cryptContext, userKey, userKeyLength ) \
		cryptDeriveKeyEx( cryptContext, userKey, userKeyLength, \
						  CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT )

/* Load/retrieve an IV into/from an encryption context */

CRET cryptLoadIV( CRYPT_CONTEXT cryptContext, const void CPTR iv, \
				  const int length );
CRET cryptRetrieveIV( CRYPT_CONTEXT cryptContext, void CPTR iv );

/* Encrypt/decrypt/hash a block of memory */

CRET cryptEncrypt( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
				   const int length );
CRET cryptDecrypt( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
				   const int length );

/* Crypt library IOCTL */

CRET cryptIoctl( CRYPT_IOCTL ioctlCode, void CPTR ioctlInformation,
				 CRYPT_CONTEXT cryptContext );

/****************************************************************************
*																			*
*								Key Managment Functions						*
*																			*
****************************************************************************/

/* Open and close a keyset */

CRET cryptKeysetOpenEx( CRYPT_KEYSET CPTR keySet, const char CPTR name, \
						const int accessMode, const char CPTR user, \
						const char CPTR password );
CRET cryptExtKeysetOpen( CRYPT_KEYSET CPTR keySet, const char CPTR name, \
						 const CRYPT_KEYSET_TYPE type );
CRET cryptKeysetClose( CRYPT_KEYSET keySet );

#define cryptKeysetOpen( keySet, name, accessMode ) \
		cryptKeysetOpenEx( keySet, name, accessMode, \
						   ( char CPTR ) CRYPT_UNUSED, ( char CPTR ) CRYPT_UNUSED )

/* Get a key from a keyset */

CRET cryptGetKeyEx( CRYPT_KEYSET keySet, CRYPT_CONTEXT CPTR cryptContext, \
					const void CPTR userID, const void CPTR password );
CRET cryptGetKeyFromObjectEx( CRYPT_KEYSET keySet, CRYPT_CONTEXT CPTR cryptContext, \
							  const void CPTR object, const void CPTR password );

#define cryptGetKey( keySet, cryptContext, userID ) \
		cryptGetKeyEx( keySet, cryptContext, userID, ( void CPTR ) CRYPT_UNUSED )
#define cryptGetKeyFromObject( keySet, cryptContext, object ) \
		cryptGetKeyFromObjectEx( keySet, cryptContext, object, \
        						 ( void CPTR ) CRYPT_UNUSED )

/****************************************************************************
*																			*
*							Certificate Managment Functions					*
*																			*
****************************************************************************/

/* Code to implement these functions is not shipped with cryptlib 2.00 since
   the details are still undergoing revisions */

/* Create/destroy a certificate */

CRET cryptCreateCert( CRYPT_CERT CPTR certificate,
					  const CRYPT_CONTEXT cryptContext );
CRET cryptDestroyCert( CRYPT_CERT certificate );

/* Get/add/delete certificate components */

CRET cryptGetCertComponent( CRYPT_CERT certificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							void CPTR certInfo );
CRET cryptAddCertComponent( CRYPT_CERT certificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							const void CPTR certInfo );
CRET cryptDeleteCertComponent( CRYPT_CERT certificate,
							   const CRYPT_CERTINFO_TYPE certInfoType,
							   const void CPTR certInfo );

/* Sign a certificate */

CRET cryptSignCert( CRYPT_CERT certificate, CRYPT_CONTEXT pkcContext );

/* Import/export a certificate */

CRET cryptImportCert( const void CPTR certObject, CRYPT_CERT CPTR certificate );
CRET cryptExportCert( void CPTR certObject, int CPTR certObjectLength,
					  CRYPT_CERT certificate );

/****************************************************************************
*																			*
*								High-Level Functions						*
*																			*
****************************************************************************/

/* Import and export a PKC-encrypted session key object */

CRET cryptExportKey( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					 const CRYPT_CONTEXT pkcContext,
					 const CRYPT_CONTEXT cryptContext );
CRET cryptImportKey( void CPTR encryptedKey, const CRYPT_CONTEXT pkcContext,
					 CRYPT_CONTEXT CPTR cryptContext );

/* Create and check a digital signature object */

CRET cryptCreateSignature( void CPTR signature, int CPTR signatureLength,
						   const CRYPT_CONTEXT pkcContext,
						   const CRYPT_CONTEXT hashContext );
CRET cryptCheckSignature( const void CPTR signature,
						  const CRYPT_CONTEXT pkcContext,
						  const CRYPT_CONTEXT hashContext );

/* Export and import a general data object and query an object */

CRET cryptExportObjectEx( void CPTR object, int CPTR objectLength,
						  CRYPT_OBJECT_TYPE objectType, const long dataLength,
						  const CRYPT_CONTEXT cryptContext );
CRET cryptImportObjectEx( const void CPTR object, int CPTR payloadStart,
						  long CPTR payloadLength,
						  CRYPT_CONTEXT CPTR cryptContext );
CRET cryptQueryObject( const void CPTR object,
					   CRYPT_OBJECT_INFO CPTR cryptObjectInfo );

#define cryptExportObject( object, objectLength, objectType, dataLength ) \
		cryptExportObjectEx( object, objectLength, objectType, dataLength, \
							 ( CRYPT_CONTEXT ) CRYPT_UNUSED )
#define cryptImportObject( object, payloadStart, payloadLength ) \
		cryptImportObjectEx( object, payloadStart, payloadLength, \
							 ( CRYPT_CONTEXT CPTR ) CRYPT_UNUSED )
#endif /* _CAPI_DEFINED */
