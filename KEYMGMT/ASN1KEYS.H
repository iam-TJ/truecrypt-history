/****************************************************************************
*																			*
*				ASN.1 Key Management Structures and Prototypes 				*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#ifndef _ASN1KEYS_DEFINED

#define _ASN1KEYS_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* Some routines are currently unused because the cryptlib key file format
   may not be used after all if any of the various standardisation efforts
   for key collections ever comes to fruition.  Define the following to
   include the extra routines (some of these clash with routines in other
   modules which postdate their removal from asn1keys.c */

/* #define FULL_KEYMGMT */

/* The default value for tagged types.  If this value is given the basic
   type is used, otherwise the value is used as a context-specific tag */

#ifndef DEFAULT_TAG
  #define DEFAULT_TAG			-1
#endif /* DEFAULT_TAG */

/* The key record for a key.  This serves as a general algorithm-independant
   container to hold the information related to a key */

typedef struct KI {
	/* Key components */
	CRYPT_ALGO algorithm;		/* PKC algorithm */
	void *keyInfo;				/* PKC key information */
	int keyInfoSize;			/* PKC key information size */

	/* Key ID information */
	BYTE keyID[ CRYPT_MAX_KEYIDSIZE ];	/* The key ID */
	int keyIDsize;				/* The key ID size */

	/* General information */
	time_t validFrom;			/* Valid from date */
	time_t validTo;				/* Valid to date */
	} PKC_INFO;

/****************************************************************************
*																			*
*							ASN.1 Crypto Types Routines						*
*																			*
****************************************************************************/

/* Read and write keys in the X.509 SubjectPublicKeyInfo format */

int readPublicKey( STREAM *stream, PKC_INFO *pkcInfo );
int writePublicKey( STREAM *stream, const PKC_INFO *pkcInfo );

#ifdef FULL_KEYMGMT

/* Routines for reading and writing key collection header records.  These are
   somewhat different from the usual ASN.1 routines in that they only handle
   input and output of the header values, as there's no need to do anything
   else */

int sizeofHeader( const int noRecords, const int maxVersion );
int writeHeader( STREAM *stream, const int noRecords, const int maxVersion, \
				 const char *description, const int tag );
int _readHeader( STREAM *stream, int *noRecords, int *maxVersion, \
				 char *description, const BOOLEAN readIdent );

#define readHeader( stream, noRecords, maxVersion, description ) \
	_readHeader( stream, noRecords, maxVersion, description, TRUE );
#define readHeaderData( stream, noRecords, maxVersion, description ) \
	_readHeader( stream, noRecords, maxVersion, description, FALSE );

/* Routines for reading and writing public and private keys.  These are
   somewhat different from the usual ASN.1 routines in that they only handle
   input and output of the keys.  Anything beyond that is up to the user */

int sizeofKey( PKC_INFO *pkcInfo );
int writeKey( STREAM *stream, PKC_INFO *pkcInfo, const int tag );
int _readKey( STREAM *stream, PKC_INFO *pkcInfo, const BOOLEAN readIdent,
			  const BOOLEAN isPublicKey );

#define readPublicKey( stream, pkcInfo ) \
		_readKey( stream, pkcInfo, TRUE, TRUE )
#define readPublicKeyData( stream, pkcInfo ) \
		_readKey( stream, pkcInfo, FALSE, TRUE )

#define readPrivateKey( stream, rsaPrivateKey ) \
		_readKey( stream, rsaPrivateKey, TRUE, FALSE )
#define readPrivateKeyData( stream, rsaPrivateKey ) \
		_readKey( stream, rsaPrivateKey, FALSE, FALSE )

/* Routines for reading and writing key record headers */

int writeKeyRecordHeader( STREAM *stream, int length, const int tag );
int _readKeyRecordHeader( STREAM *stream, int *length, const BOOLEAN readIdent );

#define readKeyRecordHeader( stream, length ) \
	_readKeyRecordHeader( stream, length, TRUE )
#define readKeyRecordHeaderData( stream, length ) \
	_readKeyRecordHeader( stream, length, FALSE )

/* Routines for reading and writing key information and certificate headers.
   Since these are functionally identical (both read/write a SET tag) we use
   the same code for both */

int writeKeyInfoHeader( STREAM *stream, int length, const int tag );
int _readKeyInfoHeader( STREAM *stream, int *length, const BOOLEAN readIdent );

#define readKeyInfoHeader( stream, length ) \
	_readKeyInfoHeader( stream, length, TRUE )
#define readKeyInfoHeaderData( stream, length ) \
	_readKeyInfoHeader( stream, length, FALSE )
#define writeKeyCertHeader( stream, length, tag ) \
	writeKeyInfoHeader( stream, length, tag )
#define readKeyCertHeader( stream, length ) \
	_readKeyInfoHeader( stream, length, TRUE )
#define readKeyCertHeaderData( stream, length ) \
	_readKeyInfoHeader( stream, length, FALSE )

#endif /* FULL_KEYMGMT */

#endif /* _ASN1KEYS_DEFINED */
