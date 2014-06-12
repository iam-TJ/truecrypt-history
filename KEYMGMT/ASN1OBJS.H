/****************************************************************************
*																			*
*								ASN.1 Object Types 							*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#ifndef _ASN1OBJS_DEFINED

#define _ASN1OBJS_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The default value for tagged types.  If this value is given the basic
   type is used, otherwise the value is used as a context-specific tag */

#ifndef DEFAULT_TAG
  #define DEFAULT_TAG			-1
#endif /* DEFAULT_TAG */

/* The ASN.1 MessageDigest type.  The isSHA1 algorithm-specific information
   field is a kludge which works for now since SHA-1 is the only algorithm
   with optional parameters, but will need to be changed if the MD types are
   ever extended to include keyed MAC's or similar algorithms */

typedef struct {
	CRYPT_ALGO type;				/* Message digest algorithm */
	BOOLEAN isSHA;					/* Set to TRUE for SHA rather than SHA1
									   if type is CRYPT_ALGO_SHA */
	BYTE data[ CRYPT_MAX_HASHSIZE ];/* Message digest */
	int length;						/* Length of MD data */
	} MESSAGE_DIGEST;

/****************************************************************************
*																			*
*							ASN.1 Object Types Routines						*
*																			*
****************************************************************************/

/* Routines for handling message digests */

int newMessageDigest( MESSAGE_DIGEST *messageDigest, const CRYPT_ALGO mdAlgo,
					  const BYTE *md, const int length );
int deleteMessageDigest( MESSAGE_DIGEST *messageDigest );
int sizeofMessageDigest( const MESSAGE_DIGEST *messageDigest );
int writeMessageDigest( STREAM *stream, const MESSAGE_DIGEST *messageDigest,
						const int tag );
int _readMessageDigest( STREAM *stream, MESSAGE_DIGEST *messageDigest,
						const BOOLEAN readIdent );

#define readMessageDigest( stream, messageDigest ) \
		_readMessageDigest( stream, messageDigest, TRUE )
#define readMessageDigestData( stream, messageDigest ) \
		_readMessageDigest( stream, messageDigest, FALSE )

/* Routines for reading and writing message digest information for creating
   generating signatures.  These add a nonce to the MD record to make sure
   we never end up signing the same information twice */

int sizeofMessageDigestInfo( const MESSAGE_DIGEST *messageDigest );
int writeMessageDigestInfo( STREAM *stream, const MESSAGE_DIGEST *messageDigest );
int readMessageDigestInfo( STREAM *stream, MESSAGE_DIGEST *messageDigest );

/* Routines for reading and writing session key information for
   encapsulation inside a conventional or PKC-encrypted data block.  The
   first function writes only the header information (but not the key
   itself) for use in various locations which need to process encryption key
   information formatted in a standardised manner) */

int writeKeyInfoHeader( STREAM *stream, const CRYPT_INFO *cryptInfo,
						int keyLength );
int sizeofKeyInfo( const CRYPT_INFO *cryptInfo, const BOOLEAN addPadding );
int writeKeyInfo( STREAM *stream, const CRYPT_INFO *cryptInfo,
				  int *keyOffset, const BOOLEAN addPadding );
int readKeyInfo( STREAM *stream, CRYPT_CONTEXT *cryptContext );

/* Routines for reading and writing encrypted and PKC-encrypted session keys */

int writeEncryptedKey( STREAM *stream, const CRYPT_INFO *cryptInfo,
					   const CRYPT_INFO *sessionKeyInfo,
					   const BYTE *buffer, const int length );
int readEncryptedKey( STREAM *stream, const CRYPT_INFO *cryptInfo,
					  CRYPT_OBJECT_INFO *cryptObjectInfo, int *keyInfoLength );
int writePKCEncryptedKey( STREAM *stream, const CRYPT_INFO *pkcInfo,
						  const CRYPT_INFO *sessionKeyInfo,
						  const BYTE *buffer, const int length );
int readPKCEncryptedKey( STREAM *stream, CRYPT_INFO *pkcInfo,
						 CRYPT_CONTEXT *sessionKeyContext,
						 CRYPT_OBJECT_INFO *cryptObjectInfo );

/* Routines for reading and writing signatures */

int writeSignature( STREAM *stream, const CRYPT_INFO *pkcInfo,
					const BYTE *buffer, const int length );
int readSignature( STREAM *stream, CRYPT_INFO *pkcInfo );

/* Routines for writing data objects */

int writeBasicObject( STREAM *stream, const BOOLEAN isContinued,
					  const long dataLength, const BOOLEAN isDataObject );
int readBasicObject( STREAM *stream, BOOLEAN *isContinued,
					 long *dataLength );
int writeEncryptedObject( STREAM *stream, const BOOLEAN isContinued,
						  const long dataLength,
						  const CRYPT_INFO *cryptInfoPtr );
int readEncryptedObject( STREAM *stream, BOOLEAN *isContinued,
						 long *dataLength,
						 CRYPT_OBJECT_INFO *cryptObjectInfo );
int writeSignedObject( STREAM *stream, const BOOLEAN isContinued,
					   const CRYPT_INFO *cryptInfoPtr, const long dataLength );
int readSignedObject( STREAM *stream, BOOLEAN *isContinued,
					  CRYPT_OBJECT_INFO *cryptObjectInfo );

/* Routines for getting information on cryptlib objects */

int readObjectWrapper( STREAM *stream, CRYPT_OBJECT_TYPE *objectType,
					   long *length );
int readCKObject( STREAM *stream, CRYPT_OBJECT_INFO *cryptObjectInfo );
int readPKObject( STREAM *stream, BYTE *keyID, int *keyIDsize,
				  CRYPT_ALGO *cryptAlgo );
int readPKKeyObject( STREAM *stream, CRYPT_ALGO cryptAlgo,
					 CRYPT_CONTEXT *cryptContext,
					 CRYPT_OBJECT_INFO *cryptObjectInfo );

#endif /* _ASN1OBJS_DEFINED */
