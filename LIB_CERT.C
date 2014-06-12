/****************************************************************************
*																			*
*					cryptlib Certificate Management Routines				*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1keys.h"
#else
  #include "keymgmt/asn1keys.h"
#endif /* Compiler-specific includes */

/* The structure which holds information on a list element */

typedef struct LI {
	/* The list element payload */
	void *data;
	int dataSize;

	/* The next and previous list element in the linked list of elements */
	struct LI *next, *prev;
	} LISTITEM;

/* The structure which stores information on a certificate */

typedef struct RI {
	/* The DER-encoded SubjectPublicKeyInfo */
	void *keyInfo;					/* Key information */
	int keyInfoSize;				/* Size of the key information */

	/* General certificate information */
	long serialNumber;				/* This may be a bignum, but there don't
									   seem to be any implementations which
									   do this */
	time_t validityNotBefore;		/* Validity start */
	time_t validityNotAfter;		/* Validity end */

	/* Name fields */
	LISTITEM *issuerNameHead, *issuerNameTail;	/* Issuer name */
	LISTITEM *subjectNameHead, *subjectNameTail;/* Subject name */

	/* A check value so we can determine whether the keyset context has been
	   initialised or not.  This is needed because passing in an
	   uninitialised block of memory as a keyset context can lead to problems
	   when we try to dereference wild pointers */
	LONG checkValue;

	/* The next and previous certificate context in the linked list of
	   contexts */
	struct RI *next, *prev;
	} CERT_INFO;

/* Macros to convert to/from certificate contexts.  These are analogous to
   the encryption context macros in crypt.h */

#define CERT_TO_INFO( x )	( CERT_INFO * ) ( ( BYTE * ) x - cryptContextConversionOffset )
#define INFO_TO_CERT( x )	( CRYPT_CERT ) ( ( BYTE * ) x + cryptContextConversionOffset )

/****************************************************************************
*																			*
*					List Functions for Certificate Information				*
*																			*
****************************************************************************/

/* Insert an element into a list */

static int insertElement( LISTITEM **listHead, LISTITEM **listTail,
						  void *data, int dataLength )
	{
	LISTITEM *newElement;

	/* Allocate memory for the new element */
	if( ( newElement  = ( LISTITEM * ) malloc( sizeof( LISTITEM ) ) ) == NULL )
		return( CRYPT_NOMEM );
	if( ( newElement->data = malloc( dataLength ) ) == NULL )
		{
		free( newElement );
		return( CRYPT_NOMEM );
		}
	memset( newElement, 0, sizeof( LISTITEM ) );
	memcpy( newElement->data, data, dataLength );
	newElement->dataSize = dataLength;

	/* Link it into the list */
	if( *listHead == NULL )
		*listHead = newElement;
	else
		{
		( *listTail )->next = newElement;
		newElement->prev = *listTail;
		}
	*listTail = newElement;

	return( CRYPT_OK );
	}

/* Delete an element from a list */

static void deleteElement( LISTITEM **listHead, LISTITEM **listTail,
						   LISTITEM *listItem )
	{
	LISTITEM *listPrevPtr = listItem->prev, *listNextPtr = listItem->next;

	/* Remove the item from the list */
	if( listItem == *listHead )
		{
		/* Special case for first item */
		*listHead = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		listPrevPtr->next = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = listPrevPtr;
		}

	/* If this was the last element, move the tail pointer back */
	if( *listTail == listItem )
		*listTail = listPrevPtr;

	/* Clear all data in the list item and free the memory */
	zeroise( listItem->data, listItem->dataSize );
	free( listItem->data );
	zeroise( listItem, sizeof( LISTITEM ) );
	free( listItem );
	}

/* Delete a list */

static void deleteList( LISTITEM **listHead, LISTITEM **listTail )
	{
	LISTITEM *listPtr = *listHead;

	/* Mark the list as being empty */
	*listHead = *listTail = NULL;

	/* If the list was empty, return now */
	if( listPtr == NULL )
		return;

	/* Destroy any remaining list items */
	while( listPtr != NULL )
		{
		LISTITEM *itemToFree = listPtr;

		listPtr = listPtr->next;
		zeroise( itemToFree->data, itemToFree->dataSize );
		free( itemToFree->data );
		zeroise( itemToFree, sizeof( LISTITEM ) );
		free( itemToFree );
		}
	}

/****************************************************************************
*																			*
*				Memory Management Functions for Certificate Contexts		*
*																			*
****************************************************************************/

/* The linked list of certificate contexts */

static CERT_INFO *certInfoListHead = NULL, *certInfoListTail;

/* Create a cert context and add it to the list */

static int createCertificateContext( CERT_INFO **certInfo )
	{
	CERT_INFO *newElement;

	/* Allocate memory for the new cert context */
	if( ( newElement  = malloc( sizeof( CERT_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( CERT_INFO ) );

	/* Link it into the list */
	if( certInfoListHead == NULL )
		certInfoListHead = newElement;
	else
		{
		certInfoListTail->next = newElement;
		newElement->prev = certInfoListTail;
		}
	certInfoListTail = newElement;

	*certInfo = newElement;
	return( CRYPT_OK );
	}

/* Delete a certificate context from the list */

static void deleteCertificateContext( CERT_INFO *certInfo )
	{
	CERT_INFO *certInfoPrevPtr = certInfo->prev, *certInfoNextPtr = certInfo->next;

	/* Remove the cert context from the list of contexts */
	if( certInfo == certInfoListHead )
		{
		/* Special case for first certificate */
		certInfoListHead = certInfoNextPtr;
		if( certInfoNextPtr != NULL )
			certInfoNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		certInfoPrevPtr->next = certInfoNextPtr;
		if( certInfoNextPtr != NULL )
			certInfoNextPtr->prev = certInfoPrevPtr;
		}

	/* If this was the last element, move the tail pointer back */
	if( certInfoListTail == certInfo )
		certInfoListTail = certInfoPrevPtr;

	/* Clear all data in the cert context and free the memory */
	zeroise( certInfo, sizeof( CERT_INFO ) );
	free( certInfo );
	}

/* Delete all certificate contexts */

int deleteAllCertificateContexts( void )
	{
	CERT_INFO *certInfoListPtr = certInfoListHead;

	/* Mark the list as being empty */
	certInfoListHead = certInfoListTail = NULL;

	/* If there are no remaining allocated cert contexts, return now */
	if( certInfoListPtr == NULL )
		return( CRYPT_OK );

	/* Destroy any remaining cert contexts */
	while( certInfoListPtr != NULL )
		{
		CERT_INFO *certInfoToFree = certInfoListPtr;

		certInfoListPtr = certInfoListPtr->next;
		cryptDestroyCert( INFO_TO_CERT( certInfoToFree ) );
		}

	/* If there were cert contexts still allocated, warn the user about
	   them */
	return( CRYPT_ORPHAN );
	}

/****************************************************************************
*																			*
*						Certificate Management API Functions				*
*																			*
****************************************************************************/

/* Create/destroy a certificate */

CRET cryptCreateCert( CRYPT_CERT CPTR certificate,
					  const CRYPT_CONTEXT pkcContext )
	{
	STREAM stream;
	CERT_INFO *certInfoPtr;
	CRYPT_INFO *pkcInfoPtr = CONTEXT_TO_INFO( pkcContext );
	void *keyInfo;
	int keyInfoSize, status;

	/* Perform basic error checking */
	if( certificate == NULL )
		return( CRYPT_BADPARM1 );
	if( isBadCookie( pkcContext ) || \
		pkcInfoPtr->checkValue != CRYPT_MAGIC || \
		!pkcInfoPtr->keySet || !pkcInfoPtr->isPKCcontext )
		return( CRYPT_BADPARM2 );

	/* Find out how large the encoded key information will be and allocate
	   memory for it */
	sMemNullOpen( &stream );
	status = writePublicKey( &stream, pkcInfoPtr->pkcInfo );
	keyInfoSize = sMemSize( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( ( keyInfo = malloc( keyInfoSize ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the certificate context */
	if( ( status = createCertificateContext( &certInfoPtr ) ) != CRYPT_OK )
		{
		free( keyInfo );
		return( status );
		}

	/* Encode the PKC information as a SubjectPublicKey and store the result
	   in the public-key field of the certificate.  We don't need to check
	   the status of writePublicKey() this time since we just called it a few
	   lines ago */
	sMemOpen( &stream, keyInfo, keyInfoSize );
	writePublicKey( &stream, pkcInfoPtr->pkcInfo );
	sMemDisconnect( &stream );
	certInfoPtr->keyInfo = keyInfo;
	certInfoPtr->keyInfoSize = keyInfoSize;

	/* Set the check value */
	certInfoPtr->checkValue = CRYPT_MAGIC;

	/* Convert the keyset information pointer to a certificate context and
	   return it to the user */
	*certificate = INFO_TO_CERT( certInfoPtr );

	return( CRYPT_OK );
	}

CRET cryptDestroyCert( CRYPT_CERT certificate )
	{
	CERT_INFO *certInfoPtr = CERT_TO_INFO( certificate );

	/* Perform basic error checking */
	if( isBadCookie( certificate ) )
		return( CRYPT_BADPARM1 );
	if( certInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* Clear the SubjectPublicKeyInfo if necessary */
	if( certInfoPtr->keyInfo != NULL )
		{
		zeroise( certInfoPtr->keyInfo, certInfoPtr->keyInfoSize );
		free( certInfoPtr->keyInfo );
		}

	/* Clear the name fields if necessary */
	if( certInfoPtr->issuerNameHead != NULL )
		deleteList( &certInfoPtr->issuerNameHead, &certInfoPtr->issuerNameTail );
	if( certInfoPtr->subjectNameHead != NULL )
		deleteList( &certInfoPtr->subjectNameHead, &certInfoPtr->subjectNameTail );

	/* Delete the certificate itself */
	deleteCertificateContext( certInfoPtr );

	return( CRYPT_OK );
	}

#if 0

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

#endif /* 0 */

/* Import a certificate */

CRET cryptImportCert( const void CPTR certObject, CRYPT_CERT CPTR certificate )
	{
	CERT_INFO *certInfoPtr = CERT_TO_INFO( certificate );
	BYTE *objectPtr = ( BYTE * ) certObject;
	void *keyInfo;
	int keyInfoSize, status;

	/* Perform basic error checking */
	if( certObject == NULL )
		return( CRYPT_BADPARM1 );
	if( isBadCookie( certificate ) || \
		certInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM2 );

	/* In this release all that's supported is reading the raw
	   SubjectPublicKeyInfo record from the input */
	if( memcmp( objectPtr, "RAW0", 4 ) )
		return( CRYPT_BADDATA );
	objectPtr += 4;

	/* Find out how big the object is */
	keyInfoSize = *objectPtr++ << 8;
	keyInfoSize += *objectPtr++;

	/* Allocate room for the SubjectPublicKeyInfo record */
	if( ( keyInfo = malloc( keyInfoSize ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the certificate context */
	if( ( status = createCertificateContext( &certInfoPtr ) ) != CRYPT_OK )
		{
		free( keyInfo );
		return( status );
		}
	memcpy( keyInfo, objectPtr, keyInfoSize );
	certInfoPtr->keyInfo = keyInfo;

	/* Set the check value and convert the keyset information pointer to a
	   certificate context */
	certInfoPtr->checkValue = CRYPT_MAGIC;
	*certificate = INFO_TO_CERT( certInfoPtr );

	return( CRYPT_OK );
	}

/* Export a certificate */

CRET cryptExportCert( void CPTR certObject, int CPTR certObjectLength,
					  CRYPT_CERT certificate )
	{
	CERT_INFO *certInfoPtr = CERT_TO_INFO( certificate );

	/* Perform basic error checking */
	if( certObject == NULL )
		return( CRYPT_BADPARM1 );
	if( certObjectLength == NULL )
		return( CRYPT_BADPARM2 );
	if( isBadCookie( certificate ) || \
		certInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM3 );

	/* In this release all that's supported is writing the raw
	   SubjectPublicKeyInfo record to the output */
	*certObjectLength = certInfoPtr->keyInfoSize + 6;
	if( certObject != NULL )
		{
		BYTE *objectPtr = certObject;

		memcpy( objectPtr, "RAW0", 4 );
		objectPtr += 4;
		*objectPtr++ = certInfoPtr->keyInfoSize >> 8;
		*objectPtr++ = certInfoPtr->keyInfoSize & 0xFF;
		memcpy( objectPtr, certInfoPtr->keyInfo, certInfoPtr->keyInfoSize + 2 );
		}

	return( CRYPT_OK );
	}
