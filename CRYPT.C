/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions".
												- Don Alvarez */

/* Prototypes for functions in cryptcapability.c */

BOOLEAN queryCapabilitiesInited( void );
void freeCapabilityList( void );
int initCapabilities( void );
int addCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, int blockSize,
				   char *name, int speed, int minKeySize, int keySize,
				   int maxKeySize );
CAPABILITY_INFO *findCapabilityInfo( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode );

/* Prototypes for functions in cryptdbx.c */

int deleteAllKeysetContexts( void );

/* To convert from the external CRYPT_CONTEXT cookie which is used to
   reference encryption contexts to the internal CRYPT_INFO structure, we
   subtract an offset from the CRYPT_CONTEXT value to obtain a pointer to
   the CRYPT_INFO struct.  The use of the conversion offset means programs
   outside the library security perimeter will generate a protection
   violation if they try to treat the CRYPT_CONTEXT as a pointer to
   anything unless they go to some lengths to determine the conversion
   value */

int cryptContextConversionOffset;

/****************************************************************************
*																			*
*				Memory Management Functions for Encryption Contexts			*
*																			*
****************************************************************************/

/* The linked list of encryption contexts */

static CRYPT_INFO *cryptInfoListHead = NULL, *cryptInfoListTail;

/* Create an encryption context and add it to the list */

static int createCryptContext( CRYPT_INFO **cryptInfo )
	{
	CRYPT_INFO *newElement;
	int status;

	/* Allocate memory for the new encryption context */
	if( ( status = secureMalloc( ( void ** ) &newElement,
								 sizeof( CRYPT_INFO ) ) ) != CRYPT_OK )
		return( status );
	memset( newElement, 0, sizeof( CRYPT_INFO ) );

	/* Link it into the list */
	if( cryptInfoListHead == NULL )
		cryptInfoListHead = newElement;
	else
		{
		cryptInfoListTail->next = newElement;
		newElement->prev = cryptInfoListTail;
		}
	cryptInfoListTail = newElement;

	*cryptInfo = newElement;
	return( CRYPT_OK );
	}

/* Delete an encryption context from the list */

static void deleteCryptContext( CRYPT_INFO *cryptInfo )
	{
	CRYPT_INFO *cryptInfoPrevPtr = cryptInfo->prev, *cryptInfoNextPtr = cryptInfo->next;

	/* Remove the encryption context from the list of contexts */
	if( cryptInfo == cryptInfoListHead )
		{
		/* Special case for first encryption context */
		cryptInfoListHead = cryptInfoNextPtr;
		if( cryptInfoNextPtr != NULL )
			cryptInfoNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		cryptInfoPrevPtr->next = cryptInfoNextPtr;
		if( cryptInfoNextPtr != NULL )
			cryptInfoNextPtr->prev = cryptInfoPrevPtr;
		}

	/* If this was the last element, move the tail pointer back */
	if( cryptInfoListTail == cryptInfo )
		cryptInfoListTail = cryptInfoPrevPtr;

	/* Clear all data in the encryption context and free the memory */
	secureFree( ( void ** ) &cryptInfo );
	}

/* Delete all encryption contexts */

static int deleteAllCryptContexts( void )
	{
	CRYPT_INFO *cryptInfoListPtr = cryptInfoListHead;

	/* If there are no remaining allocated encryption contexts, return now */
	if( cryptInfoListPtr == NULL )
		return( CRYPT_OK );

	/* Destroy any remaining encryption contexts */
	while( cryptInfoListPtr != NULL )
		{
		CRYPT_INFO *cryptInfoToFree = cryptInfoListPtr;

		cryptInfoListPtr = cryptInfoListPtr->next;
		cryptDestroyContext( INFO_TO_CONTEXT( cryptInfoToFree ) );
		}

	/* If there were encryption contexts still allocated we warn the user
	   about it */
	return( CRYPT_ORPHAN );
	}

/****************************************************************************
*																			*
*							Capability Query Functions						*
*																			*
****************************************************************************/

/* Determine whether a given encryption mode is available */

CRET cryptModeAvailable( const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode )
	{
	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );

	/* Make sure the library has been initalised */
	if( !queryCapabilitiesInited() )
		return( CRYPT_NOTINITED );

	/* See if we have any information on this encryption algo/mode */
	if( findCapabilityInfo( cryptAlgo, cryptMode ) == NULL )
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );

	return( CRYPT_OK );
	}

CRET cryptAlgoAvailable( const CRYPT_ALGO cryptAlgo )
	{
	return( cryptModeAvailable( cryptAlgo, CRYPT_MODE_NONE ) );
	}

/* Get information on a given encrytion algorithm */

CRET cryptQueryAlgoMode( const CRYPT_ALGO cryptAlgo, \
						 const CRYPT_MODE cryptMode, \
						 CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CAPABILITY_INFO *capabilityInfo;

	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptQueryInfo == NULL )
		return( CRYPT_BADPARM3 );

	/* Make sure the library has been initalised */
	if( !queryCapabilitiesInited() )
		return( CRYPT_NOTINITED );

	/* Clear the fields in the query structure */
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );

	/* Find the information record on this algorithm */
	if( ( capabilityInfo = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		{
		cryptQueryInfo->algoName = "";
		cryptQueryInfo->blockSize = CRYPT_ERROR;
		cryptQueryInfo->minKeySize = CRYPT_ERROR;
		cryptQueryInfo->keySize = CRYPT_ERROR;
		cryptQueryInfo->maxKeySize = CRYPT_ERROR;
		cryptQueryInfo->minIVsize = CRYPT_ERROR;
		cryptQueryInfo->ivSize = CRYPT_ERROR;
		cryptQueryInfo->maxIVsize = CRYPT_ERROR;
		cryptQueryInfo->speed = CRYPT_ERROR;
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );
		}

	/* Return the appropriate information */
	cryptQueryInfo->cryptAlgo = cryptAlgo;
	cryptQueryInfo->cryptMode = cryptMode;
	cryptQueryInfo->algoName = capabilityInfo->algoName;
	cryptQueryInfo->modeName = capabilityInfo->modeName;
	cryptQueryInfo->blockSize = capabilityInfo->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfo->minKeySize;
	cryptQueryInfo->keySize = capabilityInfo->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfo->maxKeySize;
	cryptQueryInfo->minIVsize = capabilityInfo->minIVsize;
	cryptQueryInfo->ivSize = capabilityInfo->ivSize;
	cryptQueryInfo->maxIVsize = capabilityInfo->maxIVsize;
	cryptQueryInfo->speed = capabilityInfo->speed;
	return( CRYPT_OK );
	}

/* Get information on the algorithm used by a given encryption context */

CRET cryptQueryContext( const CRYPT_CONTEXT cryptContext, \
						CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* Fill in the basic information */
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	if( ( status = cryptQueryAlgoMode( capabilityInfoPtr->cryptAlgo,
						capabilityInfoPtr->cryptMode, cryptQueryInfo ) ) != CRYPT_OK )
		return( status );

	/* We may be able to get more specific information than the generic
	   cryptQueryAlgoMode() call could give us since the encryption context
	   contains extra information on the algorithm being used */
	if( capabilityInfoPtr->getKeysizeFunction != NULL )
		cryptQueryInfo->maxKeySize = \
					capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr );

	/* If it's a hash function, copy in the current state */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_NONE )
		{
		if( ( status = capabilityInfoPtr->getDataFunction( cryptInfoPtr,
								cryptQueryInfo->hashValue ) ) != CRYPT_OK )
			return( status );
		}

	/* If it's a PKC function, copy in the key ID */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_PKC )
		{
		memcpy( cryptQueryInfo->keyID, cryptInfoPtr->keyID,
				cryptInfoPtr->keyIDlength );
		cryptQueryInfo->keyIDsize = cryptInfoPtr->keyIDlength;
		}

	/* Copy in other information */
	cryptQueryInfo->controlVector = cryptInfoPtr->controlVector;

	return( CRYPT_OK );
	}

/* Initialise and shut down the encryption library.  If we're being called
   from a DLL then the startup code will have already initialised the library,
   so we don't need to do anything further.  The use of a global variable to
   control this is somewhat messy, but there isn't really any clean way to do
   it */

#ifdef __WINDOWS__
  static BOOLEAN isDLLcall = FALSE;
#endif /* __WINDOWS__ */

static BOOLEAN isInitialised = FALSE;

CRET cryptInit( void )
	{
	/* Make sure we don't get called more than once */
	if( isInitialised )
		return( CRYPT_INITED );
	isInitialised = TRUE;

	/* Set up the conversion offset used to translate CRYPT_CONTEXT cookies
	   into CRYPT_INFO structures.  This doesn't have to be secure, just a
	   random value that isn't too easy to guess and which generates some
	   form of error if the the CRYPT_CONTEXT it is added to is treated as a
	   pointer (makeCookie() forces an odd address which guarantees this for
	   most architectures) */
	cryptContextConversionOffset = makeCookie( ( int ) time( NULL ) );

	/* Initialise the BigNum library */
	bnInit();

	return( initCapabilities() );
	}

CRET cryptEnd( void )
	{
	int status, dbxStatus;

#ifdef __WINDOWS__
	if( !isDLLcall )
		return( CRYPT_OK );
#endif /* __WINDOWS__ */

	/* If we haven't been initialised yet, signal an error */
	if( !isInitialised )
		return( CRYPT_NOTINITED );

	/* Clean up all library data structures */
	status = deleteAllCryptContexts();
	dbxStatus = deleteAllKeysetContexts();
	freeCapabilityList();
	endRandom();

	return( cryptStatusOK( status ) ? cryptStatusOK( dbxStatus ) ? \
			CRYPT_OK : dbxStatus : status );
	}

/****************************************************************************
*																			*
*					Encryption Context Management Functions					*
*																			*
****************************************************************************/

/* A magic value to detect whether an encryption context has been
   initialised yet */

#define CRYPT_MAGIC		0xC0EDBABEUL

/* Initialise or perform an extended initialisation of an encryption
   context */

CRET cryptCreateContextEx( CRYPT_CONTEXT CPTR cryptContext, \
						   const CRYPT_ALGO cryptAlgo, \
						   const CRYPT_MODE cryptMode, \
						   const void CPTR cryptInfoEx )
	{
	CRYPT_ALGO localCryptAlgo = cryptAlgo;
	CRYPT_MODE localCryptMode = cryptMode;
	CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	if( cryptContext == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST && \
		cryptAlgo != CRYPT_USE_DEFAULT )
		return( CRYPT_BADPARM2 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST && \
		cryptMode != CRYPT_USE_DEFAULT )
		return( CRYPT_BADPARM3 );
	if( cryptInfoEx == NULL )
		return( CRYPT_BADPARM4 );

	/* Handle any default settings for algorithm and mode */
	if( cryptAlgo == CRYPT_USE_DEFAULT )
		{
		/* If the mode is CRYPT_MODE_NONE, it's a hash context */
		if( cryptMode == CRYPT_MODE_NONE )
			localCryptAlgo = getOptionHashAlgo();
		else
			/* If the mode is CRYPT_MODE_PKC, it's a PKC context */
			if( cryptMode == CRYPT_MODE_PKC )
				localCryptAlgo = getOptionPKCAlgo();
			else
				{
				/* It's a conventional encryption context */
				localCryptAlgo = getOptionCryptAlgo();
				if( cryptMode == CRYPT_USE_DEFAULT )
					localCryptMode = getOptionCryptMode();
				}
		}
	if( localCryptMode == CRYPT_USE_DEFAULT )
		if( ( cryptAlgo < CRYPT_ALGO_FIRST_CONVENTIONAL ) || \
			( cryptAlgo >= CRYPT_ALGO_LAST_CONVENTIONAL ) )
			return( CRYPT_BADPARM3 );
		else
			localCryptMode = getOptionCryptMode();

	/* Set up the pointer to the capability information and make sure the
	   context can use the extended initialisation parameters if they're
	   present */
	if( ( capabilityInfoPtr = findCapabilityInfo( localCryptAlgo, localCryptMode ) ) == NULL )
		return( ( cryptAlgoAvailable( localCryptAlgo ) ) ? \
				CRYPT_NOMODE : CRYPT_NOALGO );
	if( cryptInfoEx != ( void * ) CRYPT_UNUSED && \
		capabilityInfoPtr->initExFunction == NULL )
		return( CRYPT_BADPARM2 );

	/* Make sure the algorithm self-test went OK */
	if( capabilityInfoPtr->selfTestStatus != CRYPT_OK )
		return( CRYPT_SELFTEST );

	/* We're through the intialization phase, now we can create the
	   encryption context */
	if( ( status = createCryptContext( &cryptInfoPtr ) ) != CRYPT_OK )
		return( status );
	cryptInfoPtr->capabilityInfo = capabilityInfoPtr;
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_PKC )
		{
		cryptInfoPtr->isPKCcontext = TRUE;
		cryptInfoPtr->keySizeBits = 0;
		cryptInfoPtr->ivSet = TRUE;	/* No IV for PKC's */

		/* Initialise the BigNum information */
		bnBegin( &cryptInfoPtr->pkcParam1 );
		bnBegin( &cryptInfoPtr->pkcParam2 );
		bnBegin( &cryptInfoPtr->pkcParam3 );
		bnBegin( &cryptInfoPtr->pkcParam4 );
		bnBegin( &cryptInfoPtr->pkcParam5 );
		bnBegin( &cryptInfoPtr->pkcParam6 );
		bnBegin( &cryptInfoPtr->pkcParam7 );
		bnBegin( &cryptInfoPtr->pkcParam8 );
		}

	/* Perform any algorithm-specific initialization */
	if( cryptInfoEx == ( void * ) CRYPT_UNUSED )
		{
		if( capabilityInfoPtr->initFunction != NULL )
			status = capabilityInfoPtr->initFunction( cryptInfoPtr );
		}
	else
		status = capabilityInfoPtr->initExFunction( cryptInfoPtr, cryptInfoEx );
	if( cryptStatusError( status ) )
		{
		deleteCryptContext( cryptInfoPtr );
		return( status );
		}

	/* If we don't need a key and IV, record them as being set */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_NONE )
		{
		cryptInfoPtr->keySet = TRUE;
		cryptInfoPtr->ivSet = TRUE;
		}

	/* Set up the IV information and key cookie export flag to the default
	   values.  These can be overridden later if required */
	cryptInfoPtr->ivLength = capabilityInfoPtr->ivSize;
	cryptInfoPtr->exportKeyCookie = CRYPT_USE_DEFAULT;

	/* Set the check value.  Note that we set it after the capability info
	   has been set, so that a check on this value will also tell us whether
	   the capability info is present */
	cryptInfoPtr->checkValue = CRYPT_MAGIC;

	/* Convert the encryption information pointer to an encryption context
	   and return it to the user */
	*cryptContext = INFO_TO_CONTEXT( cryptInfoPtr );

	return( CRYPT_OK );
	}

/* Destroy an encryption context */

CRET cryptDestroyContext( CRYPT_CONTEXT cryptContext )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* Perform any algorithm-specific shutdown */
	if( cryptInfoPtr->capabilityInfo->endFunction != NULL )
		{
		int status;

		status = cryptInfoPtr->capabilityInfo->endFunction( cryptInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's a PKC crypt context, free the BigNum information */
	if( cryptInfoPtr->isPKCcontext )
		{
		bnEnd( &cryptInfoPtr->pkcParam1 );
		bnEnd( &cryptInfoPtr->pkcParam2 );
		bnEnd( &cryptInfoPtr->pkcParam3 );
		bnEnd( &cryptInfoPtr->pkcParam4 );
		bnEnd( &cryptInfoPtr->pkcParam5 );
		bnEnd( &cryptInfoPtr->pkcParam6 );
		bnEnd( &cryptInfoPtr->pkcParam7 );
		bnEnd( &cryptInfoPtr->pkcParam8 );
		if( cryptInfoPtr->userID != NULL )
			{
			zeroise( cryptInfoPtr->userID, strlen( cryptInfoPtr->userID ) );
			free( cryptInfoPtr->userID );
			}
		if( cryptInfoPtr->pkcInfo != NULL )
			secureFree( &cryptInfoPtr->pkcInfo );
		}

	/* Delete the encryption context */
	deleteCryptContext( cryptInfoPtr );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Keying Functions							*
*																			*
****************************************************************************/

/* Load a user key into an encryption context */

CRET cryptLoadContext( CRYPT_CONTEXT cryptContext, void CPTR userKey,
					   const int userKeyLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( userKey == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	if( !cryptInfoPtr->isPKCcontext &&
		( userKeyLength < capabilityInfoPtr->minKeySize ||
		  userKeyLength > capabilityInfoPtr->maxKeySize ) )
		return( CRYPT_BADPARM3 );
	if( capabilityInfoPtr->initKeyFunction == NULL )
		return( CRYPT_NOALGO );

	/* If it's a hash function, the load key operation is meaningless */
	if( capabilityInfoPtr->cryptMode == CRYPT_MODE_NONE )
		return( CRYPT_NOTAVAIL );

	/* Load either PKC keying information or a conventional key */
	if( cryptInfoPtr->isPKCcontext )
		{
		/* Call the algorithm-specific function to load the key components */
		cryptInfoPtr->keyComponentPtr = ( void CPTR ) userKey;
		if( ( status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr ) ) != CRYPT_OK )
			return( status );
		}
	else
		{
		/* Some conventional algorithms allow various key sizes depending on
		   how they're used.  We now perform a more rigorous check to make
		   sure that the key length is correct */
		if( capabilityInfoPtr->getKeysizeFunction != NULL && \
			userKeyLength > capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr ) )
			return( CRYPT_BADPARM3 );

		/* Load the user encryption key into the encryption context */
		memcpy( cryptInfoPtr->userKey, userKey, userKeyLength );
		cryptInfoPtr->userKeyLength = userKeyLength;
		if( cryptInfoPtr->clearBuffer )
			zeroise( userKey, userKeyLength );

		/* Remember that we need to set an IV before we encrypt anything */
		if( needsIV( capabilityInfoPtr->cryptMode ) )
			cryptInfoPtr->ivSet = FALSE;
		else
			/* We don't need an IV, record it as being set */
			cryptInfoPtr->ivSet = TRUE;

		/* Call the encryption routine for this algorithm/mode */
		status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* Generate the key cookie for this key */
		status = generateKeyCookie( cryptInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Record the fact that the key has been initialized */
	cryptInfoPtr->keySet = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IV Handling Functions							*
*																			*
****************************************************************************/

/* Load an IV into an encryption context */

CRET cryptLoadIV( CRYPT_CONTEXT cryptContext, const void CPTR iv, const int ivLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( iv == NULL )
		return( CRYPT_BADPARM2 );
	if( ivLength < cryptInfoPtr->capabilityInfo->minIVsize ||
		ivLength > cryptInfoPtr->capabilityInfo->maxIVsize )
		return( CRYPT_BADPARM3 );

	/* If it's a PKC crypt context or an mode which doesn't use an IV, the
	   load IV operation is meaningless */
	if( cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );
	if( !needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		return( CRYPT_NOTAVAIL );

	/* Load the IV */
	return( loadIV( cryptInfoPtr, iv, ivLength ) );
	}

/* Retrieve an IV from an encryption context */

CRET cryptRetrieveIV( CRYPT_CONTEXT cryptContext, void CPTR iv )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( iv == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* If it's a PKC crypt context or an mode which doesn't use an IV, the
	   load IV operation is meaningless */
	if( cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );
	if( !needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		return( CRYPT_NOTAVAIL );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Copy the IV data of the required length to the output buffer */
	memcpy( iv, cryptInfoPtr->iv, cryptInfoPtr->ivLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Routines						*
*																			*
****************************************************************************/

/* Encrypt a block of memory */

CRET cryptEncrypt( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfoPtr->isPKCcontext )
		{
		if( length != CRYPT_USE_DEFAULT )
			return( CRYPT_BADPARM3 );
		}
	else
		if( length < 0 )
			return( CRYPT_BADPARM3 );
	if( !cryptInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* If there's no IV set, generate one ourselves */
	if( !cryptInfoPtr->ivSet )
		{
		BYTE iv[ CRYPT_MAX_IVSIZE ];
		int status;

		getNonce( iv, cryptInfoPtr->ivLength );
		if( ( status = loadIV( cryptInfoPtr, iv, cryptInfoPtr->ivLength ) ) != CRYPT_OK )
			return( status );
		}

	/* Call the encryption routine for this algorithm/mode */
	return( cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr, buffer, length ) );
	}

/* Decrypt a block of memory */

CRET cryptDecrypt( CRYPT_CONTEXT cryptContext, void CPTR buffer, \
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfoPtr->isPKCcontext )
		{
		if( length != CRYPT_USE_DEFAULT )
			return( CRYPT_BADPARM3 );
		}
	else
		if( length < 0 )
			return( CRYPT_BADPARM3 );
	if( !cryptInfoPtr->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfoPtr->capabilityInfo->decryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Call the decryption routine for this algorithm/mode */
	return( cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr, buffer, length ) );
	}

/****************************************************************************
*																			*
*							Miscellaneous Routines							*
*																			*
****************************************************************************/

#if 0

/* Add a new encryption capability to the library.  This routine is quite
   powerful, but what a kludge! */

CRET cryptAddCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
						 int blockSize, char *name, int speed, \
						 int minKeySize, int keySize, int maxKeySize )
	{
	int status;

	/* Add the basic capability information */
	status = addCapability( cryptAlgo, cryptMode, blockSize, name,
							speed, minKeySize, keySize, maxKeySize );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the handlers */
/* Not implemented yet */

	return( CRYPT_ERROR );
	}
#endif /* 0 */

/* Perform a library IOCTL */

CRET cryptIoctl( CRYPT_IOCTL ioctlCode, void CPTR ioctlInformation,
				 CRYPT_CONTEXT cryptContext )
	{
	/* Perform basic error checking */
	if( ioctlCode < CRYPT_IOCTL_NONE || ioctlCode > CRYPT_IOCTL_LAST )
		return( CRYPT_BADPARM1 );
	if( ioctlCode != CRYPT_IOCTL_NONE && ioctlInformation == NULL )
		return( CRYPT_BADPARM2 );
	if( ioctlCode == CRYPT_IOCTL_NONE || ioctlCode == CRYPT_IOCTL_MEMORY )
		{
		if( cryptContext != NULL )
			return( CRYPT_BADPARM3 );
		}
	else
		if( cryptContext != NULL && isBadCookie( cryptContext ) )
			return( CRYPT_BADPARM3 );

	/* Null IOCTL */
	if( ioctlCode == CRYPT_IOCTL_NONE )
		return( CRYPT_OK );

	/* Memory locking IOCTL */
	if( ioctlCode == CRYPT_IOCTL_MEMORY )
		{
		CRYPT_IOCTLINFO_MEMORY *ioctlInfo = \
							( CRYPT_IOCTLINFO_MEMORY * ) ioctlInformation;

		if( ioctlInfo->memoryLockType < CRYPT_MEMORY_NOLOCK || \
			ioctlInfo->memoryLockType > CRYPT_MEMORY_FORCELOCK )
			return( CRYPT_BADPARM2 );
		setOptionMemoryLockType( ioctlInfo->memoryLockType );
		return( CRYPT_OK );
		}

	/* Cookie export IOCTL's */
	if( ioctlCode == CRYPT_IOCTL_KEYCOOKIE )
		{
		CRYPT_IOCTLINFO_COOKIE *ioctlInfo = \
							( CRYPT_IOCTLINFO_COOKIE * ) ioctlInformation;
		if( cryptContext == NULL )
			setOptionExportKeyCookie( ( BOOLEAN ) ioctlInfo->exportCookie );
		else
			{
			CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

			cryptInfoPtr->exportKeyCookie = ioctlInfo->exportCookie;
			}
		return( CRYPT_OK );
		}
	if( ioctlCode == CRYPT_IOCTL_SIGCOOKIE )
		{
		CRYPT_IOCTLINFO_COOKIE *ioctlInfo = \
							( CRYPT_IOCTLINFO_COOKIE * ) ioctlInformation;
		if( cryptContext == NULL )
			setOptionExportSigCookie( ( BOOLEAN ) ioctlInfo->exportCookie );
		else
			{
			CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

			cryptInfoPtr->exportSigCookie = ioctlInfo->exportCookie;
			}
		return( CRYPT_OK );
		}

	/* PKC padding type IOCTL */
	if( ioctlCode == CRYPT_IOCTL_PKCPADDING )
		{
		CRYPT_IOCTLINFO_PKCPADDING *ioctlInfo = \
							( CRYPT_IOCTLINFO_PKCPADDING * ) ioctlInformation;
		if( cryptContext == NULL )
			setOptionUseOAEP( ( BOOLEAN ) ioctlInfo->useOAEP );
		else
			{
			CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );

			cryptInfoPtr->useOAEP = ioctlInfo->useOAEP;
			}
		return( CRYPT_OK );
		}

	/* Keyset table names IOCTL */
	if( ioctlCode == CRYPT_IOCTL_KEYSETNAMES )
		{
		CRYPT_IOCTLINFO_KEYSETNAMES *ioctlInfo = \
							( CRYPT_IOCTLINFO_KEYSETNAMES * ) ioctlInformation;
		if( cryptContext == NULL )
			setOptionKeysetNames( ioctlInfo );
		else
			/* The keyset-specific config is implemented in cryptdbx.c since
			   it involves manipulation of the KEYSET_INFO structure which
			   isn't exported to the entire library */
			return( setKeysetNames( cryptContext, ioctlInfo ) );
		return( CRYPT_OK );
		}

	/* We should never get here */
	return( CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !defined( __WIN32__ )

/* Whether LibMain() has been called before */

static BOOLEAN libMainCalled = FALSE;
static HWND hInst;

/* The main function for the DLL */

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{   
	int status;
	
	/* If we've been called before, return with an error message */
	if( libMainCalled )
		return( FALSE );
	libMainCalled = TRUE;

	/* Initialise the library */
	isDLLcall = TRUE;
	status = cryptInit();
	isDLLcall = FALSE;
	if( status != CRYPT_OK )
		return( FALSE );

	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

/* Shut down the DLL */

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	/* Shut down the encryption library if necessary */
	isDLLcall = TRUE;
	cryptEnd();
	isDLLcall = FALSE;

	return( TRUE );
	}

#elif defined( __WINDOWS__ ) && defined( __WIN32__ )

static HANDLE hLibInst;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	int status;

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Remember the instance handle and initialise the library */
			hLibInst = hinstDLL;
			isDLLcall = TRUE;
			status = cryptInit();
			isDLLcall = FALSE;
			break;

		case DLL_PROCESS_DETACH:
			/* Shut down the library */
			isDLLcall = TRUE;
			cryptEnd();
			isDLLcall = FALSE;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( ( status == CRYPT_OK ) ? TRUE : FALSE );
	}
#endif /* __WINDOWS__ && !__WIN32__ */
