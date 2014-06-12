/****************************************************************************
*																			*
*						 cryptlib Key Database Routines						*
*						Copyright Peter Gutmann 1995-1996					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef __WINDOWS__
  #include <sql.h>
  #include <sqlext.h>
#endif /* __WINDOWS__ */
#ifdef INC_ALL
  #include "keymgmt.h"
#else
  #include "keymgmt/keymgmt.h"
#endif /* Compiler-specific includes */

/* The structure which stores information on a keyset */

typedef struct KI {
	/* General keyset information */
	CRYPT_KEYSET_TYPE type;			/* Keyset type (native, PGP, X.509, etc) */
	KEYSET_SUBTYPE subType;			/* Keyset subtype (public, private, etc) */
	int accessMode;					/* Keyset access mode */
	BOOLEAN needsUpdate;			/* Whether the keyset has been updated */

	/* The I/O stream and type if the keyset is implemented as a file.  We
	   also remember the last known good position in the file in case we need
	   to retry an operation (for example rereading a private key if
	   decryption of encrypted fields fails) */
	FILE *filePtr;
	long filePos;					/* Last known good position in file */

	/* The username and password needed to access the database */
	char *user;
	char *password;

#ifdef __WINDOWS__
	/* ODBC access information */
	HENV hEnv;
	HDBC hDbc;
	HSTMT hStmt;
#endif /* __WINDOWS__ */

	/* A check value so we can determine whether the keyset context has been
	   initialised or not.  This is needed because passing in an
	   uninitialised block of memory as a keyset context can lead to problems
	   when we try to dereference wild pointers */
	LONG checkValue;

	/* The next and previous keyset context in the linked list of contexts */
	struct KI *next, *prev;
	} KEYSET_INFO;

/* Macros to convert to/from keyset contexts.  These are analogous to the
   encryption context macros in crypt.h */

#define KEYSET_TO_INFO( x )		( KEYSET_INFO * ) ( ( BYTE * ) x - cryptContextConversionOffset )
#define INFO_TO_KEYSET( x )		( CRYPT_KEYSET ) ( ( BYTE * ) x + cryptContextConversionOffset )

/****************************************************************************
*																			*
*				Memory Management Functions for Database Contexts			*
*																			*
****************************************************************************/

/* The linked list of key database contexts */

static KEYSET_INFO *keysetInfoListHead = NULL, *keysetInfoListTail;

/* Create a keyset context and add it to the list */

static int createKeysetContext( KEYSET_INFO **keysetInfo )
	{
	KEYSET_INFO *newElement;

	/* Allocate memory for the new keyset context */
	if( ( newElement  = malloc( sizeof( KEYSET_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( KEYSET_INFO ) );

	/* Link it into the list */
	if( keysetInfoListHead == NULL )
		keysetInfoListHead = newElement;
	else
		{
		keysetInfoListTail->next = newElement;
		newElement->prev = keysetInfoListTail;
		}
	keysetInfoListTail = newElement;

	*keysetInfo = newElement;
	return( CRYPT_OK );
	}

/* Delete a keyset context from the list */

static void deleteKeysetContext( KEYSET_INFO *keysetInfo )
	{
	KEYSET_INFO *keysetInfoPrevPtr = keysetInfo->prev, *keysetInfoNextPtr = keysetInfo->next;

	/* Remove the keyset context from the list of contexts */
	if( keysetInfo == keysetInfoListHead )
		{
		/* Special case for first keyset context */
		keysetInfoListHead = keysetInfoNextPtr;
		if( keysetInfoNextPtr != NULL )
			keysetInfoNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		keysetInfoPrevPtr->next = keysetInfoNextPtr;
		if( keysetInfoNextPtr != NULL )
			keysetInfoNextPtr->prev = keysetInfoPrevPtr;
		}

	/* If this was the last element, move the tail pointer back */
	if( keysetInfoListTail == keysetInfo )
		keysetInfoListTail = keysetInfoPrevPtr;

	/* Clear all data in the keyset context and free the memory */
	zeroise( keysetInfo, sizeof( KEYSET_INFO ) );
	free( keysetInfo );
	}

/* Delete all keyset contexts */

int deleteAllKeysetContexts( void )
	{
	KEYSET_INFO *keysetInfoListPtr = keysetInfoListHead;

	/* If there are no remaining allocated keyset contexts, return now */
	if( keysetInfoListPtr == NULL )
		return( CRYPT_OK );

	/* Destroy any remaining keyset contexts */
	while( keysetInfoListPtr != NULL )
		{
		KEYSET_INFO *keysetInfoToFree = keysetInfoListPtr;

		keysetInfoListPtr = keysetInfoListPtr->next;
		cryptKeysetClose( INFO_TO_KEYSET( keysetInfoToFree ) );
		}

	/* If there were keyset contexts still allocated, warn the user about
	   them */
	return( CRYPT_ORPHAN );
	}

/****************************************************************************
*																			*
*					System-specific Database Access Functions				*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Open a connection to a data source using ODBC.  We don't check the return
   codes for many of the functions since the worst that can happen is that
   performance will be somewhat suboptimal */

static int odbcOpen( KEYSET_INFO *keysetInfo, const char *server )
	{
	RETCODE retCode;

	/* Allocate environment and connection handles */
	SQLAllocEnv( &keysetInfo->hEnv );
	SQLAllocConnect( keysetInfo->hEnv, &keysetInfo->hDbc );

	/* Set the access mode to readonly if we can.  The default is R/W, but
	   setting it to readonly optimises transaction management.  We also
	   set cursor concurrency to readonly (which should be the default
	   anyway) */
	if( !( keysetInfo->accessMode & CRYPT_ACCESS_WRITE ) )
		{
		SQLSetConnectOption( keysetInfo->hDbc, SQL_ACCESS_MODE,
							 SQL_MODE_READ_ONLY );
		SQLSetConnectOption( keysetInfo->hDbc, SQL_CONCURRENCY,
							 SQL_CONCUR_READ_ONLY );
		}

	/* Set the cursor type to forward-only (which should be the default) */
	SQLSetConnectOption( keysetInfo->hDbc, SQL_CURSOR_TYPE,
						 SQL_CURSOR_FORWARD_ONLY );

	/* Turn off scanning for escape clauses in the SQL strings, which lets
	   the driver pass the string directly to the data source */
	SQLSetConnectOption( keysetInfo->hDbc, SQL_NOSCAN, SQL_NOSCAN_ON );

	/* Once everything is set up the way we want it, try to connect to a data
	   source and allocate a statement handle */
	retCode = SQLConnect( keysetInfo->hDbc, ( char * ) server, SQL_NTS,
						  keysetInfo->user, SQL_NTS,
						  keysetInfo->password, SQL_NTS );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		SQLFreeConnect( keysetInfo->hDbc );
		SQLFreeEnv( keysetInfo->hEnv );
		return( CRYPT_KEYSET_OPEN );
		}
	SQLAllocStmt( keysetInfo->hDbc, &keysetInfo->hStmt );

	return( CRYPT_OK );
	}

/* Close the previously-opened ODBC connection */

static int odbcClose( KEYSET_INFO *keysetInfo )
	{
	/* Commit the transaction (the default transaction mode for drivers which
	   support SQLSetConnectOption() is auto-commit so the SQLTransact() call
	   isn't strictly necessary, but we play it safe anyway) */
	if( keysetInfo->needsUpdate )
		SQLTransact( keysetInfo->hEnv, keysetInfo->hDbc, SQL_COMMIT );

	/* Clean up */
	SQLFreeStmt( keysetInfo->hStmt, SQL_DROP );
	SQLDisconnect( keysetInfo->hDbc );
	SQLFreeConnect( keysetInfo->hDbc );
	SQLFreeEnv( keysetInfo->hEnv );

	return( CRYPT_OK );
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*							Low-level Key Access Functions					*
*																			*
****************************************************************************/

/* Get a key from a keyset */

static int getKey( KEYSET_INFO *keysetInfoPtr, CRYPT_CONTEXT *cryptContext,
				   const GETKEY_INFO *getkeyInfo )
	{
	int status = CRYPT_OK;

	/* If we don't know what the key file type is, check it now.  This is
	   done when we get a key rather than when we open the keyset to avoid
	   unnecessary keyset accesses */
	if( keysetInfoPtr->subType == KEYSET_SUBTYPE_NONE )
		switch( keysetInfoPtr->type )
			{
			case CRYPT_KEYSET_NONE:
				/* The native format isn't supported yet */
				keysetInfoPtr->subType = KEYSET_SUBTYPE_ERROR;
				break;

			case CRYPT_KEYSET_PGP:
				keysetInfoPtr->subType = pgpGetKeysetType( keysetInfoPtr->filePtr );
				break;

			case CRYPT_KEYSET_X509:
				keysetInfoPtr->subType = x509GetKeysetType( keysetInfoPtr->filePtr );
				break;
			}
	if( keysetInfoPtr->subType == KEYSET_SUBTYPE_ERROR )
		return( CRYPT_BADDATA );

	/* Make sure we've got the right type of key file.  We can get a public
	   key from a private key file, but not a private key from a public key
	   file */
	if( !getkeyInfo->isPublicKey && \
		keysetInfoPtr->subType == KEYSET_SUBTYPE_PUBLIC )
		return( CRYPT_KEYSET_NOTFOUND );

	/* If it's a stream-type keyset, keep track of the position in the
	   stream */
	if( keysetInfoPtr->filePtr != NULL )
		{
		/* If we're doing a getFirst(), go back to the start of the file */
		if( getkeyInfo->keyID == CRYPT_KEYSET_GETFIRST )
			fseek( keysetInfoPtr->filePtr, 0L, SEEK_SET );

		/* Remember the last known good position */
		keysetInfoPtr->filePos = ftell( keysetInfoPtr->filePtr );
		}

	/* Get the key from the key collection */
	switch( keysetInfoPtr->type )
		{
		case CRYPT_KEYSET_NONE:
			/* The native format isn't supported yet */
			status = CRYPT_BADDATA;
			break;

		case CRYPT_KEYSET_PGP:
			status = pgpGetKey( keysetInfoPtr->filePtr, cryptContext,
								getkeyInfo );
			break;

		case CRYPT_KEYSET_X509:
			status = x509GetKey( keysetInfoPtr->filePtr, cryptContext,
								 getkeyInfo );
			break;

		default:
			/* Internal error, should never happen */
			status = CRYPT_ERROR;
		}

	/* If the problem was a failed decrypt of private-key fields, move back
	   to the last known good position */
	if( status == CRYPT_WRONGKEY && keysetInfoPtr->filePtr != NULL )
		fseek( keysetInfoPtr->filePtr, keysetInfoPtr->filePos, SEEK_SET );

	return( status );
	}

/* Set the names of the tables which contain key compoents */

int setKeysetNames( void *keySet,CRYPT_IOCTLINFO_KEYSETNAMES *ioctlInfo )
	{
	KEYSET_INFO *keysetInfoPtr = KEYSET_TO_INFO( keySet );

	UNUSED( keysetInfoPtr );
	UNUSED( ioctlInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Keyset API Functions						*
*																			*
****************************************************************************/

/* Open and close a keyset */

CRET cryptKeysetOpenEx( CRYPT_KEYSET CPTR keySet, const char CPTR name, \
						const int accessMode, const char CPTR user, \
						const char CPTR password )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status;

	/* Perform basic error checking */
	if( keySet == NULL )
		return( CRYPT_BADPARM1 );
	if( name == NULL )
		return( CRYPT_BADPARM2 );
	if( accessMode < 0 || \
		accessMode > ( CRYPT_ACCESS_READ | CRYPT_ACCESS_WRITE | CRYPT_ACCESS_CREATE ) )
		return( CRYPT_BADPARM3 );
	if( user == NULL )
		return( CRYPT_BADPARM4 );
	if( password == NULL )
		return( CRYPT_BADPARM5 );

	/* Create the keyset context */
	if( ( status = createKeysetContext( &keysetInfoPtr ) ) != CRYPT_OK )
		return( status );
	keysetInfoPtr->accessMode = accessMode;
	keysetInfoPtr->type = CRYPT_KEYSET_NONE;	/* Default internal format */

	/* Set up the user name and password if necessary */
	if( user != ( char * ) CRYPT_UNUSED )
		{
		if( ( keysetInfoPtr->user = malloc( strlen( user ) + 1 ) ) == NULL )
			{
			deleteKeysetContext( keysetInfoPtr );
			return( CRYPT_NOMEM );
			}
		strcpy( keysetInfoPtr->user, user );
		}
	if( password != ( char * ) CRYPT_UNUSED )
		{
		if( ( keysetInfoPtr->password = malloc( strlen( password ) + 1 ) ) == NULL )
			{
			deleteKeysetContext( keysetInfoPtr );
			return( CRYPT_NOMEM );
			}
		strcpy( keysetInfoPtr->password, password );
		}

#ifdef __WINDOWS__
	/* Try and establish the ODBC session */
	if( ( status = odbcOpen( keysetInfoPtr, name ) ) != CRYPT_OK )
		{
		deleteKeysetContext( keysetInfoPtr );
		return( status );
		}
#endif /* __WINDOWS__ */

	/* Set the check value */
	keysetInfoPtr->checkValue = CRYPT_MAGIC;

	/* Convert the keyset information pointer to a keyset context and return
	   it to the user */
	*keySet = INFO_TO_KEYSET( keysetInfoPtr );

	return( CRYPT_OK );
	}

CRET cryptKeysetClose( CRYPT_KEYSET keySet )
	{
	KEYSET_INFO *keysetInfoPtr = KEYSET_TO_INFO( keySet );

	/* Perform basic error checking */
	if( isBadCookie( keySet ) || keysetInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM1 );

	/* If the keyset is implemented as a file, close it */
	if( keysetInfoPtr->filePtr != NULL )
		fclose( keysetInfoPtr->filePtr );

	/* Clear the user name and password if necessary */
	if( keysetInfoPtr->user != NULL )
		{
		zeroise( keysetInfoPtr->user, strlen( keysetInfoPtr->user ) );
		free( keysetInfoPtr->user );
		}
	if( keysetInfoPtr->password != NULL )
		{
		zeroise( keysetInfoPtr->password, strlen( keysetInfoPtr->password ) );
		free( keysetInfoPtr->password );
		}

#ifdef __WINDOWS__
	/* Close down the ODBC session if necessary */
	if( keysetInfoPtr->hDbc )
		odbcClose( keysetInfoPtr );
#endif /* __WINDOWS__ */

	/* Delete the keyset context */
	deleteKeysetContext( keysetInfoPtr );

	return( CRYPT_OK );
	}

/* Open an external keyset */

CRET cryptExtKeysetOpen( CRYPT_KEYSET CPTR keySet, const char CPTR name,
						 const CRYPT_KEYSET_TYPE type )
	{
	KEYSET_INFO *keysetInfoPtr;
	FILE *filePtr;
	int status;

	/* Perform basic error checking */
	if( keySet == NULL )
		return( CRYPT_BADPARM1 );
	if( name == NULL )
		return( CRYPT_BADPARM2 );
	if( type <= CRYPT_KEYSET_NONE || type > CRYPT_KEYSET_LAST )
		return( CRYPT_BADPARM3 );

	/* Open the file containing the keyset */
	if( ( filePtr = fopen( name, "rb" ) ) == NULL )
		return( CRYPT_KEYSET_OPEN );

	/* Create the keyset context */
	if( ( status = createKeysetContext( &keysetInfoPtr ) ) != CRYPT_OK )
		{
		fclose( filePtr );
		return( status );
		}
	keysetInfoPtr->type = type;
	keysetInfoPtr->filePtr = filePtr;
	keysetInfoPtr->accessMode = CRYPT_ACCESS_READ;

	/* Set the check value */
	keysetInfoPtr->checkValue = CRYPT_MAGIC;

	/* Convert the keyset information pointer to a keyset context and return
	   it to the user */
	*keySet = INFO_TO_KEYSET( keysetInfoPtr );

	return( CRYPT_OK );
	}

/* Retrieve a key from a keyset based on a cryptlib object */

CRET cryptGetKeyFromObjectEx( CRYPT_KEYSET keySet, CRYPT_CONTEXT CPTR cryptContext,
							  const void CPTR object, const void CPTR password )
	{
	KEYSET_INFO *keysetInfoPtr = KEYSET_TO_INFO( keySet );
	CRYPT_OBJECT_INFO cryptObjectInfo;
	GETKEY_INFO getkeyInfo;
	int status;

	/* Perform basic error checking */
	if( isBadCookie( keySet ) || keysetInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM1 );
	if( cryptContext == NULL )
		return( CRYPT_BADPARM2 );
	if( object == NULL )
		return( CRYPT_BADPARM3 );
	*cryptContext = NULL;

	/* Make sure we've got a public-key object and determine the key ID */
	status = cryptQueryObject( object, &cryptObjectInfo );
	if( cryptStatusError( status ) || \
		( cryptObjectInfo.type != CRYPT_OBJECT_SIGNATURE && \
		  cryptObjectInfo.type != CRYPT_OBJECT_PKCENCRYPTED_KEY ) || \
		( cryptObjectInfo.type == CRYPT_OBJECT_PKCENCRYPTED_KEY && \
		  password == ( void * ) CRYPT_UNUSED ) )
		{
		zeroise( &cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) );
		return( CRYPT_BADPARM3 );
		}

	/* Get the key */
	memset( &getkeyInfo, 0, sizeof( GETKEY_INFO ) );
	getkeyInfo.keyID = cryptObjectInfo.keyID;
	getkeyInfo.keyIDsize = cryptObjectInfo.keyIDsize;
	getkeyInfo.isKeyID = TRUE;
	if( cryptObjectInfo.type == CRYPT_OBJECT_SIGNATURE )
		getkeyInfo.isPublicKey = TRUE;
	else
		if( password != NULL )
			{
			getkeyInfo.password = ( void * ) password;
			getkeyInfo.passwordSize = strlen( password );
			}
	status = getKey( keysetInfoPtr, cryptContext, &getkeyInfo );
	zeroise( &cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) );
	zeroise( &getkeyInfo, sizeof( GETKEY_INFO ) );
	return( status );
	}

/* Retrieve a key from a keyset based on a user ID */

CRET cryptGetKeyEx( CRYPT_KEYSET keySet, CRYPT_CONTEXT CPTR cryptContext,
					const void CPTR userID, const void CPTR password )
	{
	KEYSET_INFO *keysetInfoPtr = KEYSET_TO_INFO( keySet );
	GETKEY_INFO getkeyInfo;
	int status;

	/* Perform basic error checking */
	if( isBadCookie( keySet ) || keysetInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_BADPARM1 );
	if( cryptContext == NULL )
		return( CRYPT_BADPARM2 );
	if( userID == NULL )
		return( CRYPT_BADPARM3 );
	*cryptContext = NULL;

	/* Get the key */
	memset( &getkeyInfo, 0, sizeof( GETKEY_INFO ) );
	getkeyInfo.keyID = ( void * ) userID;
	if( userID != CRYPT_KEYSET_GETFIRST && userID != CRYPT_KEYSET_GETNEXT )
		getkeyInfo.keyIDsize = strlen( userID );
	if( password == ( void * ) CRYPT_UNUSED )
		getkeyInfo.isPublicKey = TRUE;
	else
		if( password != NULL )
			{
			getkeyInfo.password = ( void * ) password;
			getkeyInfo.passwordSize = strlen( password );
			}
	status = getKey( keysetInfoPtr, cryptContext, &getkeyInfo );
	zeroise( &getkeyInfo, sizeof( GETKEY_INFO ) );
	return( status );
	}
