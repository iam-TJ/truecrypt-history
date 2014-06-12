/****************************************************************************
*																			*
*							  PGP Key Read Routines							*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keymgmt.h"
  #include "pgp_idea.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keymgmt.h"
  #include "pgp_idea.h"
#else
  #include "crypt.h"
  #include "keymgmt/keymgmt.h"
  #include "keymgmt/pgp_idea.h"
#endif /* Compiler-specific includes */

/* Magic numbers for PGP 2.x keyrings */

#define PGP_CTB_SIGNATURE	0x89	/* Signature CTB */
#define PGP_CTB_SECKEY		0x95	/* Secret key packet CTB */
#define PGP_CTB_PUBKEY		0x99	/* Public key packet CTB */
#define PGP_CTB_TRUST		0xB0	/* Trust packet CTB */
#define PGP_CTB_USERID		0xB4	/* Userid packet CTB */

#define PGP2_VERSION_BYTE	2		/* Version number byte for PGP 2.0 */
#define PGP3_VERSION_BYTE	3		/* Version number byte for PGP 3.0 or
									   legal-kludged 2.0 */

#define PKE_ALGORITHM_RSA	1		/* RSA public-key encryption algorithm */

#define CKE_ALGORITHM_NONE	0		/* No CKE algorithm */
#define CKE_ALGORITHM_IDEA	1		/* IDEA cipher */

/* The size of the IDEA IV and key */

#define IDEA_IV_SIZE		8
#define IDEA_KEY_SIZE		16

/* The maximum size of an MPI (4096 bits) */

#define MAX_MPI_SIZE		512

/* The maximum size of a user ID */

#define MAX_USERID_SIZE		256

/* Since the key components can consume a sizeable amount of memory, we
   allocate storage for them dynamically.  This also keeps them in one place
   for easy sanitization */

typedef struct {
	/* Key components (in PGP format) */
	BYTE n[ MAX_MPI_SIZE ], e[ MAX_MPI_SIZE ], d[ MAX_MPI_SIZE ];
	BYTE p[ MAX_MPI_SIZE ], q[ MAX_MPI_SIZE ], u[ MAX_MPI_SIZE ];
	int nLen, eLen, dLen, pLen, qLen, uLen;

	/* Key components (in cryptlib format) */
	CRYPT_PKCINFO_RSA rsaKey;

	/* userID for this key */
	char userID[ MAX_USERID_SIZE ];
	} PGP_INFO;

/* There are a few OS's broken enough not to define the standard seek codes
   (SunOS springs to mind) so we define them here if they're not defined */

#ifndef SEEK_SET
  #define SEEK_SET		0
  #define SEEK_CUR		1
  #define SEEK_END		2
#endif /* SEEK_SET */

/****************************************************************************
*																			*
*								Read Byte/Word/Long 						*
*																			*
****************************************************************************/

/* Routines to read BYTE, WORD, LONG */

static BYTE fgetByte( FILE *filePtr )
	{
	return( ( BYTE ) getc( filePtr ) );
	}

static WORD fgetWord( FILE *filePtr )
	{
	WORD value;

	value = ( ( WORD ) getc( filePtr ) ) << 8;
	value |= ( WORD ) getc( filePtr );
	return( value );
	}

static LONG fgetLong( FILE *filePtr )
	{
	LONG value;

	value = ( ( LONG ) getc( filePtr ) ) << 24;
	value |= ( ( LONG ) getc( filePtr ) ) << 16;
	value |= ( ( LONG ) getc( filePtr ) ) << 8;
	value |= ( LONG ) getc( filePtr );
	return( value );
	}

/****************************************************************************
*																			*
*							PGP Keyring Read Routines						*
*																			*
****************************************************************************/

/* Read an MPI, setting the global precision if necessary */

static int readMPI( FILE *filePtr, BYTE *mpReg, int *mpiLen )
	{
	BYTE *regPtr;
	int length;

	*mpiLen = fgetWord( filePtr );
	length = bitsToBytes( *mpiLen );
	if( length > MAX_MPI_SIZE )
		return( CRYPT_ERROR );
	regPtr = mpReg;
	while( length-- )
		*regPtr++ = fgetByte( filePtr );

	return( CRYPT_OK );
	}


/* Checksum a block of data */

static WORD checksum( BYTE *data, int length )
	{
	WORD checkSum = ( ( BYTE ) ( length >> 8 ) ) + ( ( BYTE ) length );

	length = bitsToBytes( length );
	while( length-- )
		checkSum += *data++;
	return( checkSum );
	}

/* Get the length of a packet based on the CTB length field */

static int getLength( FILE *filePtr, const int ctb )
	{
	switch( ctb & 3 )
		{
		case 0:
			return( ( int ) fgetByte( filePtr ) );

		case 1:
			return( fgetWord( filePtr ) );

		case 2:
			return( ( int ) fgetLong( filePtr ) );
		}

	/* Packet error, should never happen */
	return( 0 );
	}

/* Skip to the start of the next key packet */

static void skipToKeyPacket( FILE *filePtr )
	{
	int ctb;

	/* Skip any following non-key packets */
	while( ( ctb = fgetByte( filePtr ) ) != PGP_CTB_PUBKEY && \
		ctb != PGP_CTB_SECKEY && !feof( filePtr ) )
		{
		int length = getLength( filePtr, ctb );

		/* If we get an impossibly large packet, assume we're in trouble and
		   move to the end of the file to ensure we get an EOF if we try any
		   further reads */
		if( length > 5000 )
			fseek( filePtr, 0L, SEEK_END );
		else
			/* Skip the current packet */
			fseek( filePtr, ( long ) length, SEEK_CUR );
		}

	/* Finally, put back the last CTB we read unless we've reached the end
	   of the file */
	if( !feof( filePtr ) )
		ungetc( ctb, filePtr );
	}

/* Generate a cryptlib-style key ID for the PGP key and check it against the
   given key ID */

static BOOLEAN matchKeyID( PGP_INFO *pgpInfo, const BYTE *requiredID,
						   const int requiredIDsize )
	{
	CRYPT_PKCINFO_RSA *rsaKeyPtr = &pgpInfo->rsaKey;
	BYTE keyID[ CRYPT_MAX_KEYIDSIZE ];
	int keyIDsize, status;

	/* Generate the key ID */
	cryptInitComponents( rsaKeyPtr, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKeyPtr->n, pgpInfo->n, pgpInfo->nLen );
	cryptSetComponent( rsaKeyPtr->e, pgpInfo->e, pgpInfo->eLen );
	status = generateKeyID( CRYPT_ALGO_RSA, keyID, &keyIDsize, rsaKeyPtr );
	cryptDestroyComponents( rsaKeyPtr );

	/* Check if it's the same as the key ID we're looking for */
	if( status == CRYPT_OK && keyIDsize == requiredIDsize && \
		!memcmp( requiredID, keyID, keyIDsize ) )
		return( TRUE );

	return( FALSE );
	}

/* Read a key and check whether it matches the required user ID */

static int readKey( PGP_INFO *pgpInfo, FILE *filePtr,
					const GETKEY_INFO *getkeyInfo )
	{
	BOOLEAN isEncrypted, gotUserID = FALSE, foundKey = FALSE;
	WORD checkSum, packetChecksum;
	BYTE keyIV[ IDEA_IV_SIZE ];
	int ctb, length, i, packetLength, status = CRYPT_OK;

	/* Skip CTB, packet length, and version byte */
	if( ( ctb = fgetc( filePtr ) ) != PGP_CTB_PUBKEY && \
		ctb != PGP_CTB_SECKEY )
		return( feof( filePtr ) ? CRYPT_KEYSET_NOTFOUND : CRYPT_BADDATA );
	packetLength = getLength( filePtr, ctb );
	if( ( i = fgetByte( filePtr ) ) != PGP2_VERSION_BYTE && \
		i != PGP3_VERSION_BYTE )
		{
		/* Unknown version number, skip this packet */
		ungetc( i, filePtr );
		skipToKeyPacket( filePtr );
		return( -1000 );
		}
	packetLength -= sizeof( BYTE );

	/* Read timestamp, validity period */
	fgetLong( filePtr );
	fgetWord( filePtr );
	packetLength -= sizeof( LONG ) + sizeof( WORD );

	/* Read the public key components */
	if( ( i = fgetByte( filePtr ) ) != PKE_ALGORITHM_RSA )
		{
		/* Unknown PKE algorithm type, skip this packet */
		ungetc( i, filePtr );
		skipToKeyPacket( filePtr );
		return( -1000 );
		}
	if( readMPI( filePtr, pgpInfo->n, &pgpInfo->nLen ) == CRYPT_ERROR || \
		readMPI( filePtr, pgpInfo->e, &pgpInfo->eLen ) == CRYPT_ERROR )
		return( -1000 );
	packetLength -= sizeof( BYTE ) + sizeof( WORD ) + bitsToBytes( pgpInfo->nLen ) + \
									 sizeof( WORD ) + bitsToBytes( pgpInfo->eLen );

	/* If it's a private keyring, read in the private key components */
	if( !getkeyInfo->isPublicKey )
		{
		/* Handle decryption info for secret components if necessary */
		isEncrypted = ( ctb = fgetByte( filePtr ) ) == CKE_ALGORITHM_IDEA;
		if( isEncrypted )
			for( i = 0; i < IDEA_IV_SIZE; i++ )
				keyIV[ i ] = fgetc( filePtr );
		packetLength -= sizeof( BYTE ) + ( ( isEncrypted ) ? IDEA_IV_SIZE : 0 );

		/* Read in private key components and checksum */
		readMPI( filePtr, pgpInfo->d, &pgpInfo->dLen );
		readMPI( filePtr, pgpInfo->p, &pgpInfo->pLen );
		readMPI( filePtr, pgpInfo->q, &pgpInfo->qLen );
		readMPI( filePtr, pgpInfo->u, &pgpInfo->uLen );
		packetLength -= sizeof( WORD ) + bitsToBytes( pgpInfo->dLen ) + \
						sizeof( WORD ) + bitsToBytes( pgpInfo->pLen ) + \
						sizeof( WORD ) + bitsToBytes( pgpInfo->qLen ) + \
						sizeof( WORD ) + bitsToBytes( pgpInfo->uLen );
		packetChecksum = fgetWord( filePtr );
		packetLength -= sizeof( WORD );
		}

	/* If we're searching by key ID, check whether this is the packet we
	   want */
	if( getkeyInfo->isKeyID )
		if( matchKeyID( pgpInfo, getkeyInfo->keyID, getkeyInfo->keyIDsize ) )
			foundKey = TRUE;
		else
			{
			/* These aren't the keys you're looking for... you may go about
			   your business... move along, move along */
			skipToKeyPacket( filePtr );
			return( -1000 );
			}

	/* Read the userID packet(s).  We also make sure we get at least one
	   userID if we've already got a match based on a key ID */
	while( !foundKey || !gotUserID )
		{
		/* Skip keyring trust and signature packets */
		ctb = fgetByte( filePtr );
		while( ctb == PGP_CTB_TRUST || ctb == PGP_CTB_SIGNATURE )
			{
			/* Skip the packet */
			length = getLength( filePtr, ctb );
			fseek( filePtr, length, SEEK_CUR );
			ctb = fgetByte( filePtr );
			}

		/* Check if we've got a userID packet now */
		if( ctb != PGP_CTB_USERID )
			{
			ungetc( ctb, filePtr );

			/* If we saw at least one userID, everything was OK.  Before we
			   exit we move to the next key packet so we can continue looking
			   for keys if required */
			if( gotUserID )
				{
				skipToKeyPacket( filePtr );
				return( foundKey ? CRYPT_OK : -1000 );
				}

			/* We still don't have a userID CTB, complain */
			skipToKeyPacket( filePtr );
			return( -1000 );
			}
		length = getLength( filePtr, ctb );
		for( i = 0; i < length && i < MAX_USERID_SIZE; i++ )
			pgpInfo->userID[ i ] = fgetByte( filePtr );
		pgpInfo->userID[ i ] = '\0';
		while( i++ < length )
			fgetByte( filePtr );	/* Skip excessively long userID */
		gotUserID = TRUE;

		/* Check if it's the one we want */
		if( !getkeyInfo->isKeyID && \
			( getkeyInfo->keyID == CRYPT_KEYSET_GETFIRST || \
			  getkeyInfo->keyID == CRYPT_KEYSET_GETNEXT || \
			  matchSubstring( ( char * ) getkeyInfo->keyID, pgpInfo->userID ) ) )
			foundKey = TRUE;
		}

	/* Process the secret-key fields if necessary */
	if( !getkeyInfo->isPublicKey )
		{
		/* Decrypt the secret-key fields if necessary */
		if( isEncrypted )
			{
			struct IdeaCfbContext ideaContext;
#ifdef TEST
			MD5_CTX	mdContext;

			/* Reduce the passphrase to 128 bits */
			MD5Process( &mdContext, ( BYTE * ) password, strlen( password ) );

			/* Set up the IDEA key.  PGP does IV's in a funny way by treating
			   them as the first block to en/decrypt */
			ideaCfbInit( &ideaContext, mdContext.digest );
			ideaCfbDecrypt( &ideaContext, keyIV, keyIV, 8 );
			zeroise( &mdContext, 0, sizeof( MD5_CTX ) );

#else
			HASHFUNCTION hashFunction;
			BYTE ideaKey[ IDEA_KEY_SIZE ];
			int hashInfoSize, hashInputSize, hashOutputSize;

			/* If no password is supplied, let the caller know they need a
			   password */
			if( getkeyInfo->password == NULL )
				{
				skipToKeyPacket( filePtr );
				return( CRYPT_WRONGKEY );
				}

			/* Get the hash algorithm information and hash the password */
			if( !getHashParameters( CRYPT_ALGO_MD5, &hashFunction,
									&hashInputSize, &hashOutputSize,
									&hashInfoSize ) )
				return( CRYPT_ERROR );	/* API error, should never occur */
			hashFunction( NULL, ideaKey, getkeyInfo->password,
						  getkeyInfo->passwordSize, HASH_ALL );

			/* Set up the IDEA key.  PGP does IV's in a funny way by treating
			   them as the first block to en/decrypt */
			ideaCfbInit( &ideaContext, ideaKey );
			ideaCfbDecrypt( &ideaContext, keyIV, keyIV, 8 );
			zeroise( ideaKey, IDEA_KEY_SIZE );
#endif /* TEST */

			/* Decrypt the secret-key fields */
			ideaCfbDecrypt( &ideaContext, pgpInfo->d, pgpInfo->d,
							bitsToBytes( pgpInfo->dLen ) );
			ideaCfbDecrypt( &ideaContext, pgpInfo->p, pgpInfo->p,
							bitsToBytes( pgpInfo->pLen ) );
			ideaCfbDecrypt( &ideaContext, pgpInfo->q, pgpInfo->q,
							bitsToBytes( pgpInfo->qLen ) );
			ideaCfbDecrypt( &ideaContext, pgpInfo->u, pgpInfo->u,
							bitsToBytes( pgpInfo->uLen ) );
			ideaCfbDestroy( &ideaContext );
			}

		/* Make sure all was OK */
		checkSum = checksum( pgpInfo->d, pgpInfo->dLen );
		checkSum += checksum( pgpInfo->p, pgpInfo->pLen );
		checkSum += checksum( pgpInfo->q, pgpInfo->qLen );
		checkSum += checksum( pgpInfo->u, pgpInfo->uLen );
		if( checkSum != packetChecksum )
			status = isEncrypted ? CRYPT_WRONGKEY : CRYPT_BADDATA;
		}

	/* Move on to the next key packet so we can continue looking for keys if
	   required */
	skipToKeyPacket( filePtr );
	return( status );
	}

/* Get the subtype of the key file */

KEYSET_SUBTYPE pgpGetKeysetType( FILE *filePtr )
	{
	int ctb, type = KEYSET_SUBTYPE_ERROR, length;

	/* Try and establish the file type based on the initial CTB */
	ctb = fgetc( filePtr );
	if( ctb == PGP_CTB_PUBKEY )
		type = KEYSET_SUBTYPE_PUBLIC;
	if( ctb == PGP_CTB_SECKEY )
		type = KEYSET_SUBTYPE_PRIVATE;

	/* Perform a sanity check to make sure the rest looks like a PGP
	   keyring */
	length = getLength( filePtr, ctb );
	if( type == KEYSET_SUBTYPE_PUBLIC )
		{
		if( length < 64 || length > 1024  )
			type = KEYSET_SUBTYPE_ERROR;
		}
	else
		if( length < 200 || length > 4096 )
			type = KEYSET_SUBTYPE_ERROR;
	ctb = fgetByte( filePtr );
	if( ctb != PGP2_VERSION_BYTE && ctb != PGP3_VERSION_BYTE )
		type = KEYSET_SUBTYPE_ERROR;

	/* Move back to the start of the file */
	fseek( filePtr, 0L, SEEK_SET );

	return( type );
	}

/* Get a public or private key from a file and return it in an encryption
   context */

int pgpGetKey( FILE *filePtr, CRYPT_CONTEXT *cryptContext,
			   const GETKEY_INFO *getkeyInfo )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	CRYPT_INFO *cryptInfoPtr;
	PGP_INFO *pgpInfo;
	int status = CRYPT_OK;

	/* Allocate memory for the PGP key info.  This is somewhat messy
	   security-wise for private keys because we first read the PGP key
	   components into the pgpInfo structure, decrypt and unmangle them, and
	   then move them into the rsaInfo structure in preparation for loading
	   them into an encryption context, but there's no real way around this.
	   The memory is sanitised immediately after the transfer, so the
	   critical information is only held in one of the two structures at any
	   one time */
	if( ( pgpInfo = malloc( sizeof( PGP_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( pgpInfo, 0, sizeof( PGP_INFO ) );

	/* Get the key from the keyring */
	while( ( status = readKey( pgpInfo, filePtr, getkeyInfo ) ) == -1000 );
	if( cryptStatusError( status ) )
		goto endGetKey;

	/* Load the key into the encryption context */
	status = cryptCreateContext( cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		goto endGetKey;
	rsaKey = &pgpInfo->rsaKey;
	if( getkeyInfo->isPublicKey )
		{
		/* Set up the RSA public-key fields */
		cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN, \
							 CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		}
	else
		{
		/* Set up the RSA private-key fields */
		cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN, \
							 CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		cryptSetComponent( rsaKey->d, pgpInfo->d, pgpInfo->dLen );
		cryptSetComponent( rsaKey->p, pgpInfo->p, pgpInfo->pLen );
		cryptSetComponent( rsaKey->q, pgpInfo->q, pgpInfo->qLen );
		cryptSetComponent( rsaKey->u, pgpInfo->u, pgpInfo->uLen );
		}
	status = cryptLoadContext( *cryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );

	/* Store the userID in the encryption context as well in case we want to
	   later export the key to another type of keyset */
	if( cryptStatusOK( status ) )
		{
		cryptInfoPtr = CONTEXT_TO_INFO( *cryptContext );
		if( ( cryptInfoPtr->userID = ( char * ) \
					malloc( strlen( pgpInfo->userID + 1 ) ) ) == NULL )
			{
			cryptDestroyContext( *cryptContext );
			return( CRYPT_NOMEM );
			}
		strcpy( cryptInfoPtr->userID, pgpInfo->userID );
		}

	/* Clean up */
endGetKey:
	zeroise( pgpInfo, sizeof( PGP_INFO ) );
	free( pgpInfo );

	return( status );
	}
