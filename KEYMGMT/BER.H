/****************************************************************************
*																			*
*				ASN.1 Basic Encoding Rules Constants and Structures			*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#ifndef _BER_DEFINED

#define _BER_DEFINED

/* Definitions for the ISO 8825:1990 Basic Encoding Rules */

/* Tag class */

#define BER_UNIVERSAL			0x00
#define BER_APPLICATION			0x40
#define BER_CONTEXT_SPECIFIC	0x80
#define BER_PRIVATE				0xC0

/* Whether the encoding is constructed or primitive */

#define BER_CONSTRUCTED			0x20
#define BER_PRIMITIVE			0x00

/* The ID's for universal tag numbers 0-31.  Tag number 0 is reserved for
   encoding the end-of-contents value when an indefinite-length encoding
   is used */

enum { BER_ID_RESERVED, BER_ID_BOOLEAN, BER_ID_INTEGER, BER_ID_BITSTRING,
	   BER_ID_OCTETSTRING, BER_ID_NULL, BER_ID_OBJECT_IDENTIFIER,
	   BER_ID_OBJECT_DESCRIPTOR, BER_ID_EXTERNAL, BER_ID_REAL,
	   BER_ID_ENUMERATED, BER_EMBEDDED_PDV, BER_ID_12, BER_ID_13, BER_ID_14,
	   BER_ID_15, BER_ID_SEQUENCE, BER_ID_SET, BER_ID_STRING_NUMERIC,
	   BER_ID_STRING_PRINTABLE, BER_ID_STRING_T61, BER_ID_STRING_VIDEOTEX,
	   BER_ID_STRING_IA5, BER_ID_TIME_UTC, BER_ID_TIME_GENERALIZED,
	   BER_ID_STRING_GRAPHIC, BER_ID_STRING_ISO646, BER_ID_STRING_GENERAL,
	   BER_ID_STRING_UNIVERSAL, BER_ID_29, BER_ID_STRING_BMP };

/* The encodings for the universal types */

#define BER_RESERVED		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_RESERVED )
#define BER_BOOLEAN			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BOOLEAN )
#define BER_INTEGER			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_INTEGER )
#define BER_BITSTRING		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BITSTRING )
#define BER_OCTETSTRING		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OCTETSTRING )
#define BER_NULL			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_NULL )
#define BER_OBJECT_IDENTIFIER	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_IDENTIFIER )
#define BER_OBJECT_DESCRIPTOR	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_OBJECT_DESCRIPTOR )
#define BER_EXTERNAL		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EXTERNAL )
#define BER_REAL			( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_REAL )
#define BER_ENUMERATED		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_ENUMERATED )
#define BER_EMBEDDED_PDV	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_EMBEDDED_PDV )
#define BER_12				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_12 )
#define BER_13				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_13 )
#define BER_14				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_14 )
#define BER_15				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_15 )
#define BER_SEQUENCE		( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SEQUENCE )
#define BER_SET				( BER_UNIVERSAL | BER_CONSTRUCTED | BER_ID_SET )
#define BER_STRING_NUMERIC	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_NUMERIC )
#define BER_STRING_PRINTABLE	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_PRINTABLE )
#define BER_STRING_T61		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_T61 )
#define BER_STRING_VIDEOTEX	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_VIDEOTEX )
#define BER_STRING_IA5		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_IA5 )
#define BER_TIME_UTC		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_UTC )
#define BER_TIME_GENERALIZED	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_TIME_GENERALIZED )
#define BER_STRING_GRAPHIC	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GRAPHIC )
#define BER_STRING_ISO646	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_ISO646 )
#define BER_STRING_GENERAL	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_GENERAL )
#define BER_STRING_UNIVERSAL	( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_UNIVERSAL )
#define BER_29				( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_BER29 )
#define BER_STRING_BMP		( BER_UNIVERSAL | BER_PRIMITIVE | BER_ID_STRING_BMP )

/* ID's for application-specific tags */

enum { BER_APPL_ENCRYPTED_KEY, BER_APPL_PKCENCRYPTED_KEY, BER_APPL_SIGNATURE,
	   BER_APPL_ENCRYPTED_DATA, BER_APPL_COMPRESSED_DATA,
	   BER_APPL_SIGNED_DATA, BER_APPL_RAW_DATA, BER_APPL_NONDATA };

/* The encodings for the application-specific types */

#define BER_ENCRYPTED_KEY	( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_ENCRYPTED_KEY )
#define BER_PKCENCRYPTED_KEY ( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_PKCENCRYPTED_KEY )
#define BER_SIGNATURE		( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_SIGNATURE )
#define BER_ENCRYPTED_DATA	( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_ENCRYPTED_DATA )
#define BER_COMPRESSED_DATA	( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_COMPRESSED_DATA )
#define BER_SIGNED_DATA		( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_SIGNED_DATA )
#define BER_RAW_DATA		( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_RAW_DATA )
#define BER_NONDATA			( BER_APPLICATION | BER_CONSTRUCTED | BER_APPL_NONDATA )

/* Masks to extract information from a tag number */

#define BER_CLASS_MASK			0xC0
#define BER_CONSTRUCTED_MASK	0x20
#define BER_SHORT_ID_MASK		0x1F

/* The maximum size for the short tag number encoding, and the magic value
   which indicates that a long encoding of the number is being used */

#define MAX_SHORT_BER_ID	30
#define LONG_BER_ID			0x1F

/* A struct to store information about a tag */

typedef struct {
			   int class;				/* Tag class */
			   BOOLEAN constructed;		/* Constructed or primitive */
			   int identifier;			/* Tag type */
			   long length;				/* Tag length */
			   } BER_TAGINFO;

/* Macros to read and write primitive tags.  These translate directly to
   sgetc()/sputc(), but we use these macros instead to make it more obvious
   what's going on */

#define writeTag( stream, tag )	sputc( stream, tag )
#define readTag( stream )		sgetc( stream )

/* Helper routines needed by code performing low-level ASN.1 en/decoding
   operations.  These should only be used by libraries which handle ASN.1
   primitives, not called from user code */

void writeCtag( STREAM *stream, const int identifier,
			   const BOOLEAN isConstructed );
int checkReadTag( STREAM *stream, const int tag );
int checkReadCtag( STREAM *stream, const int identifier,
				   const BOOLEAN isConstructed );
int calculateLengthSize( const long length );
int readRawObject( STREAM *stream, BYTE *buffer, int *bufferLength,
				   const int maxLength, const int tag );
int readStaticInteger( STREAM *stream, BYTE *integer, int *integerLength,
					   const int maxLength );
int writeStaticInteger( STREAM *stream, const BYTE *integer,
						const int integerLength, const int tag );
int _readStaticOctetString( STREAM *stream, BYTE *string, int *stringLength,
							const int maxLength, const BOOLEAN readIdent );
int readStaticTextString( STREAM *stream, char *string, const int maxLength,
						  const BOOLEAN readIdent );

#define readStaticOctetString( stream, string, stringLength, maxLength ) \
		_readStaticOctetString( stream, string, stringLength, maxLength, TRUE )
#define readStaticOctetStringData( stream, string, stringLength, maxLength ) \
		_readStaticOctetString( stream, string, stringLength, maxLength, FALSE )

#define writeRawObject( stream, object, size ) \
		swrite( stream, object, size )
#endif /* !_BER_DEFINED */
