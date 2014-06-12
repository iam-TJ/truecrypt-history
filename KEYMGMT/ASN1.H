/****************************************************************************
*																			*
*						  ASN.1 Constants and Structures					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#ifndef _ASN1_DEFINED

#define _ASN1_DEFINED

#include <time.h>
#if defined( INC_CHILD )|| defined( INC_ALL )
  #include "stream.h"
  #include "ber.h"
#else
  #include "keymgmt/stream.h"
  #include "keymgmt/ber.h"
#endif /* Compiler-specific includes */

/* Data structures and routines for handling ISO 8824:1990 ASN.1 data types.
   We use the types BOOLEAN (defined in "defs.h"), INTEGER, OCTET STRING,
   BITSTRING, ENUMERATION, NULL, and various constructed types such as OBJECT
   IDENTIFIER and SEQUENCE which are handled by the ASN.1 I/O routines.

   Each of the structures below act somewhat like a C++ object - their
   constructors must be called before use, and their destructors should
   be called after use.  In addition they can be queried as to their encoded
   size, and written to and read from disk.  The methods are:

   new<objectName>();		// Constructor
   delete<objectName>();	// Destructor
   assign<objectName>();	// Assign value to object
   sizeof<objectName>();	// Find encoded size of object
   read<objectName>();		// Read object
   read<objectName>Data();	// Read object's data
   write<objectName>();		// Write object

   The read() calls actually have two types, the read() form which reads
   the basic ASN.1 object type and checks the tag, and the more general
   readData() form which only reads the data contained in the ASN.1 object
   and doesn't read the tag.

   Finally, many of the data types are represented only indirectly, or don't
   have new/delete/assign methods.  This is because they are too general to
   be useful (for example the OCTET STRING code is never used, but there are
   two or three functions to read and write size-limited byte strings which
   are much more practical).

   Some ASN.1 structures are unused, either because they aren't needed or
   because they're impractical.  These are made conditional by the following
   define.  Uncommenting it will make these routines available for use (as
   well as increasing the total code size somewhat) */

/* #define STRICT_ASN1 */

/****************************************************************************
*																			*
*							Universal ASN.1 Structures						*
*																			*
****************************************************************************/

/* ASN.1 types.  These include dummy values for currently undefined types */

typedef enum {
	ASN1_TYPE_RESERVED, ASN1_TYPE_BOOLEAN, ASN1_TYPE_INTEGER,
	ASN1_TYPE_BITSTRING, ASN1_TYPE_OCTETSTRING, ASN1_TYPE_NULL,
	ASN1_TYPE_OBJECT_IDENTIFIER, ASN1_TYPE_OBJECT_DESCRIPTOR,
	ASN1_TYPE_EXTERNAL, ASN1_TYPE_REAL, ASN1_TYPE_ENUMERATED, ASN1_TYPE_11,
	ASN1_TYPE_12, ASN1_TYPE_13, ASN1_TYPE_14, ASN1_TYPE_15,
	ASN1_TYPE_SEQUENCE, ASN1_TYPE_SET, ASN1_TYPE_STRING_NUMERIC,
	ASN1_TYPE_STRING_PRINTABLE, ASN1_TYPE_STRING_T61,
	ASN1_TYPE_STRING_VIDEOTEX, ASN1_TYPE_STRING_IA5, ASN1_TYPE_TIME_UTC,
	ASN1_TYPE_TIME_GENERALIZED, ASN1_TYPE_STRING_GRAPHIC,
	ASN1_TYPE_STRING_ISO646, ASN1_TYPE_STRING_GENERAL, ASN1_TYPE_28,
	ASN1_TYPE_29, ASN1_TYPE_30
	} ASN1_TYPE;

/* The default value for tagged types.  If this value is given the basic
   type is used, otherwise the value is used as a context-specific tag */

#define DEFAULT_TAG			-1

/* The ASN.1 INTEGER type.  In most cases this will fit into a machine
   word, so we use a variant record which contains the integer in this
   form, but which can also store the value as an array of bytes, in little-
   endian format */

typedef struct {
	/* An integer value which will fit into a machine word */
	long shortInteger;

	/* A worst-case true ASN.1 integer value.  Precision is set to zero if
	   it'll fit into a longint */
	int precision;
	BYTE *longInteger;
	} INTEGER;

#ifdef STRICT_ASN1

/* The ASN.1 OCTET STRING type */

typedef struct {
	BYTE *string;				/* The octet string itself */
	int length;					/* The length of the string */
	} OCTETSTRING;

/* The ASN.1 OBJECT IDENTIFIER type */

typedef struct {
	int noFields;				/* Number of fields in object ID */
	int root;					/* ID of root node */
	int type;					/* ID of type */
	long ident;					/* Main identifier */
	long subIdent1, subIdent2, subIdent3;	/* Subidentifiers */
	} OBJECT_IDENTIFIER;

/* Values for object identifier root node and type */

enum { OBJECT_ID_CCITT, OBJECT_ID_ISO, OBJECT_ID_JOINT_ISO_CCITT };
enum { OBJECT_ID_STANDARD, OBJECT_ID_REGISTRATION_AUTHORITY,
	   OBJECT_ID_MEMBER_BODY, OBJECT_ID_IDENTIFIED_ORGANISATION };

/* The ASN.1 GENERALIZED TIME type */

typedef struct {
	int years, months, days;	/* Years, months, days */
	int hours, minutes, seconds;/* Hours, minutes, seconds */
	int fractional;				/* Fractional seconds */
	int timeDiff;				/* Offset from UTC time in hours */
	} GENERALIZED_TIME;

#endif /* STRICT_ASN1 */

/****************************************************************************
*																			*
*			Constants and Structures for Useful ASN.1 Data Types			*
*																			*
****************************************************************************/

/* The types of strings we may use */

typedef enum {
	/* String non-type (generally used for unknown string types */
	STRINGTYPE_NONE,		/* String non-type */

	/* Standard ASN.1 string types */
	STRINGTYPE_ISO646,		/* ISO 646/ASCII */
	STRINGTYPE_ISO10646,	/* ISO 10646/Unicode Level 5 compression */

	/* Single-byte ISO string types */
	STRINGTYPE_ISO8859_1,	/* ISO 8859-1/latin1, West European languages */
	STRINGTYPE_ISO8859_2,	/* ISO 8859-2/latin2, East European languages */
	STRINGTYPE_ISO8859_3,	/* ISO 8859-3/latin3, Other latin languages */
	STRINGTYPE_ISO8859_4,	/* ISO 8859-4/latin4, North European languages */
	STRINGTYPE_ISO8859_5,	/* ISO 8859-5 Cyrillic */
	STRINGTYPE_ISO8859_6,	/* ISO 8859-6 Arabic */
	STRINGTYPE_ISO8859_7,	/* ISO 8859-7 Greek */
	STRINGTYPE_ISO8859_8,	/* ISO 8859-8 Hebrew */
	STRINGTYPE_ISO8859_9,	/* ISO 8859-9/latin5, Latin 1 modification for Turkey */
	STRINGTYPE_ISO8859_10,	/* ISO 8859-10/latin6, Scandinvian languages */

	/* Single-byte non-ISO string types */
	STRINGTYPE_KOI8,		/* Russian KOI8 (Unix and derivatives) */
	STRINGTYPE_ALTKOI8,		/* Alternative KOI8/MSDOS CP866 */
	STRINGTYPE_MAZOVIA,		/* Polish Mazovia (preferred to 8859-2 in Poland */
	STRINGTYPE_EBCDIC,		/* IBM 037 EBCDIC (NB: Several EBCDIC types) */

	/* Multibyte nonstandard string types */
	STRINGTYPE_JIS,			/* Japanese JIS (NB: Several types. Use EUC-J??) */
	STRINGTYPE_SHIFT_JIS,	/* Japanese (Unix and PC) */
	STRINGTYPE_EUC_C,		/* Chinese (PRC). Guo-Biao (GB2312-80) is EUC-C codeset 1 */
	STRINGTYPE_EUC_H,		/* Han (Taiwanese). Big5 is EUC-H codeset 1 */
	STRINGTYPE_EUC_J,		/* Japanese (Unix) */
	STRINGTYPE_EUC_K,		/* Korean */

	/* Unicode/ISO10646 subtypes */
	STRINGTYPE_UTF_1,		/* UCS Translation Format 1: 1, 2, 3, 5 bytes/char */
	STRINGTYPE_UTF_2		/* UCS Translation Format 2: 1-6 bytes/char */
	} STRINGTYPE;

/* The types of currencies we may use */

typedef enum {
	/* Currency non-type (generally used for unknown currency types */
	CURRENCYTYPE_NONE,		/* Currency non-type */

	/* Common currencies */
	CURRENCYTYPE_USD		/* US dollars */
	} CURRENCYTYPE;

/* The ASN.1 GENERALIZED_STRING type.  This is much more useful than the
   strange and bizarre standard ASN.1 string types */

typedef struct {
	STRINGTYPE type;		/* The string type */
	int length;				/* Length of string */
	BYTE *string;			/* The string itself */
	} GENERALIZED_STRING;

/* The ASN.1 TIME type.  Again, this is preferred to the ISO 8601-compliant
   standard ASN.1 time type */

typedef struct {
	time_t seconds;			/* Seconds since 1970 */
	time_t fractional;		/* Fractional seconds */
	} TIME;

/* The ASN.1 MONETARY_AMOUNT type.  There is no ASN.1 type that this is
   better than */

typedef struct {
	CURRENCYTYPE currency;	/* Currency type */
	long units;				/* Currency units */
	long fractional;		/* Fractional currency seconds */
	} MONETARY_AMOUNT;

/****************************************************************************
*																			*
*							ASN.1 Function Prototypes						*
*																			*
****************************************************************************/

/* Routines to read and write the identifier information for an ASN.1 value.
   These are occasionally needed by higher-level routines to handle a stream
   of complex ASN.1 structures involving constructed and choice types */

int readLength( STREAM *stream, long *length );
void writeLength( STREAM *stream, long length );

/* Generalized ASN.1 type manipulation routines */

int readUniversalData( STREAM *stream );
int readUniversal( STREAM *stream );
long sizeofObject( const long length );

/* Routines for handling integers */

int newInteger( INTEGER *integer, const long value );
int deleteInteger( INTEGER *integer );
int assignInteger( INTEGER *integer, const long value );
int sizeofInteger( const INTEGER *integer );
int writeInteger( STREAM *stream, const INTEGER *integer, const int tag );
int _readInteger( STREAM *stream, INTEGER *integer, const BOOLEAN readIdent );

#define readInteger( stream,integer ) \
		_readInteger( stream, integer, TRUE )
#define readIntegerData( stream,integer )	\
		_readInteger( stream, integer, FALSE )

/* Generally most integers will be non-bignum values, so we also define
   routines to handle values which will fit into a machine word */

int sizeofShortInteger( const long integer );
int writeShortInteger( STREAM *stream, const long value, const int tag );
int _readShortInteger( STREAM *stream, long *value, const BOOLEAN readIdent );

#define readShortInteger( stream, integer ) \
		_readShortInteger( stream, integer, TRUE )
#define readShortIntegerData( stream, integer )	\
		_readShortInteger( stream, integer, FALSE )

/* Routines for handling enumerations */

int sizeofEnumerated( const int enumerated );
int writeEnumerated( STREAM *stream, const int enumerated, const int tag );
int _readEnumerated( STREAM *stream, int *enumeration, const BOOLEAN readIdent );

#define readEnumerated( stream, enumeration ) \
		_readEnumerated( stream, enumeration, TRUE )
#define readEnumeratedData( stream, enumeration ) \
		_readEnumerated( stream, enumeration, FALSE )

/* Routines for handling booleans */

#define sizeofBoolean()	( sizeof( BYTE ) + sizeof( BYTE ) )
int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag );
int _readBoolean( STREAM *stream, BOOLEAN *boolean, const BOOLEAN readIdent );

#define readBoolean( stream, boolean ) \
		_readBoolean( stream, boolean, TRUE )
#define readBooleanData( stream, boolean ) \
		_readBoolean( stream, boolean, FALSE )

/* Routines for handling null values */

#define sizeofNull()	( sizeof( BYTE ) + sizeof( BYTE ) + sizeof( BYTE ) )
int writeNull( STREAM *stream, const int tag );
int _readNull( STREAM *stream, BOOLEAN const readIdent );

#define readNull( stream )		_readNull( stream, TRUE )
#define readNullData( stream )	_readNull( stream, FALSE )

#ifdef STICT_ASN1

/* Routines for handling octet strings */

int newOctetString( OCTETSTRING *octetString, const BYTE *value, const int length );
int deleteOctetString( OCTETSTRING *octetString );
int assignOctetString( OCTETSTRING *octetString, const BYTE *value, const int length );
int sizeofOctetString( const OCTETSTRING *octetString );
int writeOctetString( STREAM *stream, const OCTETSTRING *octetString, const int tag );
int _readOctetString( STREAM *stream, OCTETSTRING *octetString, const BOOLEAN readIdent );

#define readOctetString( stream, octetString ) \
		_readOctetString( stream, octetString, TRUE )
#define readOctetStringData( stream, octetString ) \
		_readOctetString( stream, octetString, FALSE )

#endif /* STRICT_ASN1 */

/* Octet strings are basically just byte strings, and it's generally easier
   to write them as such rather than creating an octet string only to destroy
   it a few moments later */

int writeByteString( STREAM *stream, const BYTE *string, const int length, \
					 const int tag );

/* Routines for handling bit strings */

int sizeofBitString( const long bitString );
int writeBitString( STREAM *stream, const long bitString, const int tag );
int _readBitString( STREAM *stream, long *bitString, const BOOLEAN readIdent );

#define readBitString( stream, bitString ) \
		_readBitString( stream, bitString, TRUE )
#define readBitStringData( stream, bitString ) \
		_readBitString( stream, bitString, FALSE )

#ifdef STRICT_ASN1

/* Routines for handling ISO 646 strings */

int sizeofISO646string( const char *iso646string );
int writeISO646string( STREAM *stream, const char *iso646string, const int tag );
int _readISO646string( STREAM *stream, char *iso646string, const BOOLEAN readIdent );

#define readISO646string( stream, iso646string ) \
		_readISO747String( stream, iso646string, TRUE )
#define readISO646stringData( stream, iso646string ) \
		_readISO747String( stream, iso646string, FALSE )

/* Routines for handling object identifiers */

int sizeofObjectIdentifier( const OBJECT_IDENTIFIER *objectIdentifier );
int writeObjectIdentifier( STREAM *stream, const OBJECT_IDENTIFIER *objectIdentifier, int tag );
int _readObjectIdentifier( STREAM *stream, OBJECT_IDENTIFIER *objectIdentifier );

#define readObjectIdentifier( stream, objectIdentifier ) \
		_readObjectIdentifier( stream, objectIdentifier, TRUE )
#define readObjectIdentifierData( stream, objectIdentifier ) \
		_readObjectIdentifier( stream, objectIdentifier, FALSE )

/* Routines for handling generalized time */

int newGeneralizedTime( GENERALIZED_TIME *generalizedTime,
						 const int years, const int months, const int days,
						 const int hours, const int minutes, const int seconds );
int deleteGeneralizedTime( GENERALIZED_TIME *generalizedTime );
int assignGeneralizedTime( GENERALIZED_TIME *generalizedTime,
							const int years, const int months, const int days,
							const int hours, const int minutes, const int seconds );
int sizeofGeneralizedTime( const GENERALIZED_TIME *generalizedTime );
int writeGeneralizedTime( STREAM *stream, const GENERALIZED_TIME *generalizedTime, int tag );
int _readGeneralizedTime( STREAM *stream, GENERALIZED_TIME *generalizedTime, BOOLEAN readIdent );

#define readGeneralizedTime( stream, generalizedTime ) \
		_readGeneralizedTime( stream, generalizedTime, TRUE )
#define readGeneralizedTimeData( stream, generalizedTime ) \
		_readGeneralizedTime( stream, generalizedTime, FALSE )

#endif /* STRICT_ASN1 */

/* Routines for handling UTC time */

int writeUTCTime( STREAM *stream, const time_t time, const int tag );
int _readUTCTime( STREAM *stream, time_t *time, const BOOLEAN readIdent );

#define readUTCTime( stream, time )		_readUTCTime( stream, time, TRUE )
#define readUTCTimeData( stream, time )	_readUTCTime( stream, time, FALSE )

/* Routines for handling generalized strings */

int newGeneralizedString( GENERALIZED_STRING *generalizedString,
						  const STRINGTYPE type, const BYTE *string,
						  const int length );
int deleteGeneralizedString( GENERALIZED_STRING *generalizedString );
int assignGeneralizedString( GENERALIZED_STRING *generalizedString,
							 const STRINGTYPE type, const BYTE *string,
							 const int length );
int sizeofGeneralizedString( const GENERALIZED_STRING *generalizedString );
int writeGeneralizedString( STREAM *stream, const GENERALIZED_STRING *generalizedString,
							const int tag );
int _readGeneralizedString( STREAM *stream, GENERALIZED_STRING *generalizedString,
							const BOOLEAN readIdent );

#define readGeneralizedString( stream, generalizedString ) \
		_readGeneralizedString( stream, generalizedString, TRUE )
#define readGeneralizedStringData( stream, generalizedString ) \
		_readGeneralizedString( stream, generalizedString, FALSE )

/* Generally most strings will be ISO 646/ASCII, so we also define routines
   to handle ASCII strings */

int sizeofTextString( const char *string );
int writeTextString( STREAM *stream, const char *string, const int tag );

/* Macros to simplify things when we're working with ISO 646 generalized
   strings */

#define newString( string, value ) \
		newGeneralizedString( string, STRINGTYPE_ISO646, ( BYTE * ) value, strlen( value ) )
#define deleteString( string )	deleteGeneralizedString( string )
#define assignString( string, value ) \
		assignGeneralizedString( string, STRINGTYPE_ISO646, ( BYTE * ) value, strlen( value ) )
#define sizeofString( string )	sizeofGeneralizedString( string )
#define writeString( stream, string, tag ) \
		writeGeneralizedString( stream, string, tag )
#define readString( stream, string ) \
		readGeneralizedString( stream, string )
#define readStringData( stream, string ) \
		readGeneralizedStringData( stream, string )

/* Routines for handling time */

int newTime( TIME *time, const time_t seconds, const time_t fractional );
int deleteTime( TIME *time );
int assignTime( TIME *time, const time_t seconds, const time_t fractional );
int sizeofTime( const TIME *time );
int writeTime( STREAM *stream, const TIME *time, const int tag );
int _readTime( STREAM *stream, TIME *time, const BOOLEAN readIdent );

#define readTime( stream, time )		_readTime( stream, time, TRUE )
#define readTimeData( stream, time )	_readTime( stream, time, FALSE )

/* Routines for handling monetary amounts */

int newMonetaryAmount( MONETARY_AMOUNT *monetaryAmount,
					   const CURRENCYTYPE currency, const long units,
					   const long fractional );
int deleteMonetaryAmount( MONETARY_AMOUNT *monetaryAmount );
int assignMonetaryAmount( MONETARY_AMOUNT *monetaryAmount,
						  const CURRENCYTYPE currency, const long units,
						  const long fractional );
int sizeofMonetaryAmount( const MONETARY_AMOUNT *monetaryAmount );
int writeMonetaryAmount( STREAM *stream, const MONETARY_AMOUNT *monetaryAmount,
						 const int tag );
int _readMonetaryAmount( STREAM *stream, MONETARY_AMOUNT *monetaryAmount,
						 const BOOLEAN readIdent );

#define readMonetaryAmount( stream, monetaryAmount ) \
		_readMonetaryAmount( stream, monetaryAmount, TRUE )
#define readMonetaryAmountData( stream, monetaryAmount ) \
		_readMonetaryAmount( stream, monetaryAmount, FALSE )

#endif /* !_ASN1_DEFINED */
