/****************************************************************************
*																			*
*						   ASN.1 Core Library Routines						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
#endif /* Compiler-specific includes */

/* Limits of these routines (mainly for easy portability to all systems):

   Type identifiers are assumed to be less then 2^16, the lengths of a few
   other types (mainly constructed or otherwise complex types) are assumed to
   be less than 2^16.  This is mainly to allow easy use on systems with
   16-bit ints, and shouldn't be a serious problem.

   Encoding follows the Distinguished Encoding Rules.  Things like
   constructed encodings and alternate long forms aren't used.

   These routines include handling for a small number other useful types. */

/* Some ASN.1 structures are unused, either because they aren't needed or
   because they're impractical.  These are made conditional by the following
   define.  Uncommenting it will make these routines available for use (as
   well as increasing the total code size somewhat) */

/* #define STRICT_ASN1 */

/* The difference between the Unix and Julian epochs, in seconds */

#define EPOCH_DIFF	0x18A41200L		/* 0x3118A41200 or 210866803200 secs */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#ifdef STRICT_ASN1

/* Calculate the size of an encoded flagged value */

static int calculateFlaggedSize( const long value )
	{
	if( value >= 16384L )
		return( 3 );
	else
		if( value >= 128L )
			return( 2 );
		else
			return( 1 );
	}
#endif /* STRICT_ASN1 */

/* Calculate the size of the encoded length octets */

int calculateLengthSize( const long length )
	{
	if( length < 127 )
		/* Use short form of length octets */
		return( 1 );
	else
		/* Use long form of length octets: length-of-length followed by
		   32, 24, 16, or 8-bit length */
		return( 1 + ( ( length > 0xFFFFFFL ) ? 4 : \
					  ( length > 0xFFFF ) ? 3 : ( length > 0xFF ) ? 2 : 1 ) );
	}

/****************************************************************************
*																			*
*					Constructors/Destructors for ASN.1 Types				*
*																			*
****************************************************************************/

/* Initialise an integer to a given value, and destroy it afterwards */

int newInteger( INTEGER *integer, const long value )
	{
	/* Initialise long format fields */
	integer->precision = 0;
	integer->longInteger = NULL;

	/* Initialise short format fields */
	integer->shortInteger = value;
	return( CRYPT_OK );
	}

int deleteInteger( INTEGER *integer )
	{
	/* Free any storage used and zero fields */
	if( integer->longInteger != NULL )
		free( integer->longInteger );
	return( newInteger( integer, 0L ) );
	}

/* Assign a value to an integer */

int assignInteger( INTEGER *integer, const long value )
	{
	deleteInteger( integer );
	return( newInteger( integer, value ) );
	}

#ifdef STRICT_ASN1

/* Initialise an octet string to a given value, and destroy it afterwards */

int newOctetString( OCTETSTRING *octetString, const BYTE *value,
					const int length )
	{
	octetString->length = length;
	if( !length )
		/* No length, set string field to null value */
		octetString->string = NULL;
	else
		{
		/* Allocate room for data and initialise it */
		if( ( octetString->string = ( BYTE * ) malloc( length ) ) == NULL )
			return( CRYPT_ERROR );
		memcpy( octetString->string, value, length );
		}
	return( CRYPT_OK );
	}

int deleteOctetString( OCTETSTRING *octetString )
	{
	/* Free any storage used and zero fields */
	if( octetString->string != NULL )
		free( octetString->string );
	return( newOctetString( octetString, NULL, 0 ) );
	}

/* Assign a value to an octet string */

int assignOctetString( OCTETSTRING *octetString, const BYTE *value,
					   const int length )
	{
	deleteOctetString( octetString );
	return( newOctetString( octetString, value, length ) );
	}

/* Initialise a generalized time structure to a given value, and destroy it
   afterwards */

int newGeneralizedTime( GENERALIZED_TIME *generalizedTime,
						const int years, const int months, const int days,
						const int hours, const int minutes, const int seconds )
	{
	/* Set up main time fields */
	generalizedTime->years = years;
	generalizedTime->months = months;
	generalizedTime->days = days;
	generalizedTime->hours = hours;
	generalizedTime->minutes = minutes;
	generalizedTime->seconds = seconds;

	/* Fractional seconds are system-specific */
	generalizedTime->fractional = 0;

	/* Currently we don't have any time differential information */
	generalizedTime->timeDiff = 0;
	return( CRYPT_OK );
	}

int deleteGeneralizedTime( GENERALIZED_TIME *generalizedTime )
	{
	/* Zero fields */
	return( newGeneralizedTime( generalizedTime, 0, 0, 0, 0, 0, 0 ) );
	}

/* Assign a value to a generalized time structure */

int assignGeneralizedTime( GENERALIZED_TIME *generalizedTime,
						   const int years, const int months, const int days,
						   const int hours, const int minutes, const int seconds )
	{
	deleteGeneralizedTime( generalizedTime );
	return( newGeneralizedTime( generalizedTime, years, months, days,
								hours, minutes, seconds ) );
	}
#endif /* STRICT_ASN1 */

/* Initialise a generalized string string structure, and destroy it
   afterwards */

int newGeneralizedString( GENERALIZED_STRING *generalizedString,
						  const STRINGTYPE type, const BYTE *string,
						  const int length )
	{
	/* Set up general information */
	generalizedString->length = length;
	generalizedString->type = type;

	if( !length )
		/* No length, set string field to null value */
		generalizedString->string = NULL;
	else
		{
		/* Allocate room for data and initialise it, adding a null terminator
		   for those routines which expect one */
		if( ( generalizedString->string = ( BYTE * ) malloc( length + 1 ) ) == NULL )
			return( CRYPT_ERROR );
		memcpy( generalizedString->string, string, length );
		generalizedString->string[ length ] = '\0';
		}
	return( CRYPT_OK );
	}

int deleteGeneralizedString( GENERALIZED_STRING *generalizedString )
	{
	/* Free any storage used and zero fields */
	if( generalizedString->string != NULL )
		free( generalizedString->string );
	return( newGeneralizedString( generalizedString, STRINGTYPE_NONE, NULL, 0 ) );
	}

/* Assign a value to a generalized string */

int assignGeneralizedString( GENERALIZED_STRING *generalizedString,
							 const STRINGTYPE type, const BYTE *string,
							 const int length )
	{
	deleteGeneralizedString( generalizedString );
	return( newGeneralizedString( generalizedString, type, string, length ) );
	}

/* Initialise a time structure to a given value, and destroy it afterwards */

int newTime( TIME *time, const time_t seconds, const time_t fractional )
	{
	/* Set up time fields */
	time->seconds = seconds;
	time->fractional = fractional;
	return( CRYPT_OK );
	}

int deleteTime( TIME *time )
	{
	/* Zero fields */
	return( newTime( time, 0L, 0L ) );
	}

/* Assign a value to a time structure */

int assignTime( TIME *time, const time_t seconds, const time_t fractional )
	{
	deleteTime( time );
	return( newTime( time, seconds, fractional ) );
	}

/* Initialise a monetary amount structure to a given value, and destroy it
   afterwards */

int newMonetaryAmount( MONETARY_AMOUNT *monetaryAmount,
					   const CURRENCYTYPE currency, const long units,
					   const long fractional )
	{
	/* Set up monetary amount fields */
	monetaryAmount->currency = currency;
	monetaryAmount->units = units;
	monetaryAmount->fractional = fractional;
	return( CRYPT_OK );
	}

int deleteMonetaryAmount( MONETARY_AMOUNT *monetaryAmount )
	{
	/* Zero fields */
	return( newMonetaryAmount( monetaryAmount, CURRENCYTYPE_NONE, 0L, 0L ) );
	}

/* Assign a value to a monetary amount structure */

int assignMonetaryAmount( MONETARY_AMOUNT *monetaryAmount,
						  const CURRENCYTYPE currency, const long units,
						  const long fractional )
	{
	deleteMonetaryAmount( monetaryAmount );
	return( newMonetaryAmount( monetaryAmount, currency, units, fractional ) );
	}

/****************************************************************************
*																			*
*						sizeof() methods for ASN.1 Types					*
*																			*
****************************************************************************/

/* Determine the encoded size of an object given only a length.  This can be
   used for a number of simple objects and avoids having to create an object
   only to destroy it after a single call to a sizeof() routine */

long sizeofObject( const long length )
	{
	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( length ) + length );
	}

/* Determine the encoded size of an integer value */

int sizeofInteger( const INTEGER *integer )
	{
	int size;

	if( !integer->precision )
		/* It's stored internally as a signed short value */
		size = ( integer->shortInteger < 128 ) ? 1 :
			   ( integer->shortInteger < 32768L ) ? 2 :
			   ( integer->shortInteger < 8388608L ) ? 3 :
			   ( integer->shortInteger < 2147483648UL ) ? 4 : 5;
	else
		/* It's stored internally as a little-endian long value */
		size = integer->precision;

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of a short integer value.  This saves having
   to create an integer type just to pass it to sizeofInteger() */

int sizeofShortInteger( const long value )
	{
	INTEGER integer;
	int size;

	/* Create an integer to hold the numeric value, find it's size, and
	   delete it.  The encoding is the same as that of an integer */
	newInteger( &integer, ( long ) value );
	size = sizeofInteger( &integer );
	deleteInteger( &integer );
	return( size );
	}

/* Determine the encoded size of an enumerated value.  This is encoded as an
   integer so we just create an integer for it and calculate its value */

int sizeofEnumerated( const int enumerated )
	{
	return( sizeofShortInteger( enumerated ) );
	}

#ifdef STRICT_ASN1

/* Determine the encoded size of an octet string */

int sizeofOctetString( const OCTETSTRING *octetString )
	{
	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( octetString->length ) +
			octetString->length );
	}
#endif /* STRICT_ASN1 */

/* Determine the encoded size of a bitstring */

int sizeofBitString( const long bitString )
	{
	int size = ( bitString > 65535L ) ? 3 : ( bitString > 256 ) ? 2 : 1;

	/* Return the total encoded size (the extra byte is for the bitcount
	   mod 8) */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + 1 + size );
	}

#ifdef STRICT_ASN1

/* Determine the encoded size of an ISO 646 string */

int sizeofISO646string( const char *iso646string )
	{
	int size = strlen( iso646string );

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of an object identifier */

int sizeofObjectIdentifier( const OBJECT_IDENTIFIER *objectIdentifier )
	{
	int size = sizeof( BYTE ) + calculateFlaggedSize( objectIdentifier->ident );

	/* Calculate the size of the optional fields */
	if( objectIdentifier->noFields > 3 )
		size += calculateFlaggedSize( objectIdentifier->subIdent1 );
	if( objectIdentifier->noFields > 4 )
		size += calculateFlaggedSize( objectIdentifier->subIdent2 );
	if( objectIdentifier->noFields > 5 )
		size += calculateFlaggedSize( objectIdentifier->subIdent3 );

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of a generalized time value */

int sizeofGeneralizedTime( const GENERALIZED_TIME *generalizedTime )
	{
	char buffer[ 10 ];
	int size = 14;			/* Size of fixed-size fields */

	/* Add the fractional seconds field if there is one present */
	if( generalizedTime->fractional )
		size += sprintf( buffer, ".%d", generalizedTime->fractional );

	/* Add the time differential if there is one */
	if( generalizedTime->timeDiff )
		size += 5;			/* '+' + 4-digit hour difference */

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}
#endif /* STRICT_ASN1 */

/* Determine the encoded size of a generalizedString value */

int sizeofGeneralizedString( const GENERALIZED_STRING *generalizedString )
	{
	int size;

	/* It's a composite type.  Evaluate the size of the enumerated value
	   needed to encode the string type and the octet string needed to
	   encode the string itself */
	size = sizeofEnumerated( generalizedString->type ) +
		   ( int ) sizeofObject( generalizedString->length );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of an ASCII string value.  This saves having
   to create a generalizedString type just to pass it to
   sizeofGeneralizedString() */

int sizeofTextString( const char *string )
	{
	int size = sizeofEnumerated( STRINGTYPE_ISO646 ) +
			   ( int ) sizeofObject( strlen( string ) );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of a time value */

int sizeofTime( const TIME *time )
	{
	int size = 2 + 5;	/* Size of fixed-size fields for 5-byte INTEGER */

	if( time->fractional )
		{
		INTEGER integer;

		/* Calculate size of fractional component.  It's actually a context-
		   specific tagged type, but the encoded size is the same as an
		   integer */
		newInteger( &integer, time->fractional );
		size += sizeofInteger( &integer );
		deleteInteger( &integer );
		}

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Determine the encoded size of a monetary amount value */

int sizeofMonetaryAmount( const MONETARY_AMOUNT *monetaryAmount )
	{
	int size;

	/* It's a composite type.  Evaluate the size of the enumerated value
	   needed to encode the currency and the integer and optional fractional
	   component needed to encode the monetary amount */
	size = sizeofEnumerated( monetaryAmount->currency );
	size += sizeofShortInteger( monetaryAmount->units );
	if( monetaryAmount->fractional )
		/* Calculate size of fractional component.  It's actually a context-
		   specific tagged type, but the encoded size is the same as an
		   integer */
		size += sizeofShortInteger( monetaryAmount->fractional );

	/* Return the total encoded size */
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/****************************************************************************
*																			*
*							ASN.1 Output Routines							*
*																			*
****************************************************************************/

/* Write a value in 7-bit flagged format */

static void writeFlagged( STREAM *stream, const long value )
	{
	long flaggedValue = value;
	BOOLEAN hasHighBits = FALSE;

	/* Write the high octets (if necessary) with flag bits set, followed by
	   the final octet */
	if( flaggedValue >= 16384L )
		{
		sputc( stream, ( BYTE ) ( 0x80 | ( flaggedValue >> 14 ) ) );
		flaggedValue -= 16384L;
		hasHighBits = TRUE;
		}
	if( ( flaggedValue > 128L ) || hasHighBits )
		{
		sputc( stream, ( BYTE ) ( 0x80 | ( flaggedValue >> 7 ) ) );
		flaggedValue -= 128L;
		}
	sputc( stream, ( BYTE ) flaggedValue );
	}

#ifdef STRICT_ASN1

/* Write the identifier octets for an ASN.1 data type */

void writeIdentifier( STREAM *stream, const int class,
					  const BOOLEAN isConstructed, const int identifier )
	{
	int constructed = ( isConstructed ) ? BER_CONSTRUCTED : 0;

	/* Check if we can write it as a short encoding of the type */
	if( identifier <= MAX_SHORT_BER_ID )
		sputc( stream, ( BYTE ) ( class | constructed | identifier ) );
	else
		{
		/* Write it as a long encoding */
		sputc( stream, ( BYTE ) ( class | constructed | LONG_BER_ID ) );

		/* Write the identifier as a flagged value */
		writeFlagged( stream, identifier );
		}
	}
#endif /* STRICT_ASN1 */

/* Write a context-specific tag */

void writeCtag( STREAM *stream, const int identifier,
				const BOOLEAN isConstructed )
	{
	int constructed = ( isConstructed ) ? BER_CONSTRUCTED : 0;

	/* Check if we can write it as a short encoding of the type */
	if( identifier <= MAX_SHORT_BER_ID )
		sputc( stream, ( BYTE ) ( BER_CONTEXT_SPECIFIC | constructed | \
								  identifier ) );
	else
		{
		/* Write it as a long encoding */
		sputc( stream, ( BYTE ) ( BER_CONTEXT_SPECIFIC | constructed | \
								  LONG_BER_ID ) );

		/* Write the identifier as a flagged value */
		writeFlagged( stream, identifier );
		}
	}

/* Write the length octets for an ASN.1 data type */

void writeLength( STREAM *stream, long length )
	{
	/* Check if we can use the short form of length octets */
	if( length < 127 )
		sputc( stream, ( BYTE ) length );
	else
		{
		int noLengthOctets = ( length > 0xFFFFFFL ) ? 4 : \
							 ( length > 0xFFFFL ) ? 3 : \
							 ( length > 0xFF ) ? 2 : 1;

		/* Write number of length octets */
		sputc( stream, ( BYTE ) ( 0x80 | noLengthOctets ) );

		/* Write the length octets themselves */
		if( length > 0xFFFFFFL )
			{
			sputc( stream, ( BYTE ) ( length >> 24 ) );
			length &= 0xFFFFFFL;
			}
		if( length > 0xFFFFL )
			{
			sputc( stream, ( BYTE ) ( length >> 16 ) );
			length &= 0xFFFFL;
			}
		if( length > 0xFF )
			{
			sputc( stream, ( BYTE ) ( length >> 8 ) );
			length &= 0xFF;
			}
		sputc( stream, ( BYTE ) length );
		}
	}

/* Write a (non-bignum) numeric value - used by several routines */

static void writeNumeric( STREAM *stream, const long integer )
	{
	BOOLEAN needsLZ = TRUE;
	BYTE buffer[ 5 ];
	int length = 0, i;

	/* Determine the number of bytes necessary to encode the integer and
	   encode it into a temporary buffer */
	if( integer < 0 )
		buffer[ length++ ] = 0;
	if( integer > 0x00FFFFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 24 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00800000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x0000FFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 16 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00008000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x000000FFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 8 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00000080L && needsLZ )
		buffer[ length++ ] = 0;
	buffer[ length++ ] = ( BYTE ) integer;

	/* Write the length and integer */
	writeLength( stream, length );
	for( i = 0; i < length; i++ )
		sputc( stream, buffer[ i ] );
	zeroise( buffer, sizeof( buffer ) );
	}

/* Write an integer */

int writeInteger( STREAM *stream, const INTEGER *integer, const int tag )
	{
	/* Write the identifier field */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_INTEGER );
	else
		writeCtag( stream, tag, FALSE );

	/* Check if it's stored internally as a short value */
	if( !integer->precision )
		writeNumeric( stream, integer->shortInteger );
	else
		{
		/* Write it as a big-endian long value */
		writeLength( stream, integer->precision );
		swrite( stream, integer->longInteger, integer->precision );
		}
	return( sGetStatus( stream ) );
	}

/* Write a short integer value */

int writeShortInteger( STREAM *stream, const long integer, const int tag )
	{
	/* Write the identifier and numeric fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_INTEGER );
	else
		writeCtag( stream, tag, FALSE );
	writeNumeric( stream, integer );
	return( sGetStatus( stream ) );
	}

/* Write a bignum integer value */

int writeStaticInteger( STREAM *stream, const BYTE *integer,
						const int integerLength, const int tag )
	{
	/* Write the identifier field */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_INTEGER );
	else
		writeCtag( stream, tag, FALSE );

	/* Write it as a big-endian long value */
	writeLength( stream, integerLength );
	swrite( stream, integer, integerLength );

	return( sGetStatus( stream ) );
	}

/* Write an enumerated value */

int writeEnumerated( STREAM *stream, const int enumerated, const int tag )
	{
	/* Write the identifier and numeric fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_ENUMERATED );
	else
		writeCtag( stream, tag, FALSE );
	writeNumeric( stream, ( long ) enumerated );
	return( sGetStatus( stream ) );
	}

/* Write a null value */

int writeNull( STREAM *stream, const int tag )
	{
	/* Write the identifier and null length octet */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_NULL );
	else
		writeCtag( stream, tag, FALSE );
	sputc( stream, 0 );
	return( sGetStatus( stream ) );
	}

/* Write a boolean value.  Note that we always encode TRUE as 1 and FALSE
   as 0 even though the BER state that TRUE can be any nonzero value */

int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag )
	{
	/* Write the identifier and boolean value */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_BOOLEAN );
	else
		writeCtag( stream, tag, FALSE );
	sputc( stream, 1 );								/* Length is one byte */
	sputc( stream, ( BYTE ) ( boolean ? 1 : 0 ) );	/* Write TRUE or FALSE */
	return( sGetStatus( stream ) );
	}

#ifdef STRICT_ASN1

/* Write an octet string */

int writeOctetString( STREAM *stream, const OCTETSTRING *octetString,
					  const int tag )
	{
	/* Write the identifier and string fields */
    if( tag == DEFAULT_TAG )
		writeTag( stream, BER_OCTETSTRING );
	else
		writeCtag( stream, tag, FALSE );
	writeLength( stream, octetString->length );
	swrite( stream, octetString->string, octetString->length );
	return( sGetStatus( stream ) );
	}
#endif /* STRICT_ASN1 */

/* Write a byte string.  This saves having to create an octet string just
   to write a block of bytes */

int writeByteString( STREAM *stream, const BYTE *string, const int length,
					 const int tag )
	{
	/* Write the identifier and string fields */
    if( tag == DEFAULT_TAG )
		writeTag( stream, BER_OCTETSTRING );
	else
		writeCtag( stream, tag, FALSE );
	writeLength( stream, length );
	swrite( stream, string, length );
	return( sGetStatus( stream ) );
	}

/* Write a bit string */

int writeBitString( STREAM *stream, const long bitString, const int tag )
	{
	int octetLength = ( bitString > 0xFFFFFFL ) ? 4 : \
					  ( bitString > 0xFFFFL ) ? 3 : \
					  ( bitString > 0xFF ) ? 2 : 1;

	/* Write the identifier and length (string length in octets + extra octet
	   for remaining bits).  Since we always work in octets to make things
	   easier to handle, the bit remainder count is always 0 (all unused data
	   bits are set to 0) */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_BITSTRING );
	else
		writeCtag( stream, tag, FALSE );
	writeLength( stream, octetLength + 1 );
	sputc( stream, 0 );			/* Write bit remainder octet */

	/* Write the bit string itself */
	if( bitString > 0xFFFFFFL )
		sputc( stream, ( BYTE ) ( bitString >> 24 ) );
	if( bitString > 0xFFFFL )
		sputc( stream, ( BYTE ) ( bitString >> 16 ) );
	if( bitString > 0xFF )
		sputc( stream, ( BYTE ) ( bitString >> 8 ) );
	sputc( stream, ( BYTE ) bitString );
	return( sGetStatus( stream ) );
	}

#ifdef STRICT_ASN1

/* Write an ISO 646 string */

int writeISO646string( STREAM *stream, const char *iso646string,
						const int tag )
	{
	/* Write the identifier and string fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_STRING_ISO646 );
	else
		writeCtag( stream, tag, FALSE );
	writeLength( stream, isi646tring->length );
	swrite( stream, iso646tring->string, iso646tring->length );
	return( sGetStatus( stream ) );
	}

/* Write an object identifier */

int writeObjectIdentifier( STREAM *stream, const OBJECT_IDENTIFIER *objectIdentifier,
							const int tag )
	{
	int length = sizeof( BYTE ) + calculateFlaggedSize( objectIdentifier->ident );

	/* Write the identifier and length fields.  The root, type, and ident
	   fields are always present, the rest are optional.  The first two are
	   encoded as one byte, the remaining values are variable - length and
	   their size must be determined at runtime */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_OBJECT_IDENTIFIER );
	else
		writeCtag( stream, tag, FALSE );
	if( objectIdentifier->noFields > 3 )
		length += calculateFlaggedSize( objectIdentifier->subIdent1 );
	if( objectIdentifier->noFields > 4 )
		length += calculateFlaggedSize( objectIdentifier->subIdent2 );
	if( objectIdentifier->noFields > 5 )
		length += calculateFlaggedSize( objectIdentifier->subIdent3 );
	writeLength( stream, length );

	/* Write the object identifier */
	writeFlagged( stream, ( objectIdentifier->root * 40 ) + objectIdentifier->type );
	writeFlagged( stream, objectIdentifier->ident );
	if( objectIdentifier->noFields > 3 )
		writeFlagged( stream, objectIdentifier->subIdent1 );
	if( objectIdentifier->noFields > 4 )
		writeFlagged( stream, objectIdentifier->subIdent2 );
	if( objectIdentifier->noFields > 5 )
		writeFlagged( stream, objectIdentifier->subIdent3 );
	}

/* Write a generalized time value */

int writeGeneralizedTime( STREAM *stream, const GENERALIZED_TIME *generalizedTime,
						   const int tag )
	{
	char buffer[ 40 ];
	int count;

	/* Print the main time fields */
	count = sprintf( buffer, "%04d%02d%02d%02d%02d%02d", generalizedTime->years,
					 generalizedTime->months, generalizedTime->days,
					 generalizedTime->hours, generalizedTime->minutes,
					 generalizedTime->seconds );

	/* Add the fractional seconds field if there is one present */
	if( generalizedTime->fractional )
		count += sprintf( buffer + count, ".%d", generalizedTime->fractional );

	/* Add the time differential if there is one */
	if( generalizedTime->timeDiff )
		count += sprintf( buffer + count, "+%02d00", generalizedTime->timeDiff );

	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_TIME_GENERALIZED );
	else
		writeCtag( stream, tag, FALSE );
	writeLength( stream, count );

	/* Write the time string */
	swrite( stream, ( BYTE * ) buffer, count );
	}
#endif /* STRICT_ASN1 */

/* Write a generalized string value */

int writeGeneralizedString( STREAM *stream, const GENERALIZED_STRING *generalizedString,
							 const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, sizeofEnumerated( generalizedString->type ) +
						 ( int ) sizeofObject( generalizedString->length ) );

	/* It's a composite type.  Write the enumeration which encodes the string
	   type, followed by the data as an octet string */
	writeEnumerated( stream, generalizedString->type, DEFAULT_TAG );
	writeByteString( stream, generalizedString->string,
					 generalizedString->length, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Generalized strings are often just ISO 646/ASCII strings, so we use the
   following special-case routine to write these simple string values to save
   having to create a generalizedString just to write it out */

int writeTextString( STREAM *stream, const char *string, const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, sizeofEnumerated( STRINGTYPE_ISO646 ) +
				 ( int ) sizeofObject( strlen( string ) ) );

	/* It's a composite type.  Write the enumeration which encodes the string
	   type, followed by the data as an octet string */
	writeEnumerated( stream, STRINGTYPE_ISO646, DEFAULT_TAG );
	writeByteString( stream, ( BYTE * ) string, strlen( string ), DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Write a time value */

int writeTime( STREAM *stream, const TIME *time, const int tag )
	{
	time_t seconds = time->seconds + EPOCH_DIFF;

	/* Write the identifier field */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag, TRUE );

	/* Calculate the length and write it.  The seconds field is (for all
	   intents and purposes) always 2 bytes for the integer encoding + 5 bytes
	   for the payload (it's + 4 bytes before 4576BCE and + 6 bytes after
	   34,865AD) */
	writeLength( stream, 2 + 5 + ( ( time->fractional ) ? \
								   sizeofShortInteger( time->fractional ) : 0 ) );

	/* Write seconds component */
	writeTag( stream, BER_INTEGER );
	writeLength( stream, 5 );
	sputc( stream, 0x31 );		/* Write MSB of time in seconds */
	sputc( stream, ( BYTE ) ( seconds >> 24 ) );
	sputc( stream, ( BYTE ) ( seconds >> 16 ) );
	sputc( stream, ( BYTE ) ( seconds >> 8 ) );
	sputc( stream, ( BYTE ) seconds );

	/* Write fractional component */
	if( time->fractional )
		writeShortInteger( stream, time->fractional, DEFAULT_TAG );
	return( sGetStatus( stream ) );
	}

#if 0

/* Write a monetary amount value */

int writeMonetaryAmount( STREAM *stream, const MONETARY_AMOUNT *monetaryAmount,
						  const int tag )
	{
	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_MONETARY_AMOUNT );
	else
		writeCtag( stream, tag, TRUE );
	writeLength( stream, sizeofEnumerated( monetaryAmount->currency ) +
				 sizeofShortInteger( monetaryAmount->units ) +
				 sizeofShortInteger( monetaryAmount->fractional ) );

	/* It's a composite type.  Write the enumeration which encodes the
	   currency type, followed by the data as an integer and optional second
	   integer */
	writeEnumerated( stream, monetaryAmount->currency, DEFAULT_TAG );
	writeShortInteger( stream, monetaryAmount->units, DEFAULT_TAG );
	if( monetaryAmount->fractional )
		writeShortInteger( stream, monetaryAmount->fractional, 0 );

	return( sGetStatus( stream ) );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							ASN.1 Input Routines							*
*																			*
****************************************************************************/

/* Read a value in 7-bit flagged format */

static int readFlagged( STREAM *stream, long *flaggedValue )
	{
	long value = 0L;
	int readDataLength = 1, count = 4;
	BYTE data;

	/* Read the high octets (if any) with flag bits set, followed by
	   the final octet */
	data = sgetc( stream );
	while( count-- && ( data & 0x80 ) )
		{
		int ch;

		value <<= 7;
		value |= data & 0x7F;
		ch = sgetc( stream );
		if( ch == STREAM_EMPTY || ch == STREAM_READ )
			return( CRYPT_ERROR );
		data = ch;
		readDataLength++;
		}
	*flaggedValue = value | data;
	if( count <= 0 )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}

	return( readDataLength );
	}

/* Read the identifier octets for an ASN.1 data type */

int readIdentifier( STREAM *stream, BER_TAGINFO *tagInfo )
	{
	BYTE data;
	int readDataLength = 1;

	data = sgetc( stream );
	tagInfo->class = data & BER_CLASS_MASK;
	tagInfo->constructed = ( data & BER_CONSTRUCTED_MASK ) ? TRUE : FALSE;
	if( ( data & BER_SHORT_ID_MASK ) != LONG_BER_ID )
		/* ID is encoded in short form */
		tagInfo->identifier = data & BER_SHORT_ID_MASK;
	else
		{
		/* ID is encoded in long form */
		long value;

		readDataLength += readFlagged( stream, &value );
		tagInfo->identifier = ( int ) value;
		}
	tagInfo->length = 0;

	return( readDataLength );
	}

/* Undo a read for when we're looking ahead for a certain tagged type */

int unreadTag( STREAM *stream )
	{
	/* This code isn't very general-purpose in that it assumes that the tag
	   will fit into a single octet.  However since we're only going to use
	   this to undo lookahead for context-specific tags of optional types,
	   this should be safe */
	sungetc( stream );
	return( 1 );
	}

/* Read and check the type of a tag */

int checkReadTag( STREAM *stream, const int tag )
	{
	/* Read the start of the fixed sequence of fields */
	if( readTag( stream ) != tag )
		{
		unreadTag( stream );
		return( 0 );
		}
	return( 1 );
	}

/* Read and check the type of a context-specific tag */

int checkReadCtag( STREAM *stream, const int identifier,
				   const BOOLEAN isConstructed )
	{
	BER_TAGINFO tagInfo;
	int readDataLength;

	/* Read the start of the fixed sequence of fields */
	readDataLength = readIdentifier( stream, &tagInfo );
	if( tagInfo.class != BER_CONTEXT_SPECIFIC || \
		tagInfo.constructed != isConstructed ||
		tagInfo.identifier != identifier )
		{
		unreadTag( stream );
		return( 0 );
		}
	return( readDataLength );
	}

/* Read the length octets for an ASN.1 data type */

int readLength( STREAM *stream, long *length )
	{
	int readDataLength = 1;
	BYTE data;

	data = sgetc( stream );
	if( !( data & 0x80 ) )
		/* Data is encoded in short form */
		*length = ( long ) data;
	else
		{
		/* Data is encoded in long form.  First get the octet count */
		int noLengthOctets = data & 0x7F;
		long localLength = 0;

		/* Now read the length octets themselves */
		while( noLengthOctets-- > 0 )	/* Terminates after max.127 iterations */
			{
			localLength <<= 8;
			localLength |= ( unsigned int ) sgetc( stream );
			readDataLength++;
			}
		*length = localLength;
		}

	return( readDataLength );
	}

/* Read a short (< 128 bytes) raw object without decoding it.  This is used
   to read short data blocks like object identifiers which are only ever
   handled in encoded form */

int readRawObject( STREAM *stream, BYTE *buffer, int *bufferLength,
				   const int maxLength, const int tag )
	{
	int readDataLength = 2, remainder = 0, length, status;

	/* Read the identifier field and length.  Since we need to remember each
	   byte as it is read we can't just call readLength() for the length,
	   but since we only need to handle lengths which can be encoded in a
	   single byte this isn't much of a problem */
	if( readTag( stream ) != tag )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}
	length = sgetc( stream );
	if( length & 0x80 )
		{
		/* If the object is longer than 127 bytes, we can't handle it */
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}
	buffer[ 0 ] = tag;
	buffer[ 1 ] = length;

	/* Read in the object, limiting the size to the maximum buffer size */
	if( length > maxLength - 2 )
		{
		remainder = ( int ) length - ( maxLength - 2 );
		length = maxLength - 2;
		}
	sread( stream, buffer + 2, ( int ) length );
	*bufferLength = ( int ) length;

	/* Read in any remaining data if necessary */
	if( remainder > 0 && \
		( status = sSkip( stream, remainder ) ) != STREAM_OK )
		return( status );

	return( readDataLength + ( int ) length );
	}

/* Read a numeric value - used by several routines */

static int readNumeric( STREAM *stream, INTEGER *integer )
	{
	int readDataLength;
	long length;

	/* Read the length field */
	readDataLength = readLength( stream, &length );
	readDataLength += ( int ) length;

	/* Check if it's a short value */
	if( length <= sizeof( long ) )
		{
		integer->precision = 0;
		integer->shortInteger = 0L;
		while( length-- > 0 )	/* Terminates after sizeof( long ) iterations */
			{
			integer->shortInteger <<= 8;
			integer->shortInteger |= sgetc( stream );
			}
		}
	else
		{
		int status;

		/* Read it in as a long value.  First, allocate the room for it */
		if( integer->longInteger != NULL )
			free( integer->longInteger );
		if( ( integer->longInteger = ( BYTE * ) malloc( ( size_t ) length ) ) == NULL )
			return( CRYPT_ERROR );

		/* Now read it in as a big-endian value */
		integer->precision = ( int ) length;
		status = sread( stream, integer->longInteger, ( int ) length );
		if( status != STREAM_OK )
			return( status );
		}

	return( readDataLength );
	}

/* Read an integer value into a static buffer - used by internal routines */

int readStaticInteger( STREAM *stream, BYTE *integer, int *integerLength,
					   const int maxLength )
	{
	int readDataLength = 1, remainder = 0, status;
	long length;

	/* Read the identifier field */
	if( readTag( stream ) != BER_INTEGER )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}

	/* Read the length field */
	readDataLength += readLength( stream, &length );
	readDataLength += ( int ) length;
	*integerLength = ( int ) length;

	/* Now read in the numeric value, limiting the size to the maximum buffer
	   size */
	if( length > maxLength )
		{
		remainder = ( int ) length - maxLength;
		length = maxLength;
		}
	if( ( status = sread( stream, integer, ( int ) length ) ) != STREAM_OK )
		return( status );

	/* Read in any remaining data */
	if( ( status = sSkip( stream, remainder ) ) != STREAM_OK )
		return( status );
	return( readDataLength );
	}

/* Read a string value - used by several routines */

int readStringValue( STREAM *stream, BYTE **string, int *stringLength )
	{
	int readDataLength;
	long length;

	/* Read the string length */
	readDataLength = readLength( stream, &length );
	*stringLength = ( int ) length;

	/* Read the string itself.  First allocate the room for it */
	if( *string != NULL )
		free( *string );
	if( ( *string = ( BYTE * ) malloc( ( size_t ) length + 1 ) ) == NULL )
		return( CRYPT_ERROR );

	/* Now read it in, adding a null terminator for those routines which
	   need it */
	sread( stream, *string, ( int ) length );
	( *string )[ ( int ) length ] = '\0';

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + ( int ) length );
	}

/* Read an octet string value into a static buffer - used by internal routines */

int _readStaticOctetString( STREAM *stream, BYTE *string, int *stringLength,
							const int maxLength, const BOOLEAN readIdent )
	{
	int readDataLength = 0, remainder = 0, status;
	long length;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_OCTETSTRING )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Now read in the string, limiting the size to the maximum buffer size */
	readDataLength += readLength( stream, &length );
	if( length > maxLength )
		{
		remainder = ( int ) length - maxLength;
		length = maxLength;
		}
	sread( stream, string, ( int ) length );
	*stringLength = ( int ) length;

	/* Read in any remaining data */
	if( ( status = sSkip( stream, remainder ) ) != STREAM_OK )
		return( status );
	return( readDataLength + ( int ) length );
	}

/* Read an ISO 646/ASCII string value into a static buffer - used by internal
   routines */

int readStaticTextString( STREAM *stream, char *string, const int maxLength,
						  const BOOLEAN readIdent )
	{
	int dataLength, readDataLength = 0, status;
	long length;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}
	readDataLength += readLength( stream, &length );	/* Skip SEQUENCE length info */
	readDataLength += readEnumerated( stream, &status );
	if( status != STRINGTYPE_ISO646 )
		{
		/* If it's not an ISO 646 string, we shouldn't be using a
		   textString function to read it */
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}
	readDataLength += readStaticOctetString( stream, ( BYTE * ) string,
											 &dataLength, maxLength - 1 );
	string[ dataLength ] = '\0';

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a universal type and discard it (used to skip unknown or unwanted
   types) */

int readUniversalData( STREAM *stream )
	{
	long length;
	int readDataLength = readLength( stream, &length ), status;

	readDataLength += ( int ) length;
	if( ( status = sSkip( stream, ( int ) length ) ) != STREAM_OK )
		return( status );
	return( readDataLength );
	}

int readUniversal( STREAM *stream )
	{
	readTag( stream );
	return( readUniversalData( stream ) + 1 );
	}

/* Read an integer */

int _readInteger( STREAM *stream, INTEGER *integer, const BOOLEAN readIdent )
	{
	int readDataLength = 0;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_INTEGER )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the numeric field */
	readDataLength += readNumeric( stream, integer );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a short integer value */

int _readShortInteger( STREAM *stream, long *value, const BOOLEAN readIdent )
	{
	INTEGER integer;
	int readDataLength;

	/* Create an integer to hold the numeric value */
	newInteger( &integer, 0L );

	/* Read the numeric field and extract the integer value */
	readDataLength = _readInteger( stream, &integer, readIdent );
	*value = integer.shortInteger;

	/* Delete the created integer */
	deleteInteger( &integer );

	if( integer.precision )
		{
		/* If we're expecting a short integer and get a bignum, something has
		   gone wrong */
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}
	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read an enumerated value.  This is encoded as an integer so we just
   create an integer for it and read it as such */

int _readEnumerated( STREAM *stream, int *enumeration, const BOOLEAN readIdent )
	{
	INTEGER integer;
	int readDataLength = 0;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_ENUMERATED )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Create an integer to hold the numeric value */
	newInteger( &integer, 0L );

	/* Read the numeric field and extract the enumerated type */
	readDataLength += readNumeric( stream, &integer );
	*enumeration = ( int ) integer.shortInteger;

	/* Delete the created integer */
	deleteInteger( &integer );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a null value */

int _readNull( STREAM *stream, const BOOLEAN readIdent )
	{
	int readDataLength = 0;

	/* Read the identifier if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_NULL )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Skip length octet */
	sgetc( stream );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + 1 );
	}

/* Read a boolean value */

int _readBoolean( STREAM *stream, BOOLEAN *boolean, const BOOLEAN readIdent )
	{
	int readDataLength = 0;

	/* Read the identifier if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_BOOLEAN )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Skip length octet and read boolean value */
	sgetc( stream  );
	*boolean = sgetc( stream ) ? TRUE : FALSE;

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + 2 );
	}

#ifdef STRICT_ASN1

/* Read an octet string */

int _readOctetString( STREAM *stream, OCTETSTRING *octetString,
					  const BOOLEAN readIdent )
	{
	int readDataLength = 0;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_OCTETSTRING )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the string field */
	readDataLength += readStringValue( stream, &octetString->string,
									   &octetString->length );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}
#endif /* STRICT_ASN1 */

/* Read a bit string */

int _readBitString( STREAM *stream, long *bitString, const BOOLEAN readIdent )
	{
	int readDataLength = 0, byteCount;
	long length, bitValue = 0;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_BITSTRING )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the length field (string length in octets + extra octet for
	   remaining bits) */
	readDataLength += readLength( stream, &length ) + 1;
	length--;						/* Don't count length of extra octet */
	byteCount = sgetc( stream );	/* Read remainder bits */
	if( length > 4 )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_BADDATA );
		}

	/* Read the bit string itself */
	for( byteCount = 0; byteCount < length; byteCount++ )
		bitValue = ( bitValue << 8 ) | sgetc( stream );
	*bitString = bitValue;
	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + ( int ) length );
	}

#ifdef STRICT_ASN1

/* Read an ISO 646 string */

int _readISO646string( STREAM *stream, char *iso646string,
					   const BOOLEAN readIdent )
	{
	int readDataLength = 0, dummy;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_STRING_ISO646 )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the string fields */
	readDataLength += readStringValue( stream, ( ( BYTE ** ) &iso646string ), &dummy );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read an object identifier */

int _readObjectIdentifier( STREAM *stream, OBJECT_IDENTIFIER *objectIdentifier, BOOLEAN readIdent )
	{
	long value;
	int data, readDataLength = 0;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_OBJECT_IDENTIFIER )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the length fields.  The length field is one shorter than the
	   in-memory value since the first two values are encoded as one */
	readDataLength = readLength( stream, &objectIdentifier->noFields );
	objectIdentifier->noFields++;

	/* Read the identifier itself */
	readDataLength += readFlagged( stream, &value );
	data = ( int ) value;
	objectIdentifier->root = data / 40;
	objectIdentifier->type = data % 40;
	length += readFlagged( stream, &value);
	objectIdentifier->ident = value;
	if( objectIdentifier->noFields > 3 )
		{
		readDataLength += readFlagged( stream, &value );
		objectIdentifier->subIdent1 = value;
		}
	if( objectIdentifier->noFields > 4 )
		{
		readDataLength += readFlagged( stream, &value );
		objectIdentifier->subIdent2 = value;
		}
	if( objectIdentifier->noFields > 5 )
		{
		readDataLength += readFlagged( stream, &value );
		objectIdentifier->subIdent3 = value;
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}
/* Read a generalized time value */

int _readGeneralizedTime( STREAM *stream, GENERALIZED_TIME *generalizedTime, BOOLEAN readIdent )
	{
	char buffer[ 40 ];
	int length, readDataLength = 0, index;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_GENERALIZED_TIME )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the length field */
	readDataLength = readLength( stream, &length );

	/* Read the time string itself into memory */
	sread( stream, ( BYTE * ) buffer, length );

	/* Read the main time fields */
	sscanf( buffer, "%04d%02d%02d%02d%02d%02d", &generalizedTime->years,
			&generalizedTime->months, &generalizedTime->days,
			&generalizedTime->hours, &generalizedTime->minutes,
			&generalizedTime->seconds );
	index = 14;		/* Size of main time field */

	/* Read the fractional seconds field if there is one present */
	if( buffer[ index ] == '.' )
		{
		sscanf( buffer + index + 1, "%d", &generalizedTime->fractional );
		index++;		/* Skip dit */
		while( index < length && isalpha( buffer[ index ] ) )
			index++;	/* Skip to end of fractional field */
		}

	/* Read the time differential if there is one */
	if( buffer[ index ] == '-' || buffer[ index ] == '+' )
		sscanf( buffer + index + 1, "%02d", &generalizedTime->timeDiff );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + length );
	}
#endif /* STRICT_ASN1 */

/* Read a UTC time value */

static int getDigits( STREAM *stream )
	{
	int result, ch = sgetc( stream );

	if( isdigit( ch ) )
		{
		result = ( ch - '0' ) * 10;
		ch = sgetc( stream );
		if( isdigit( ch ) )
			return( result + ( ch - '0' ) );
		}

	return( -1 );
	}

int _readUTCTime( STREAM *stream, time_t *time, const BOOLEAN readIdent )
	{
	int readDataLength = 0, status = CRYPT_OK;
	struct tm utcTime;
	long length;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_TIME_UTC )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the length field and make sure it's of the correct size */
	readDataLength = readLength( stream, &length );
	if( length < 11 || length > 17 )
		{
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}

	/* Decode the time fields.  Ideally we should use sscanf(), but there
	   are too many dodgy versions of this around */
	memset( &utcTime, 0, sizeof( struct tm ) );
	utcTime.tm_year = getDigits( stream );
	utcTime.tm_mon = getDigits( stream ) - 1;
	utcTime.tm_mday = getDigits( stream );
	utcTime.tm_hour = getDigits( stream );
	utcTime.tm_min = getDigits( stream );
	length -= 10;

	/* Read any extra fields if necessary */
	if( length )
		{
		int ch = sgetc( stream );

		/* Read the seconds field if there is one present */
		if( length >= 2 && isdigit( ch ) )
			{
			sungetc( stream );
			utcTime.tm_sec = getDigits( stream );
			length -= 2;
			if( length )
				ch = sgetc( stream );
			}

		/* Read the time differential if there is one.  Since the differential
		   is given as the difference between GMT and the local time, the sign
		   of the amount to add is the opposite of the differential sign (eg
		   GMT-0500 means add 5 hours to get GMT) */
		if( length == 5 && ( ch == '-' || ch == '+' ) )
			{
			int sign = ( ch == '-' ) ? 1 : -1;
			int hourOffset, minuteOffset;

			hourOffset = getDigits( stream );
			minuteOffset = getDigits( stream );
			if( ( minuteOffset | hourOffset ) == -1 )
				status = CRYPT_ERROR;
			utcTime.tm_hour += hourOffset * sign;
			utcTime.tm_min += minuteOffset * sign;
			}
		else
			/* If there's anything left, the data format is wrong */
			if( length && !( length == 1 && ch == 'Z' ) )
				status = CRYPT_ERROR;
		}

	/* Make sure there were no format errors */
	if( ( utcTime.tm_year | utcTime.tm_mon | utcTime.tm_mon | \
		  utcTime.tm_mday | utcTime.tm_hour | utcTime.tm_min | \
		  utcTime.tm_sec ) == -1 )
		status = CRYPT_ERROR;

	/* Finally, convert it to the local time.  Since the UTCTime doesn't
	   take centuries into account (and you'd think that when the ISO came up
	   with the worlds least efficient time encoding format they could have
	   spared another two bytes to fully specify the year), we adjust by one
	   century for years < 80, and hope there aren't any Y2K bugs in
	   mktime().

		"The time is out of joint; o cursed spite,
		 That ever I was born to set it right"	- Shakespeare,
												  "Hamlet" */
	if( utcTime.tm_year < 80 )
		utcTime.tm_year += 100;
	if( status == CRYPT_OK )
		{
		time_t theTime = mktime( &utcTime );

		if( theTime == -1 )
			status = CRYPT_ERROR;
		else
			*time = mktime( localtime( &theTime ) );
		}
	if( status == CRYPT_ERROR )
		{
		*time = 0;
		sSetError( stream, STREAM_BADDATA );
		return( CRYPT_ERROR );
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + ( int ) length );
	}

/* Read a generalized string value */

int _readGeneralizedString( STREAM *stream, GENERALIZED_STRING *generalizedString,
							const BOOLEAN readIdent )
	{
	BER_TAGINFO tagInfo;
	int readDataLength = 0;
	long dummy;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read type and string data components */
	readDataLength += readLength( stream, &dummy );	/* Skip SEQUENCE length info */
	readDataLength += readEnumerated( stream, ( int * ) &generalizedString->type );
	readDataLength += readIdentifier( stream, &tagInfo );	/* Skip OCTET STRING tag */
	readDataLength += readStringValue( stream, &generalizedString->string,
									   &generalizedString->length );

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a time value */

int _readTime( STREAM *stream, TIME *time, const BOOLEAN readIdent )
	{
	int tagLength = 0, readDataLength = 0;
	BER_TAGINFO tagInfo;
	long length, totalLength;
	time_t timeStamp;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read the length field */
	readDataLength = readLength( stream, &totalLength );
	tagLength += readDataLength;

	/* Read seconds component.  Because this is outside the range of time_t
	   on most systems we can't use readInteger.  Instead we skip the first
	   octet and treat the remainder as a time_t */
	readDataLength += readIdentifier( stream, &tagInfo );
	readDataLength += readLength( stream, &length );
	readDataLength += ( int ) length;
	sgetc( stream );	/* Skip billions of seconds */
	timeStamp = ( time_t ) sgetc( stream ) << 24;
	timeStamp |= ( time_t ) sgetc( stream ) << 16;
	timeStamp |= ( time_t ) sgetc( stream ) << 8;
	timeStamp |= ( time_t ) sgetc( stream );
	timeStamp -= EPOCH_DIFF;
	time->seconds = timeStamp;

	/* Read optional fractional component */
	if( totalLength - readDataLength > 0 )
		{
		long integer;

		readShortInteger( stream, &integer );
		time->fractional = ( time_t ) integer;
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( tagLength + ( int ) totalLength );
	}

#if 0

/* Read a monetary amount value */

int _readMonetaryAmount( STREAM *stream, MONETARY_AMOUNT *monetaryAmount,
						 const BOOLEAN readIdent )
	{
	int readDataLength = 0, totalLength;

	/* Read the identifier field if necessary */
	if( readIdent )
		{
		if( readTag( stream ) != BER_MONETARY_AMOUNT )
			{
			sSetError( stream, STREAM_BADDATA );
			return( CRYPT_ERROR );
			}
		readDataLength++;
		}

	/* Read type and units components */
	readDataLength += readLength( stream, &totalLength );
	readDataLength += readEnumerated( stream, ( int * ) &monetaryAmount->currency );
	readDataLength += readShortInteger( stream, &monetaryAmount->units );

	/* Read optional fractional component */
	if( totalLength - readDataLength > 0 )
		{
		INTEGER fractional;
		int length;

		newInteger( &fractional, 0L );
		if( ( length = checkReadCtagIdentifier( stream, 0, TRUE ) ) != CRYPT_OK )
			return( CRYPT_ERROR );
		readDataLength += readIntegerData( stream, &fractional ) + length;
		monetaryAmount->fractional = fractional.shortInteger;
		deleteInteger( &fractional );
		}

	if( sGetStatus( stream ) != STREAM_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}
#endif /* 0 */
