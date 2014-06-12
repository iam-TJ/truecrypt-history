/* ASN.1/cryptlib object dumping code, based on ASN.1 dump program by dpk */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Tag classes */

#define CLASS_MASK		0xC0	/* Bits 8 and 7 */
#define UNIVERSAL		0x00	/* 0 = Universal (defined by ITU X.680) */
#define APPLICATION		0x40	/* 1 = Application */
#define CONTEXT			0x80	/* 2 = Context-specific */
#define PRIVATE			0xC0	/* 3 = Private */

/* Encoding type */

#define FORM_MASK		0x20	/* Bit 6 */
#define PRIMITIVE		0x00	/* 0 = primitive */
#define CONSTRUCTED		0x20	/* 1 = constructed */

/* Universal tags */

#define TAG_MASK		0x1F	/* Bits 5 - 1 */
#define BOOLEAN			0x01	/*  1: TRUE or FALSE */
#define INTEGER			0x02	/*  2: Arbitrary precision integer */
#define BITSTRING		0x03	/*  2: Sequence of bits */
#define OCTETSTRING		0x04	/*  4: Sequence of bytes */
#define NULLTAG			0x05	/*  5: NULL */
#define OID				0x06	/*  6: Object Identifier (numeric sequence) */
#define OBJDESCRIPTOR	0x07	/*  7: Object Descriptor (human readable) */
#define EXTERNAL		0x08	/*  8: External / Instance Of */
#define REAL			0x09	/*  9: Real (Mantissa * Base^Exponent) */
#define ENUMERATED		0x0A	/* 10: Enumerated */
#define EMBEDDED_PDV	0x0B	/* 11: Embedded Presentation Data Value */
#define SEQUENCE		0x10	/* 16: Constructed Sequence / Sequence Of */
#define SET				0x11	/* 17: Constructed Set / Set Of */
#define NUMERICSTR		0x12	/* 18: Numeric String (digits only) */
#define PRINTABLESTR	0x13	/* 19: Printable String */
#define T61STR			0x14	/* 20: T61 String (Teletex) */
#define VIDEOTEXSTR		0x15	/* 21: Videotex String */
#define IA5STR			0x16	/* 22: IA5 String */
#define UTCTIME			0x17	/* 23: UTC Time */
#define GENERALIZEDTIME	0x18	/* 24: Generalized Time */
#define GRAPHICSTR		0x19	/* 25: Graphic String */
#define VISIBLESTR		0x1A	/* 26: Visible String (ISO 646) */
#define GENERALSTR		0x1B	/* 27: General String */
#define UNIVERSALSTR	0x1C	/* 28: Universal String */
#define BMPSTR			0x1E	/* 30: Basic Multilingual Plane String */

/* Length encoding */

#define LEN_XTND  0x80		/* Indefinite or long form */
#define LEN_MASK  0x7f		/* Bits 7 - 1 */

/* Structure to hold info on an ASN.1 item */

struct Item {
	int id;						/* Identifier/tag */
	long len;					/* Data length */
	};

/* Return descriptive strings for universal tags */

char *idstr( int tagID )
	{
	switch( tagID & TAG_MASK )
		{
		case BOOLEAN:
			return( "BOOLEAN" );
		case INTEGER:
			return( "INTEGER" );
		case BITSTRING:
			return( "BIT STRING" );
		case OCTETSTRING:
			return( "OCTET STRING" );
		case NULLTAG:
			return( "NULL" );
		case OID:
			return( "OBJECT IDENTIFIER" );
		case OBJDESCRIPTOR:
			return( "ObjectDescriptor" );
		case EXTERNAL:
			return( "EXTERNAL" );
		case REAL:
			return( "REAL" );
		case ENUMERATED:
			return( "ENUMERATED" );
		case EMBEDDED_PDV:
			return( "EMBEDDED PDV (1993)" );
		case SEQUENCE:
			return( "SEQUENCE" );
		case SET:
			return( "SET" );
		case NUMERICSTR:
			return( "NumericString" );
		case PRINTABLESTR:
			return( "PrintableString" );
		case T61STR:
			return( "TeletexString" );
		case VIDEOTEXSTR:
			return( "VideotexString" );
		case IA5STR:
			return( "IA5String" );
		case UTCTIME:
			return( "UTCTime" );
		case GENERALIZEDTIME:
			return( "GeneralizedTime" );
		case GRAPHICSTR:
			return( "GraphicString" );
		case VISIBLESTR:
			return( "VisibleString" );
		case GENERALSTR:
			return( "GeneralString" );
		case UNIVERSALSTR:
			return( "UniversalString (1993)" );
		case BMPSTR:
			return( "BMPString (1993)" );
		default:
			return( "Unknown (Reserved)" );
		}
	}

/* Return descriptive strings for cryptlib objects and algorithms */

static char stringBuffer[ 100 ];

static char *objectStr( int objectID )
	{
	char *objectName[] = { "TagEncryptedKey", "TagPKCEncryptedKey",
						   "TagSignature", "TagEncryptedData",
						   "TagCompressedData", "TagSignedData",
						   "TagRawData", "TagNonData" };

	if( objectID < 8 )
		{
		sprintf( stringBuffer, "%s(%d)", objectName[ objectID ], objectID );
		return( stringBuffer );
		}
	sprintf( stringBuffer, "Unknown(%d)", objectID );
	return( stringBuffer );
	}

static char *enumAlgo( int value )
	{
	struct { int value; char *name; } enumInfo[] = {
		{ 0, "CRYPT_ALGO_NONE" }, { 1, "CRYPT_ALGO_DES" },
		{ 2, "CRYPT_ALGO_3DES" }, { 3, "CRYPT_ALGO_IDEA" },
		{ 4, "CRYPT_ALGO_MDCSHS" },{ 5, "CRYPT_ALGO_RC2" },
		{ 6, "CRYPT_ALGO_RC4" }, { 7, "CRYPT_ALGO_RC5" },
		{ 8, "CRYPT_ALGO_SAFER" }, { 9, "CRYPT_ALGO_BLOWFISH" },
		{ 10, "CRYPT_ALGO_GOST" }, { 11, "CRYPT_ALGO_SKIPJACK" },
		{ 100, "CRYPT_ALGO_DH" },  { 101, "CRYPT_ALGO_RSA" },
		{ 102, "CRYPT_ALGO_DSS" }, { 200, "CRYPT_ALGO_MD2" },
		{ 201, "CRYPT_ALGO_MD4" }, { 202, "CRYPT_ALGO_MD5" },
		{ 204, "CRYPT_ALGO_SHA" }, { 204, "CRYPT_ALGO_RIPEMD160" },
		{ -1, NULL }
		};
	int i;

	for( i = 0; enumInfo[ i ].value != -1; i++ )
		if( enumInfo[ i ].value == value )
			{
			sprintf( stringBuffer, "%s (%d)", enumInfo[ i ].name, value );
			return( stringBuffer );
			}
	sprintf( stringBuffer, "CRYPT_ALGO_UNKNOWN (%d)", value );
	return( stringBuffer );
	}

static char *enumMode( int value )
	{
	struct { int value; char *name; } enumInfo[] = {
		{ 0, "CRYPT_MODE_NONE" }, { 1, "CRYPT_MODE_STREAM" },
		{ 2, "CRYPT_MODE_ECB" }, { 3, "CRYPT_MODE_CBC" },
		{ 4, "CRYPT_MODE_CFB" }, { 5, "CRYPT_MODE_OFB" },
		{ 6, "CRYPT_MODE_PCBC" }, { 7, "CRYPT_MODE_COUNTER" },
		{ 100, "CRYPT_MODE_PKC" },
		{ -1, NULL }
		};
	int i;

	for( i = 0; enumInfo[ i ].value != -1; i++ )
		if( enumInfo[ i ].value == value )
			{
			sprintf( stringBuffer, "%s (%d)", enumInfo[ i ].name, value );
			return( stringBuffer );
			}
	sprintf( stringBuffer, "CRYPT_MODE_UNKNOWN (%d)", value );
	return( stringBuffer );
	}

/* Return descriptive strings for an object identifier */

static char *oidStr( char *oid, int oidLength )
	{
	struct { char *oid; char *string; } oidInfo[] = {
		{ "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x01\x01", "pkcs-1 (1 2 840 113549 1 1)" },
		{ "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", "rsaEncryption (1 2 840 113549 1 1 1)" },
		{ "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02", "md2withRSAEncryption (1 2 840 113549 1 1 2)" },
		{ "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04", "md5withRSAEncryption (1 2 840 113549 1 1 4)" },
		{ "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05", "sha1withRSAEncryption (1 2 840 113549 1 1 5)" },
		{ "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x03\x01", "dhKeyAgreement (1 2 840 113549 1 3 1)" },
		{ "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x04", "rc4 (1 2 840 113549 3 4)" },
		{ "\x06\x05\x2B\x0E\x03\x02\x0C", "dsaEncryption (1 3 14 3 2 12)" },
		{ "\x06\x05\x2B\x0E\x03\x02\x0D", "dsaWithSHA (1 3 14 3 2 13)" },
		{ "\x06\x03\x55\x04\x03", "commonName (2 5 4 3)" },
		{ "\x06\x03\x55\x04\x06", "countryName (2 5 4 6)" },
		{ "\x06\x03\x55\x04\x07", "localityName (2 5 4 7)" },
		{ "\x06\x03\x55\x04\x08", "stateOrProvinceName (2 5 4 8)" },
		{ "\x06\x03\x55\x04\x0A", "organizationName (2 5 4 10)" },
		{ "\x06\x03\x55\x04\x0B", "organizationalUnitName (2 5 4 11)" },
		{ NULL, NULL }
		};
	int i = 0;

	memset( oid + oidLength, 0, 2 );
	while( oidInfo[ i ].oid != NULL )
		{
		if( !memcmp( oidInfo[ i ].oid + 2, oid, oidLength ) )
			return( oidInfo[ i ].string );
		i++;
		}

	return( NULL );
	}

/* Indent a string by the appropriate amount */

static void doIndent( int level )
	{
	int i;

	for( i = 0; i < level; i++ )
		printf( "  " );
	}

/* Dump data as a string of hex digits up to a maximum of 128 bytes */

static void dumpHex( FILE *inFile, long length, int level )
	{
	long noBytes = length;
	int i;

	if( noBytes > 128 )
		noBytes = 128;	/* Only output a maximum of 128 bytes */
	if( level > 8 )
		level = 8;		/* Make sure we don't go off the edge of the screen */
	for( i = 0; i < noBytes; i++ )
		{
		if( !( i % 16 ) )
			{
			printf( "\n\t    : " );
			doIndent( level + 1 );
			}
		printf( "%s%02X", i % 16 ? " " : "", getc( inFile ) );
		}
	if( length > 128 )
		{
		length -= 128;
		printf( "\n\t    : " );
		doIndent( level + 5 );
		printf( "[ Another %ld bytes skipped ]", length );
		fseek( inFile, length, SEEK_CUR );
		}

	printf( "\n" );
	}

/* Get an integer value */

static long getValue( FILE *inFile, long length )
	{
	long value = 0;
	int i;

	for( i = 0; i < length; i++ )
		value = ( value << 8 ) | getc( inFile );
	return( value );
	}

/* Get an ASN.1 objects tag and length */

struct Item *getItem( FILE *inFile )
	{
	static struct Item object;
	long length;

	object.id = fgetc( inFile );
	if( feof( inFile ) )
		return( NULL );
	if( ( length = getc( inFile ) ) & LEN_XTND )
		{
		int i;

		length &= LEN_MASK;
		if( !length )
			{
			puts( "\nError: Indefinite-length encoded data found.\n" );
			exit( EXIT_FAILURE );
			}
		if( length > 4 )
			{
			printf( "\nError: Object length field %d too large.\n", length );
			exit( EXIT_FAILURE );
			}
	    object.len = 0;
		for( i = 0; i < length; i++ )
			object.len = ( object.len << 8 ) | getc( inFile );
		}
	else
		object.len = length;

	return( &object );
	}

/* Print an ASN.1 object */

void printAsn1( FILE *inFile, int level, long length )
	{
	struct Item *item;
	long lastPos = ftell( inFile );
	int seenEnum = 0;

	while( ( item = getItem( inFile ) ) != NULL )
		{
		long value;
		int i;

		/* Decrement the enum level */
		if( seenEnum )
			seenEnum--;

		/* Print offset into buffer, tag, length, and offset of next item */
		printf( "%4ld %2X %4d: ", lastPos, item->id, item->len );
		doIndent( level );

		if( ( item->id & CLASS_MASK ) == UNIVERSAL )
			{
			/* Print the object type */
			printf( "%s", idstr( item->id ) );

			/* Perform a sanity check */
			if( ( ( item->id & TAG_MASK ) != NULLTAG ) && ( item->len < 1 ) )
				{
				puts( "\nError: Object has bad length field." );
				exit( EXIT_FAILURE );
				}

			if( ( item->id & FORM_MASK ) == CONSTRUCTED )
				{
				puts( " {" );
				printAsn1( inFile, level + 1, item->len );
				printf( "\t    :   " );
				doIndent( level );
				puts( "}" );
				}
			else
				{
				char string[ 150 ], *oidName;

				switch( item->id & TAG_MASK )
					{
					case BOOLEAN:
						printf(" %s\n", getc( inFile ) ? "TRUE" : "FALSE" );
						break;

					case INTEGER:
						if( item->len > 4 )
							dumpHex( inFile, item->len, level );
						else
							printf( " %ld\n", getValue( inFile, item->len ) );
						break;

					case ENUMERATED:
						if( !seenEnum )
							{
							printf( " %s\n", enumAlgo( ( int ) \
										getValue( inFile, item->len ) ) );
							seenEnum = 2;
							}
						else
							printf( " %s\n", enumMode( ( int ) \
										getValue( inFile, item->len ) ) );
						break;

					case BITSTRING:
						printf( " %d unused bits", getc( inFile ) );
						item->len -= 1;
					case OCTETSTRING:
						dumpHex( inFile, item->len, level );
						break;

					case OID:
						/* Heirarchical Object Identifier: First two
						   levels are encoded into one byte, since the
						   root level has only 3 nodes (40*x + y) */
						fread( string, 1, ( size_t ) item->len, inFile );
						if( ( oidName = oidStr( string, ( int ) item->len ) ) != NULL )
							{
							if( 14 + ( level * 2 ) + 17 + strlen( oidName ) >= 80 )
								{
								printf( "\n\t    :" );
								doIndent( level + 1 );
								}
							printf( " %s\n", oidName );
							break;
							}

						printf( " '%d %d", string[ 0 ] / 40,
								string[ 0 ] % 40 );
						value = 0;
						for( i = 1; i < item->len; i++ )
							{
							value = ( value << 7 ) | ( string[ i ] & 0x7F );
							if( !( string[ i ] & 0x80 ) )
								{
								printf( " %ld", value );
								value = 0;
								}
							}
						printf( "'\n" );
						break;

					case NULLTAG:
						putchar( '\n' );
						break;

					case OBJDESCRIPTOR:
					case PRINTABLESTR:
					case UTCTIME:
					case GENERALIZEDTIME:
					case GRAPHICSTR:
					case VISIBLESTR:
					case GENERALSTR:
					case UNIVERSALSTR:
					case NUMERICSTR:
					case T61STR:
					case VIDEOTEXSTR:
					case IA5STR:
					case BMPSTR:
						fread( string, 1, ( size_t ) item->len, inFile );
						string[ ( int ) item->len ] = '\0';
						printf( " '%s'\n", string );
						break;

					default:
						printf( "Unrecognised primitive, hex value is:\n ");
						dumpHex( inFile, item->len, level );
						break;
					}
				}
			}
		else
			{
			/* Print the object type */
			if( ( item->id & CLASS_MASK ) == APPLICATION )
					printf( "[APPLICATION %s]",
							objectStr( item->id & TAG_MASK ) );
			else
				{
				switch( item->id & CLASS_MASK )
					{
					case CONTEXT:
						printf( "[CONTEXT-SPECIFIC" );
						break;

					case PRIVATE:
						printf( "[PRIVATE" );
					}
				printf( " %d]", item->id & TAG_MASK );
				}

			/* Perform a sanity check */
			if( ( ( item->id & TAG_MASK ) != NULLTAG ) && ( item->len < 1 ) )
				{
				puts( "\nError: Object has bad length." );
				exit( EXIT_FAILURE );
				}

			/* If it's constructed, print the various fields in it */
			if( ( item->id & FORM_MASK ) == CONSTRUCTED )
				{
				puts( " {" );
				printAsn1( inFile, level + 1, item->len );
				printf( "\t    :   " );
				doIndent( level );
				puts( "}" );
				}
			else
				/* This could be anything, dump it as hex data */
				dumpHex( inFile, item->len, level );
			}


		length -= ( int )( ftell( inFile ) - lastPos );
		lastPos = ftell( inFile );
		if( length <= 0 )
			return;
		}
	}

int main( int argc, char *argv[] )
	{
	FILE *inFile;

	/* Check args and open the input file */
	if( argc != 2 )
		{
		puts( "Usage: dumpasn1 <file>" );
		exit( EXIT_FAILURE );
		}
	if( ( inFile = fopen( argv[ 1 ], "rb" ) ) == NULL )
		{
		perror( argv[ 1 ] );
		exit( EXIT_FAILURE );
		}
	printAsn1( inFile, 0, 50000L );
	fclose( inFile );

	return( EXIT_SUCCESS );
	}
