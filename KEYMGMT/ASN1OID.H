/****************************************************************************
*																			*
*							  ASN.1 Object Identifiers						*
*							Copyright Peter Gutmann 1996					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

/* The maximum (encoded) object identifier size */

#define MAX_OID_SIZE		20

/* Various object identifiers.  We take advantage of the fact that object
   identifiers were designed to be handled in the encoded form (without any
   need for decoding) and compare expected OID's with the raw encoded form */

#define OID_PKCS1			( ( BYTE * ) "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x01\x01" )
							/* pkcs-1			1 2 840 113549 1 1 */
#define OID_RSAENCRYPTION	( ( BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" )
							/* rsaEncryption	1 2 840 113549 1 1 1 */
#define OID_DHKEYAGREEMENT	( ( BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x03\x01" )
							/* dhKeyAgreement	1 2 840 113549 1 3 1 */
#define OID_RC4				( ( BYTE * ) "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x04" )
							/* rc4				1 2 840 113549 3 4 */
#define OID_DSAENCRYPTION	( ( BYTE * ) "\x06\x05\x2B\x0E\x03\x02\x0C" )
							/* dsaEncryption	1 3 14 3 2 12 */
#define OID_COMMONNAME		( ( BYTE * ) "\x06\x03\x55\x04\x03" )
							/* commonName		2 5 4 3 */

/* Get the length of an encoded object identifier */

#define sizeofOID( oid )	( ( int ) oid[ 1 ] )

#endif /* _ASN1OID_DEFINED */
