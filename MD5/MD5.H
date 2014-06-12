#ifndef _MD5_DEFINED

#define _MD5_DEFINED

/* The MD5 block size and message digest sizes, in bytes */

#define MD5_DATASIZE	64
#define MD5_DIGESTSIZE	16

/* The structure for storing MD5 info */

typedef struct {
			   LONG digest[ 4 ];			/* Message digest */
			   LONG countLo, countHi;		/* 64-bit bit count */
			   LONG data[ 16 ];				/* MD5 data buffer */
#ifdef _BIG_WORDS
			   BYTE dataBuffer[ MD5_DATASIZE ];	/* Byte buffer for data */
#endif /* _BIG_WORDS */
			   BOOLEAN done;				/* Whether final digest present */
			   } MD5_INFO;

/* Message digest functions */

void md5Initial( MD5_INFO *md5Info );
void md5Update( MD5_INFO *md5Info, BYTE *buffer, int count );
void md5Final( MD5_INFO *md5Info );

#endif /* _MD5_DEFINED */

