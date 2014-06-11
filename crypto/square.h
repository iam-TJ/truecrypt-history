#define R 8	/* number of rounds */
#define SQUARE_BLOCKSIZE (4*sizeof(sword32))

#ifndef USUAL_TYPES
#define USUAL_TYPES

	typedef unsigned char	sbyte;	/*  8 bit */
	typedef unsigned short	sword16;	/* 16 bit */

#ifdef __alpha
	typedef unsigned int	sword32;	/* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	sword32;	/* 32 bit */
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

extern const char *squareBanner;

typedef sbyte squareBlock[SQUARE_BLOCKSIZE];
typedef sword32 squareKeySchedule[R+1][4];

void squareGenerateRoundKeys ( const squareBlock key , squareKeySchedule roundKeys_e , squareKeySchedule roundKeys_d );
void squareExpandKey ( const squareBlock key , squareKeySchedule roundKeys_e );
void squareEncrypt ( sword32 text [4 ], squareKeySchedule roundKeys );
void squareDecrypt ( sword32 text [4 ], squareKeySchedule roundKeys );
void squareEncrypt ( sword32 text [4 ], squareKeySchedule roundKeys );
void squareDecrypt ( sword32 text [4 ], squareKeySchedule roundKeys );
void squareinitialise ( char *keyin , void *ks );
