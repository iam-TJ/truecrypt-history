/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

typedef struct DrvSYSTEMTIME
{				/* st  */
  unsigned short wYear;
  unsigned short wMonth;
  unsigned short wDayOfWeek;
  unsigned short wDay;
  unsigned short wHour;
  unsigned short wMinute;
  unsigned short wSecond;
  unsigned short wMilliseconds;
} DrvSYSTEMTIME;


typedef struct infostruct
{
  char infotext[256];		/* disk owner */
  int accessed;			/* any user...   4 */
  int preferredletter;		/* any user	  4 */
  int magiclow;			/* any user	  4 */
  int magichigh;		/* any user	  4 */

  DrvSYSTEMTIME newtime;	/* any user    16 bytes */
  int TimeValid1;		/* any user	  4 bytes */

  DrvSYSTEMTIME oldtime;	/* any user	  16 bytes */
  int TimeValid2;		/* any user	  4 */


  int newmode;			/* any user	  4 */


  unsigned int sumLOW;
  unsigned int sumHIGH;
  unsigned int sum3;		/* dummy */
  unsigned int sum4;		/* dummy */


  char invalidsum;
  char owner;
  char spare2;
  char spare3;
} infostruct;

/* Everything below this line is automatically updated by the -mkproto-tool- */

int cmpsector ( char *ba , char *bb );
void InitializeCipher ( void *ks , int cipher , char *blin , short keylen );
void DeCipherKeys ( void *ks , int cipher , unsigned long *buffer , int CBCEnable );
void getiv64 ( int *l , int *r , int *cbccl , int *cbccr , int temp_block , char *WhiTable );
void cipherblockwr ( void *ks , int cipher , unsigned long *buffer , char *WhiTable , int tempblock , int numsectors );
void cipherblockrd ( void *ks , int cipher , unsigned long *buffer , char *WhiTable , int tempblock , int numsectors );
void cipherblock ( void *ks , int cipher , int wr , unsigned long *buffer , char *WhiTable , int tempblock , int numsectors );
void scramble ( void *ks , int cipher , int wr , char *buffer , char *keys , unsigned int temp_block , unsigned int num_sectors );
void CipherOneItem ( void *ks , int cipher , int mode , char *buffer , char *data , int size , char *WhiTable );
void cipherupgrade ( int cipher , int mode , infostruct *i , char *digestptr , char *WhiTable );
void encipherupgrade ( int cipher , infostruct *i , char *digestptr , char *WhiTable );
void decipherupgrade ( int cipher , infostruct *i , char *digestptr , char *WhiTable );
void threedesencipher ( unsigned long *b , void *ks );
void threedesdecipher ( unsigned long *b , void *ks );
void threedesinitialise ( char *key , void *ks );
void incrementaccesscount ( int cipher , char *sectorbuffer , char *tempkeybuffer , char *digestptr , char *WhiTable );
void shash ( char *pw , int size , SHA1_CTX *S , char *hash );
void _cdecl SD_decrypt ( unsigned long *buffer , long sectorNo , long noSectors , void *ks , char *master_iv , int cipher );
void _cdecl SD_encrypt ( unsigned long *buffer , long sectorNo , long noSectors , void *ks , char *master_iv , int cipher );
int SD_ReadHeader ( char *dev , int *nVolType , char *lpszPassword , PCRYPTO_INFO *retInfo );
