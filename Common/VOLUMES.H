/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void EncryptCFB ( unsigned char *iv , unsigned char *auxKey , unsigned char *buffer , int noBytes );
void DecryptCFB ( unsigned char *iv , unsigned char *auxKey , unsigned char *buffer , int noBytes );
_inline unsigned long DecryptXor ( unsigned long input , unsigned long *reg1 , unsigned long reg2 );
_inline unsigned long EncryptXor ( unsigned long input , unsigned long *reg1 , unsigned long reg2 );
void _cdecl EncryptSector ( unsigned long *data , unsigned long secNo , unsigned long noSectors , unsigned char *auxKey , unsigned char *iv , int cipher );
void _cdecl DecryptSector ( unsigned long *data , unsigned long secNo , unsigned long noSectors , unsigned char *auxKey , unsigned char *iv , int cipher );
void InitKey ( PKEY_INFO keyInfo , int doEncrypt );
void SetupKey ( PCRYPTO_INFO cryptoInfo , PKEY_INFO keyInfo );
void _cdecl DummySectorStub ( void *a , unsigned long b , unsigned long c , void *d , void *e , int f );
void _cdecl EncryptSector8 ( unsigned long *data , unsigned long secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
void _cdecl DecryptSector8 ( unsigned long *data , unsigned long secNo , unsigned long noSectors , unsigned char *ks , unsigned char *iv , int cipher );
int VolumeReadHeader ( char *dev , int *nVolType , char *lpszPassword , PCRYPTO_INFO *retInfo );
void SetVolumeID ( char *dev , int nVolType );
int CheckVolumeID ( char *dev );
int VolumeWriteHeader ( fatparams *ft , char *dev , int nVolType , int cipher , char *lpszPassword , int pkcs5 , PCRYPTO_INFO *retInfo );
PCRYPTO_INFO newkey ( int cipher , char *lpszUserKey , int nUserKeyLen , PKEY_INFO keyInfo );
PCRYPTO_INFO newkey2 ( int cipher , int pkcs5 , char *lpszUserKey , int nUserKeyLen , PKEY_INFO keyInfo );
