/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

extern char szDriverPassword[4][MAX_PASSWORD + 1];
extern int nDriverPasswordLen[4];
extern int nPasswordIdx;

/* Everything below this line is automatically updated by the -mkproto-tool- */

int VolumeReadHeaderCache (BOOL bCache, char *dev, int *nVolType, char *lpszPassword, int nPasswordLen, PCRYPTO_INFO * retInfo);
void WipeCache (void);
