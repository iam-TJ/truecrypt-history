/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

extern unsigned long crc_32_tab[];

#define UPDC32(octet, crc)\
  (unsigned long)((crc_32_tab[(((unsigned long)crc) ^ ((unsigned char)octet)) & 0xff] ^ (((unsigned long)crc) >> 8)))

/* Everything below this line is automatically updated by the -mkproto-tool- */

