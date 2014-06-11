#include "e4mdefs.h"

#include "crypto.h"
#include "sdvol.h"
#include "endian.h"

int
cmpsector (char *ba, char *bb)
{
  int x = 1;
  int c;
  for (c = 0; c < SECTOR_SIZE; c++)
    {
      if ((*ba) != (*bb))
	x = 0;
      ba++;
      bb++;
    }
  return x;
}

void
InitializeCipher (void *ks, int cipher, char *blin, short keylen)
{
  unsigned char blowkey[]= "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz   ";
  memset (&blowkey[0], 0, 36);
  memcpy (&blowkey[0], blin, keylen);

  /* SD needs special init here because it has a weakness in that the SHA'd
     blowfish key is 20 bytes long... but the disk blowfish key is 32 bytes
     long which means the strength of the SD implementation is only 160bits
     NOT 256bits as claimed */

  init_sd_cipher (cipher, keylen, blowkey, ks);

  /* A similar problem to the above applies to SD's implemenation of 3des, it
     is likewise limited to only 160bits */
}

void
DeCipherKeys (void *ks, int cipher, unsigned long *buffer, int CBCEnable)
{
  /* This deciphers the whitening table, and the ENCRYPTION KEY with the
     chosen cipher */
  int ivl2;
  int ivr2;
  int n;
  int ivr = 0;
  /* CBC starts at 0 on this occasion */
  int ivl = 0;
  int bl = 2;

  if (cipher == SQUARE)
    bl = 4;

  /* 128 = SECTOR_SIZE bytes We are doing 2 Kbytes */
  for (n = 0; n < 128 * 4; n = n + bl)
    {
      ivl2 = buffer[n];
      ivr2 = buffer[n + 1];

      decipher_block (cipher, &buffer[n], ks);

      if (CBCEnable)

	{
	  buffer[n] = ivl ^ buffer[n];
	  buffer[n + 1] = ivr ^ buffer[n + 1];
	}

      ivl = ivl2;
      ivr = ivr2;
    }

}

/* WhiTable is a pointer to the 1k "summer"/whitening table, This routine
   generates the IV (left) and IV(Right) for each sector. lower 64 bits is IV
   It also generates XOR 'whitening' values to xor the cipher text with *JUST*
   before or after it is written/read to from disk. This can be found in the
   upper 64 bits summed

Parameters: temp_block is the current SECTOR block being dealt with. l and r
   are pointers to the address of the variables whick will contain the IV
   (left) and IV(right) values... cbccl and cbccr are pointers which contain
   the addresses of variables which will be set to the so called "whitening"
   values.

cbccl= cipher block chaining constant left cbccl= cipher block chaining
   constant right

*/

void
getiv64 (int *l, int *r, int *cbccl, int *cbccr, int temp_block, char *WhiTable)
{

  _asm
  {
    mov ecx,[temp_block]
    mov esi,[WhiTable]

    /* ecx = sector number..... */

      pushad
      push ebp

      xor eax, eax
      xor edx, edx
      xor ebp, ebp
      xor edi, edi


      mov ebx, 32


      formIVW:

      push esi
      shr ecx, 1
      jnc nohigh
      add esi, 16
      nohigh:


      add eax,[esi]		/* 96 bits */
    adc edx,[esi + 4]
    adc ebp,[esi + 8]
    adc edi,[esi + 12]

    pop esi
      add esi, 32
      dec ebx
      jnz formIVW
      mov ecx, ebp
      pop ebp
      mov esi,[cbccl]
      mov[esi], ecx
      mov esi,[cbccr]
      mov[esi], edi
      mov esi,[l]
      mov[esi], eax
      mov esi,[r]
      mov[esi], edx
      popad
  }
}

void
cipherblockwr (void *ks, int cipher, unsigned long *buffer, char *WhiTable, int tempblock, int numsectors)
{
  char *temp;

  int ivl, ivr;

  int cbccl, cbccr;
  int n;


  int bl = 2;

  if (cipher == SQUARE)
    bl = 4;

  while (numsectors)
    {

      getiv64 (&ivl, &ivr, &cbccl, &cbccr, tempblock, WhiTable);

      /* generally 128/2*8 interations , sector scrambler... */
      for (n = 0; n < 128; n = n + bl)
	{
	  buffer[n] = ivl ^ buffer[n];
	  buffer[n + 1] = ivr ^ buffer[n + 1];

	  encipher_block (cipher, &buffer[n], ks);

	  ivl = buffer[n];
	  ivr = buffer[n + 1];

	  buffer[n] ^= cbccl;
	  buffer[n + 1] ^= cbccr;


	}
      tempblock++;
      numsectors--;

      temp = (char *) buffer;
      temp += SECTOR_SIZE;
      buffer = (unsigned long *) temp;
    }

}




void
cipherblockrd (void *ks, int cipher, unsigned long *buffer, char *WhiTable, int tempblock, int numsectors)

{
  char *temp;

  int ivl, ivr, ivl2, ivr2, cbccl, cbccr;

  int n;
  int bl = 2;


  if (cipher == SQUARE)
    bl = 4;

  while (numsectors)
    {

      getiv64 (&ivl, &ivr, &cbccl, &cbccr, tempblock, WhiTable);


      /* sector scrambler... */
      for (n = 0; n < 128; n = n + bl)
	{

	  buffer[n] ^= cbccl;
	  buffer[n + 1] ^= cbccr;

	  ivl2 = buffer[n];
	  ivr2 = buffer[n + 1];

	  decipher_block (cipher, &buffer[n], ks);

	  buffer[n] = ivl ^ buffer[n];
	  buffer[n + 1] = ivr ^ buffer[n + 1];

	  ivl = ivl2;
	  ivr = ivr2;
	}

      tempblock++;
      numsectors--;

      temp = (char *) buffer;
      temp += SECTOR_SIZE;
      buffer = (unsigned long *) temp;

    }

}

#define SCRAMBLE_READ  0
#define SCRAMBLE_WRITE 1

void
cipherblock (void *ks, int cipher, int wr, unsigned long *buffer, char *WhiTable, int tempblock, int numsectors)

{
  int index = 0;

  if (wr == SCRAMBLE_WRITE)
    {
      cipherblockwr (ks, cipher, buffer, WhiTable, tempblock, numsectors);
      return;
    }

  if (wr == SCRAMBLE_READ)
    cipherblockrd (ks, cipher, buffer, WhiTable, tempblock, numsectors);
}

void
scramble (void *ks, int cipher, int wr, char *buffer, char *keys, unsigned int temp_block, unsigned int num_sectors)

{
  /* if (cv->cipher != SUMMEROLD) 00 is old summer */
  {
    cipherblock (ks, cipher, wr, (unsigned long *) buffer, keys, temp_block, num_sectors);
    return;
  }
}

void
CipherOneItem (void *ks, int cipher, int mode, char *buffer, char *data, int size, char *WhiTable)
{
  memset (buffer, 0, SECTOR_SIZE);
  memcpy (buffer, data, size);
  scramble (ks, cipher, mode, buffer, WhiTable, 3, 1);
  memcpy (data, buffer, size);
}

/* Under Win9x the memory used here normally comes from the stack, I cannot
   do this under NT because it's > 4096 which means stack probe code is
   dragged in. All I can do is allocate some non-page memory here, if the
   alloc fails here, the driver will crash */

void
cipherupgrade (int cipher, int mode, infostruct * i, char *digestptr, char *WhiTable)
{
  unsigned char tkey[36] = "abcdefghijklmnopqrstuvwxyz123456";
  char *i2 = e4malloc (2048);
  char *ks = e4malloc (MAX_EXPANDED_KEY);

  memcpy (&tkey[0], digestptr, SHA_DIGESTSIZE);

  InitializeCipher (ks, cipher, (char *) &tkey, SHA_DIGESTSIZE);

  CipherOneItem (ks, cipher, mode, i2, (char *) &i->sumLOW, 16, WhiTable);
  CipherOneItem (ks, cipher, mode, i2, (char *) &i->infotext, 256, WhiTable);

  memset (ks, 0, sizeof (ks));

  e4mfree (i2);
  e4mfree (ks);
}

void
encipherupgrade (int cipher, infostruct * i, char *digestptr, char *WhiTable)
{
  cipherupgrade (cipher, SCRAMBLE_WRITE, i, digestptr, WhiTable);
}

void
decipherupgrade (int cipher, infostruct * i, char *digestptr, char *WhiTable)
{
  cipherupgrade (cipher, SCRAMBLE_READ, i, digestptr, WhiTable);

}

void
threedesencipher (unsigned long *b, void *ks)
{
  des_encrypt (b, ks, 1);
  des_encrypt (b, (void *) ((char *) ks + 128), 0);
  des_encrypt (b, (void *) ((char *) ks + 256), 1);
}

void
threedesdecipher (unsigned long *b, void *ks)
{
  des_encrypt (b, (void *) ((char *) ks + 256), 0);
  des_encrypt (b, (void *) ((char *) ks + 128), 1);
  des_encrypt (b, ks, 0);
}

void
threedesinitialise (char *key, void *ks)
{
  char *key2 = key + 8;
  char *key3 = key2 + 8;

  des_key_sched ((des_cblock *) key, ks);
  des_key_sched ((des_cblock *) key2, (void *) ((char *) ks + 128));
  des_key_sched ((des_cblock *) key3, (void *) ((char *) ks + 256));
}

/* The text in the information sector is itself encrypted with the SHA'd
   password, as well as with the disk key! When we get here the info sector
   has been decrypted with the disk key, but the text must still be decrypted
   & then encrypted again with the SHA'd password. */
void
incrementaccesscount (int cipher, char *sectorbuffer, char *tempkeybuffer, char *digestptr, char *WhiTable)
{
  unsigned int sumlow, sumhigh;
  char *textstringaddress;
  infostruct *i = (infostruct *) sectorbuffer;

  _asm
  {

    mov edx,[tempkeybuffer]
    xor eax, eax
      xor ebx, ebx
      mov ecx, 2048 / 8
      sum:add eax,[edx]
    adc ebx,[edx + 4]
    add edx, 8
      dec ecx
      jnz sum
      mov[sumlow], eax
      mov[sumhigh], ebx
  }

    textstringaddress = sectorbuffer;
  /* text is at the start */

  i->invalidsum = 0;

  if (i->newmode == 0x38af2924)
    {
      decipherupgrade (cipher, i, digestptr, WhiTable);

      _asm
      {

	mov edx,[textstringaddress]
	mov eax,[sumlow]
	mov ebx,[sumhigh]
	mov ecx, 32
	  texsum:add eax,[edx]
	adc ebx,[edx + 4]
	add edx, 8
	  dec ecx
	  jnz texsum
	  mov[sumlow], eax
	  mov[sumhigh], ebx
      }

      if ((i->sumLOW != sumlow) || (i->sumHIGH != sumhigh))

	  i->invalidsum = 1;


    }

  if ((i->magiclow == 0xa852c732) && (i->magichigh == 0xb1593286))
    {

      i->accessed++;
      /* prefdrive = i->preferredletter; */
      memcpy ((char *) &i->oldtime, (char *) &i->newtime, sizeof (DrvSYSTEMTIME));
      i->TimeValid2 = i->TimeValid1;
      /* memcpy ((char *) &i->newtime, (char *) &DiskTime, sizeof
         (DrvSYSTEMTIME)); */
      i->TimeValid1 = 0x67293c87;
    }
  else
    {
      /* This is done, if the disk isn 't initialised */
      i->magiclow = 0xa852c732;
      i->magichigh = 0xb1593286;
      i->accessed = 1;
      i->preferredletter = 0 - 'A';
      strcpy ((char *) &i->infotext, "Newly created volume");

      /* some random junk value...signifies invalid time */
      i->TimeValid1 = 0x67293c87;
      i->TimeValid2 = 0x238f3232;
      i->invalidsum = 0;

      _asm
      {

	mov edx,[textstringaddress]
	mov eax,[sumlow]
	mov ebx,[sumhigh]
	mov ecx, 32
	  texsum2:add eax,[edx]
	adc ebx,[edx + 4]
	add edx, 8
	  dec ecx
	  jnz texsum2
	  mov[sumlow], eax
	  mov[sumhigh], ebx
      }


        i->sumLOW = sumlow;
      i->sumHIGH = sumhigh;
      i->sum3 = 0;
      i->sum4 = 0;
    }

  i->newmode = 0x38af2924;

  encipherupgrade (cipher, i, digestptr, WhiTable);
}

/* password HASH algortihm SHA1 */

void
shash (char *pw, int size, SHA1_CTX * S, char *hash)
{
  SHA1Init (S);
  SHA1Update (S, (unsigned char *) pw, size);
  SHA1Final ((unsigned char *) hash, S);
  LongReverse ((unsigned long *) hash, SHA_DIGESTSIZE);
}

void _cdecl
SD_decrypt (unsigned long *buffer,
	    long sectorNo,
	    long noSectors,
	    void *ks,
	    char *master_iv,
	    int cipher)
{
  scramble (ks, cipher, SCRAMBLE_READ, (char *) buffer, master_iv, sectorNo, noSectors);
}

void _cdecl
SD_encrypt (unsigned long *buffer,
	    long sectorNo,
	    long noSectors,
	    void *ks,
	    char *master_iv,
	    int cipher)
{
  scramble (ks, cipher, SCRAMBLE_WRITE, (char *) buffer, master_iv, sectorNo, noSectors);
}

/* Input to this function is 16 disk sectors */
int
SD_ReadHeader (char *dev, int *nVolType, char *lpszPassword, PCRYPTO_INFO * retInfo)
{
  unsigned char tkey[36];
  char *digestptr = lpszPassword;
  char *sectorbuffer = e4malloc (2048);
  PCRYPTO_INFO cryptoInfo;
  int i;

  if (nVolType);		/* Remove warning */

  if (sectorbuffer == NULL)
    return ERR_OUTOFMEMORY;

  *retInfo = cryptoInfo = crypto_open ();
  if (cryptoInfo == NULL)
    {
      e4mfree (sectorbuffer);
      return ERR_OUTOFMEMORY;
    }

  cryptoInfo->encrypt_sector = &SD_encrypt;
  cryptoInfo->decrypt_sector = &SD_decrypt;

  for (i = 0; i < 8; i++)
    {
      int cipher = i + 32;

      memcpy (cryptoInfo->iv, dev, 2048);

      /* Copy in the users sha1 digest */
      memcpy (&tkey[0], digestptr, SHA_DIGESTSIZE);
      InitializeCipher (&cryptoInfo->ks, cipher, (char *) &tkey, SHA_DIGESTSIZE);

      /* Try to decipher the disk key */
      DeCipherKeys (&cryptoInfo->ks, cipher, (unsigned long *) cryptoInfo->iv, 1);
      memcpy (&tkey[0], (char *) cryptoInfo->iv + 1024, 32);

      /* Load the disk key */
      InitializeCipher (&cryptoInfo->ks, cipher, (char *) &tkey, 32);

      memcpy (&cryptoInfo->iv[1024 + SECTOR_SIZE], dev + 0 + 8192, SECTOR_SIZE);	/* skip 16 sectors, read
											   sector# 0 */

      cryptoInfo->decrypt_sector ((unsigned long *) &cryptoInfo->iv[1024 + SECTOR_SIZE], 0, 1, cryptoInfo->ks, cryptoInfo->iv, cipher);

      memcpy (sectorbuffer, dev + SECTOR_SIZE + 8192, SECTOR_SIZE);	/* skips 16 sectors,
									   read sector# 1 */
      cryptoInfo->decrypt_sector ((unsigned long *) sectorbuffer, 1, 1, cryptoInfo->ks, cryptoInfo->iv, cipher);
      if (cmpsector (sectorbuffer, (char *) &cryptoInfo->iv[1024 + SECTOR_SIZE]) != 0)
	{
	  memcpy (sectorbuffer, dev + 1024 + 8192, SECTOR_SIZE);	/* skips 16 sectors,
									   read sector# 2 */
	  cryptoInfo->decrypt_sector ((unsigned long *) sectorbuffer, 2, 1, cryptoInfo->ks, cryptoInfo->iv, cipher);
	  if (cmpsector (sectorbuffer, (char *) &cryptoInfo->iv[1024 + SECTOR_SIZE]) != 0)
	    {
	      char tempkeybuffer[2048];
	      infostruct *iblock;

	      memcpy (sectorbuffer, dev + 1536 + 8192, SECTOR_SIZE);	/* Copy sector# 3 */
	      memcpy (tempkeybuffer, dev, 2048);	/* Copy first 2kb */
	      cryptoInfo->decrypt_sector ((unsigned long *) sectorbuffer, 3, 1, cryptoInfo->ks, cryptoInfo->iv, cipher);

	      incrementaccesscount (cipher, sectorbuffer, tempkeybuffer, digestptr, (char *) cryptoInfo->iv);

	      iblock = (infostruct *) sectorbuffer;

	      cryptoInfo->cipher = cipher;

	      cryptoInfo->voltype = *nVolType = SD_VOLTYPE;

	      e4mfree (sectorbuffer);

	      return 0;
	    }
	}
    }

  crypto_close (cryptoInfo);

  e4mfree (sectorbuffer);

  return ERR_PASSWORD_WRONG;
}
