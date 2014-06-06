/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include "crypto.h"
#include "fat.h"
#include "progress.h"

#include <time.h>

#define WRITE_BUF_SIZE 65536

void
GetFatParams (fatparams * ft)
{
	int fatsecs, j;

	if (ft->num_sectors >= 2098000)
		ft->cluster_size = 64;
	else if (ft->num_sectors >= 1050000)
		ft->cluster_size = 32;
	else if (ft->num_sectors >= 526000)
		ft->cluster_size = 16;
	else if (ft->num_sectors >= 264000)
		ft->cluster_size = 8;
	else if (ft->num_sectors >= 132000)
		ft->cluster_size = 4;
	else if (ft->num_sectors >= 68000)
		ft->cluster_size = 2;
	else
		ft->cluster_size = 1;

	for (j = 2;; j = j << 1)
	{
		if ((ft->num_sectors * SECTOR_SIZE) / SECTOR_SIZE / j < 65536)
			break;
	}

	ft->secs_track = (ft->num_sectors * SECTOR_SIZE) / SECTOR_SIZE / j;
	ft->heads = j;

	ft->dir_entries = 512;
	ft->fats = 2;
	ft->create_time = time (NULL);
	ft->media = 0xf8;
	ft->sector_size = SECTOR_SIZE;
	ft->hidden = 0;

	ft->size_root_dir = ft->dir_entries * 32;
	fatsecs = ft->num_sectors - (ft->size_root_dir + SECTOR_SIZE + 1) / SECTOR_SIZE - 1;

	ft->size_fat = 12;
	ft->cluster_count = (int) ((__int64) fatsecs * SECTOR_SIZE) /
	    (ft->cluster_size * SECTOR_SIZE + 3);
	ft->fat_length = (((ft->cluster_count * 3 + 1) >> 1) + SECTOR_SIZE + 1) /
	    SECTOR_SIZE;

	/* MS-DOS programmers reference p32, clusters > 4086 = FAT16 */
	if (ft->cluster_count > 4086)
	{
		ft->size_fat = 16;
		ft->cluster_count = (int) ((__int64) fatsecs * SECTOR_SIZE) /
		    (ft->cluster_size * SECTOR_SIZE + 4);
		ft->fat_length = (ft->cluster_count * 2 + SECTOR_SIZE + 1) /
		    SECTOR_SIZE;
	}

	if (ft->num_sectors >= 65536)
	{
		ft->sectors = 0;
		ft->total_sect = ft->num_sectors;
	}
	else
	{
		ft->sectors = ft->num_sectors;
		ft->total_sect = 0;
	}


}

void
PutBoot (fatparams * ft, unsigned char *boot)
{
	int cnt = 0;

	boot[cnt++] = 0xeb;	/* boot jump */
	boot[cnt++] = 0x3c;
	boot[cnt++] = 0x90;
	memcpy (boot + cnt, "E4M  \0", 8);	/* system id */
	cnt += 8;
	memcpy (boot + cnt, (short *) &ft->sector_size, 2);	/* bytes per sector */
	cnt += 2;
	memcpy (boot + cnt, (char *) &ft->cluster_size, 1);	/* sectors per cluster */
	cnt++;
	boot[cnt++] = 0x01;	/* 1 reserved sector */
	boot[cnt++] = 0x00;
	memcpy (boot + cnt, (char *) &ft->fats, 1);	/* 2 fats */
	cnt++;
	memcpy (boot + cnt, (short *) &ft->dir_entries, 2);	/* 512 root entries */
	cnt += 2;
	memcpy (boot + cnt, (short *) &ft->sectors, 2);	/* # sectors */
	cnt += 2;
	memcpy (boot + cnt, (char *) &ft->media, 1);	/* media byte */
	cnt++;
	memcpy (boot + cnt, (short *) &ft->fat_length, 2);	/* fat size */
	cnt += 2;
	memcpy (boot + cnt, (short *) &ft->secs_track, 2);	/* # sectors per track */
	cnt += 2;
	memcpy (boot + cnt, (short *) &ft->heads, 2);	/* # heads */
	cnt += 2;
	boot[cnt++] = 0x00;	/* 0 hidden sectors */
	boot[cnt++] = 0x00;
	boot[cnt++] = 0x00;
	boot[cnt++] = 0x00;
	memcpy (boot + cnt, (long *) &ft->total_sect, 4);	/* # huge sectors */
	cnt += 4;
	boot[cnt++] = 0x00;	/* drive number */
	boot[cnt++] = 0x00;	/* reserved */
	boot[cnt++] = 0x29;	/* boot sig */
	memcpy (boot + cnt, (long *) &ft->create_time, 4);	/* vol id */
	cnt += 4;
	memcpy (boot + cnt, (char *) ft->volume_name, 11);	/* vol title */
	cnt += 11;
	if (ft->size_fat == 16)
		memcpy (boot + cnt, "FAT16   ", 8);	/* filesystem type */
	else
		memcpy (boot + cnt, "FAT12   ", 8);	/* filesystem type */
	cnt += 8;
	memset (boot + cnt, 0, 448);	/* boot code */
	cnt += 448;
	boot[cnt++] = 0x55;
	boot[cnt++] = 0xaa;	/* boot sig */
}


BOOL
WriteSector (HFILE dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     int *nSecNo, int *progress, PCRYPTO_INFO cryptoInfo,
	     int nFrequency, diskio_f write)
{
	(*cryptoInfo->encrypt_sector) ((unsigned long *) sector,
	(*nSecNo)++, 1, cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->cipher);
	memcpy (write_buf + *write_buf_cnt, sector, SECTOR_SIZE);
	(*write_buf_cnt) += SECTOR_SIZE;

	if (*write_buf_cnt == WRITE_BUF_SIZE)
	{
		if ((*write) (dev, write_buf, WRITE_BUF_SIZE) == HFILE_ERROR)
			return FALSE;
		else
			*write_buf_cnt = 0;
	}

	if (++(*progress) == nFrequency)
	{
		if (UpdateProgressBar (*nSecNo) == TRUE)
			return FALSE;
		*progress = 0;
	}

	return TRUE;

}

int
Format (fatparams * ft, HFILE dev, int nVolType, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], *write_buf;
	int progress = 0, nSecNo = 1;
	int x, n;

	if ((*write) (dev, (char *) &ft->header, SECTOR_SIZE) == HFILE_ERROR)
		return ERR_OS_ERROR;

	write_buf = e4malloc (WRITE_BUF_SIZE);

	memset (sector, 0, sizeof (sector));

	if (isE4M (nVolType) == TRUE)
	{
		PutBoot (ft, (unsigned char *) sector);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				 cryptoInfo, nFrequency, write) == FALSE)
			goto fail;
	}

	/* write fat */
	for (x = 1; x <= ft->fats; x++)
	{
		for (n = 0; n < ft->fat_length; n++)
		{
			memset (sector, 0, SECTOR_SIZE);
			if (n == 0)
			{
				unsigned char fat_sig[4];
				if (ft->size_fat == 16)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0xff;
				}
				else
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0x00;
				}

				memcpy (sector, fat_sig, 4);
			}
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				    cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
	}


	/* write rootdir */
	for (x = 0; x < ft->size_root_dir / SECTOR_SIZE; x++)
	{
		memset (sector, 0, SECTOR_SIZE);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				 cryptoInfo, nFrequency, write) == FALSE)
			goto fail;

	}

	/* write data area */
	x = ft->num_sectors - 1 - ft->size_root_dir / SECTOR_SIZE - ft->fat_length * 2;
	while (x--)
	{
		memset (sector, 0, SECTOR_SIZE);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				 cryptoInfo, nFrequency, write) == FALSE)
			goto fail;
	}

	if (write_buf_cnt != 0 && (*write) (dev, write_buf, write_buf_cnt) == HFILE_ERROR)
		goto fail;

	e4mfree (write_buf);
	return 0;

      fail:

	e4mfree (write_buf);
	return ERR_OS_ERROR;
}
