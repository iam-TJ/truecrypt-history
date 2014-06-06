/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "e4mdefs.h"
#include "crypto.h"
#include "fat.h"
#include "volumes1.h"
#include "voltest.h"

void
dumpsector (int sector, char *vh)
{
	int i;
	printf ("sector %d\n ", sector);
	for (i = 0; i < 32; i++)
	{
		int n;
		for (n = 0; n < 16; n++)
			fprintf (stdout, "%02x ", (unsigned char) vh[n + (i * 16)]);
		for (n = 0; n < 16; n++)
		{
			if (vh[n + (i * 16)] >= '0' && vh[n + (i * 16)] <= '9')
				fprintf (stdout, "%c", (unsigned char) vh[n + (i * 16)]);
			else if (vh[n + (i * 16)] >= 'a' && vh[n] <= 'z')
				fprintf (stdout, "%c", (unsigned char) vh[n + (i * 16)]);
			else if (vh[n + (i * 16)] >= 'A' && vh[n + (i * 16)] <= 'Z')
				fprintf (stdout, "%c", (unsigned char) vh[n + (i * 16)]);
			else
				fprintf (stdout, "%c", (unsigned char) '.');
		}

		fprintf (stdout, "\n ");
	}
}

extern int getopt (int, char **, char *);
extern char *optarg;

void
main (int argc, char *argv[])
{
	PCRYPTO_INFO cryptoInfo;
	FILE *f;
	int nVolType;
	char buffer[512];

	char szPassword[MAX_PASSWORD + 1] =
	{0};
	char szFileName[300] =
	{0};
	int encrypt_test = 0, sector_test = 0, sector_count = 1;
	int sector_flag = 0;
	int x;


	while ((x = getopt (argc, argv, "p:ts:v:c:")) != EOF)
	{
		switch (x)
		{
		case 'p':
			strcpy (szPassword, optarg);
			break;
		case 't':
			encrypt_test = 1;
			break;
		case 's':
			sector_test = atoi (optarg);
			sector_flag = 1;
			break;
		case 'c':
			sector_count = atoi (optarg);
			break;
		case 'v':
			strcpy (szFileName, optarg);
			break;
		}
	}

	if (*szFileName == 0)
	{
		printf ("\n%s usage: -v volume [-p password] [-t] [-s secNumber] [-c secCount]\n", argv[0]);
		printf ("\t-t tests encryption, -s decrypts from a sector number, for -c sectors.\n\n");
		printf ("\tAtleast the volume is required.\n\n");
		printf ("\tOnly file based volumes are supported.\n\n");
		exit (1);
	}

	f = fopen (szFileName, "rb");
	if (f == NULL)
	{
		perror (szFileName);
		exit (1);
	}

	x = fread (buffer, 1, sizeof (buffer), f);
	if (x != sizeof (buffer))
	{
		printf ("This volume is too small. The volume must be > %d bytes in size.", sizeof (buffer));
		fclose (f);
		exit (1);
	}

	x = VolumeReadHeader (buffer, &nVolType, szPassword, &cryptoInfo);
	if (x == 0)
	{
		char tmp[512];

		memset (tmp, 0, 512);
		memcpy (tmp, "Hello world", 11);

		cryptoInfo->encrypt_sector ((void *) tmp, 0xff, 1, cryptoInfo->ks,
					cryptoInfo->iv, cryptoInfo->cipher);

		cryptoInfo->decrypt_sector ((void *) tmp, 0xff, 1, cryptoInfo->ks,
					cryptoInfo->iv, cryptoInfo->cipher);

		if (encrypt_test)
			if (memcmp (tmp, "Hello world", 11) == 0)
			{
				printf ("\nEncrypt/Decrypt reversible pass\n");
			}
			else
			{
				printf ("\nEncrypt/Decrypt reversible fail\n");
			}



		if (sector_flag != 0)
		{
			char *secs = malloc (512 * sector_count);
			int i;

			if (secs == NULL)
			{
				printf ("Out of memory.");
				fclose (f);
				exit (1);
			}

			sector_test += 1;

			x = fseek (f, sector_test * 512, SEEK_SET);
			if (x != 0)
			{
				perror ("volume too small?");
				fclose (f);
				exit (1);
			}

			x = fread (secs, 1, 512 * sector_count, f);
			if (x != 512 * sector_count)
			{
				perror ("volume too small?");
				fclose (f);
				exit (1);
			}

			cryptoInfo->decrypt_sector ((unsigned long *) secs, sector_test, sector_count, cryptoInfo->ks,
					cryptoInfo->iv, cryptoInfo->cipher);

			for (i = 0; i < sector_count; i++)
				dumpsector (i + sector_test, secs + i * 512);

			free (secs);

		}

		printf ("Success, %s volume cipher = %s, format ver %d\n",
			nVolType != SFS_VOLTYPE ? "E4M" : "SFS",
			get_cipher_name (cryptoInfo->cipher),
			nVolType == E4M_OLD_VOLTYPE ? 1 : (nVolType != SFS_VOLTYPE ? 2 : 1));

		fclose (f);

		exit (0);
	}
	else
	{
		printf ("Failure, not an E4M volume or wrong password\n");
		exit (1);
	}

	fclose (f);
	exit (0);
}
