/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include <malloc.h>
#include <ctype.h>
#include "cmdline.h"

int
Win32CommandLine (char *lpszCommandLine, char ***lpszArgs)
{
	int i = 0, k = 0, x = 0, nValid = TRUE;
	int nLen = strlen (lpszCommandLine);
	int nArrSize = 16;
	char szTmp[256];

	*lpszArgs = malloc (sizeof (char *)* nArrSize);

	if (*lpszArgs == NULL)
		return 0;

	while (i < nLen)
	{
		if (lpszCommandLine[i] == ' ')
		{
			if (k > 0)
			{
				szTmp[k] = 0;
				(*lpszArgs)[x] = strdup (szTmp);
				if ((*lpszArgs)[x] == NULL)
				{
					free (*lpszArgs);
					return 0;
				}
				x++;
				k = 0;
				if (x == nArrSize)
				{
					break;
				}
			}
			i++;
			continue;
		}
		if (lpszCommandLine[i] == '"')
		{
			i++;
			while (i < nLen)
			{
				if (lpszCommandLine[i] == '"')
					break;
				if (k < sizeof (szTmp))
					szTmp[k++] = lpszCommandLine[i++];
				else
				{
					free (*lpszArgs);
					return 0;
				}
			}

			if (lpszCommandLine[i] != '"')
			{
				nValid = FALSE;
				break;
			}
		}
		else
		{
			if (k < sizeof (szTmp))
				szTmp[k++] = lpszCommandLine[i];
			else
			{
				free (*lpszArgs);
				return 0;
			}
		}

		i++;
	}

	if (nValid == FALSE)
	{
		free (*lpszArgs);
		return 0;
	}
	else if (k > 0)
	{
		szTmp[k] = 0;
		(*lpszArgs)[x] = strdup (szTmp);
		if ((*lpszArgs)[x] == NULL)
		{
			free (*lpszArgs);
			return 0;
		}
		x++;
		k = 0;
	}
	if (!x)
	{
		free (*lpszArgs);
		return 0;
	}
	return x;
}

int
GetArgSepPosOffset (char *lpszArgument)
{
	if (lpszArgument[0] == '/')
		return 1;
	else if (lpszArgument[0] == '-' && lpszArgument[1] == '-')
		return 2;
	else if (lpszArgument[0] == '-')
		return 1;
	else
		return 0;
}

typedef struct argument_t
{
	char long_name[16];
	char short_name[8];
	int nArgId;
} argument;

int
GetArgumentID (char *lpszArgument, int *nArgPos)
{
	argument args[]=
	{
		{"/volume", "/v", VOLUME_ARG},
		{"/letter", "/l", DRIVE_LETTER_ARG},
		{"/explore", "/e", EXPLORE_ARG},
		{"/beep", "/b", BEEP_ARG},
		{"/password", "/p", PASSWORD_ARG},
		{"/auto", "/a", AUTO_ARG},
		{"/cache", "/c", CACHE_ARG},
		{"/history", "/h", HISTORY_ARG},
		{"/wipecache", "/wc", WIPE_ARG}
	};

	char szTmp[256];
	int i, arg_cnt;

	i = strlen (lpszArgument);
	szTmp[i] = 0;
	while (--i >= 0)
	{
		szTmp[i] = (char) tolower (lpszArgument[i]);
	}

	arg_cnt = sizeof (args) / sizeof (args[0]);

	for (i = 0; i < arg_cnt; i++)
	{
		size_t k;

		k = strlen (args[i].long_name);
		if (memcmp (args[i].long_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < arg_cnt; x++)
			{
				size_t m;

				m = strlen (args[x].long_name);
				if (memcmp (args[x].long_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return args[i].nArgId;
			}
		}
	}

	for (i = 0; i < arg_cnt; i++)
	{
		size_t k;

		k = strlen (args[i].short_name);
		if (memcmp (args[i].short_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < arg_cnt; x++)
			{
				size_t m;

				m = strlen (args[x].short_name);
				if (memcmp (args[x].short_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return args[i].nArgId;
			}
		}
	}


	return UNRECOGNIZED_ARG;
}

int
GetArgumentValue (char **lpszCommandLineArgs, int nArgPos, int *nArgIdx,
		  int nNoCommandLineArgs, char *lpszValue, int nValueSize)
{
	*lpszValue = 0;

	if (nArgPos)
	{
		/* Handles the case of no space between parameter code and
		   value */
		memcpy (lpszValue, &lpszCommandLineArgs[*nArgIdx][nArgPos], nValueSize * sizeof (char));
		lpszValue[nValueSize - 1] = 0;
		return HAS_ARGUMENT;
	}
	else if (*nArgIdx + 1 != nNoCommandLineArgs)
	{
		int x = GetArgSepPosOffset (lpszCommandLineArgs[*nArgIdx + 1]);
		if (x == 0)
		{
			/* Handles the case of space between parameter code
			   and value */
			memcpy (lpszValue, &lpszCommandLineArgs[*nArgIdx + 1][x], nValueSize * sizeof (char));
			lpszValue[nValueSize - 1] = 0;
			(*nArgIdx)++;
			return HAS_ARGUMENT;
		}
	}

	return HAS_NO_ARGUMENT;
}
