/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

enum _args_
{
	UNRECOGNIZED_ARG,
	DRIVE_LETTER_ARG,
	EXPLORE_ARG,
	BEEP_ARG,
	PASSWORD_ARG,
	AUTO_ARG,
	CACHE_ARG,
	HISTORY_ARG,
	WIPE_ARG,
	VOLUME_ARG
};

#define HAS_ARGUMENT	1
#define HAS_NO_ARGUMENT !HAS_ARGUMENT

/* Everything below this line is automatically updated by the -mkproto-tool- */

int Win32CommandLine ( char *lpszCommandLine , char ***lpszArgs );
int GetArgSepPosOffset ( char *lpszArgument );
int GetArgumentID ( char *lpszArgument , int *nArgPos );
int GetArgumentValue ( char **lpszCommandLineArgs , int nArgPos , int *nArgIdx , int nNoCommandLineArgs , char *lpszValue , int nValueSize );
