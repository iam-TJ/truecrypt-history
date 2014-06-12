/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"
#include "progress.h"

extern HWND hCurPage;
extern HWND hProgressBar;
extern BOOL bThreadCancel;
extern int nPbar;

void
InitProgressBar (int nRange)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE, 0, MAKELPARAM (0, nRange));
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);
}

BOOL
UpdateProgressBar (int nSecNo)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_STEPIT, 0, 0);
	if (nSecNo);		/* remove warning */

	return bThreadCancel;
}
