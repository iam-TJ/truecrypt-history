/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */


/* Everything below this line is automatically updated by the -mkproto-tool- */

void AddComboItem ( HWND hComboBox , char *lpszFileName );
LPARAM MoveEditToCombo ( HWND hComboBox );
int GetOrderComboIdx ( HWND hComboBox , int *nIdxList , int nElems );
LPARAM UpdateComboOrder ( HWND hComboBox );
void LoadCombo ( HWND hComboBox , char *lpszSection , char *lpszKey , char *lpszIni );
void DumpCombo ( HWND hComboBox , char *lpszSection , char *lpszKey , char *lpszIni );
