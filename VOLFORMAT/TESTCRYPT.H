/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void init_cipher2 ( int cipher , void *key , void *ks , int key_len );
void ResetCipherTest ( HWND hwndDlg , int nCipherChoice );
BOOL Des56TestLoop ( void *test_vectors , int nVectorCount , int enc );
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
