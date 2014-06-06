/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2006 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#define FILE_HISTORY "History.xml"

void AddComboItem ( HWND hComboBox , char *lpszFileName );
LPARAM MoveEditToCombo ( HWND hComboBox );
int GetOrderComboIdx ( HWND hComboBox , int *nIdxList , int nElems );
LPARAM UpdateComboOrder ( HWND hComboBox );
void LoadCombo ( HWND hComboBox );
void DumpCombo ( HWND hComboBox , int bClear );
void ClearCombo (HWND hComboBox);
int IsComboEmpty (HWND hComboBox);