# Microsoft Developer Studio Project File - Name="voltest" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=voltest - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "voltest.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "voltest.mak" CFG="voltest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "voltest - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "voltest - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "voltest - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "c:\dev\e4m\common" /I "c:\dev\e4m\crypto" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "VOLTEST" /YX /FD /c
# ADD BASE RSC /l 0xc09 /d "NDEBUG"
# ADD RSC /l 0xc09 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "voltest - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vDebug"
# PROP BASE Intermediate_Dir "vDebug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vDebug"
# PROP Intermediate_Dir "vDebug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "c:\dev\e4m\common" /I "c:\dev\e4m\crypto" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "VOLTEST" /FR /YX /FD /c
# ADD BASE RSC /l 0xc09 /d "_DEBUG"
# ADD RSC /l 0xc09 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "voltest - Win32 Release"
# Name "voltest - Win32 Debug"
# Begin Source File

SOURCE="..\voltest\b-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\\crypto\bf_skey.c
# End Source File
# Begin Source File

SOURCE="..\voltest\c-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\\crypto\c_ecb.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\c_skey.c
# End Source File
# Begin Source File

SOURCE=..\\common\crc.c
# End Source File
# Begin Source File

SOURCE=..\\common\crypto.c
# End Source File
# Begin Source File

SOURCE="..\voltest\d-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\\crypto\des.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=..\\common\endian.c
# End Source File
# Begin Source File

SOURCE=..\voltest\getopt.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\idea.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\idea_386.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\md5.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\misty1.c
# End Source File
# Begin Source File

SOURCE=..\\common\pkcs5.c
# End Source File
# Begin Source File

SOURCE=..\\common\random.c
# End Source File
# Begin Source File

SOURCE=..\\common\sdvol.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\set_key.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\sha.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\sha1.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\square.c
# End Source File
# Begin Source File

SOURCE=..\\crypto\tea_asm.c
# End Source File
# Begin Source File

SOURCE=..\voltest\voltest.c
# End Source File
# Begin Source File

SOURCE=..\\common\volumes1.c
# End Source File
# End Target
# End Project
