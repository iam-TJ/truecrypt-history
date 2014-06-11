# Microsoft Developer Studio Project File - Name="volmount" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=volmount - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "volmount.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "volmount.mak" CFG="volmount - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "volmount - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "volmount - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "volmount - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W4 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "VOLMOUNT" /Fr /YX"e4mdefs.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comctl32.lib /nologo /subsystem:windows /machine:I386

!ELSEIF  "$(CFG)" == "volmount - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "mDebug"
# PROP BASE Intermediate_Dir "mDebug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "mDebug"
# PROP Intermediate_Dir "mDebug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W4 /Gm /GX /Zi /Od /I "c:\dev\e4m\common" /I "c:\dev\e4m\crypto" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "VOLMOUNT" /FR /YX"e4mdefs.h" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comctl32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "volmount - Win32 Release"
# Name "volmount - Win32 Debug"
# Begin Source File

SOURCE="..\volmount\b-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\crypto\bf_skey.c
# End Source File
# Begin Source File

SOURCE=..\crypto\c_ecb.c
# End Source File
# Begin Source File

SOURCE=..\crypto\c_enc.c
# End Source File
# Begin Source File

SOURCE=..\crypto\c_skey.c
# End Source File
# Begin Source File

SOURCE=..\volmount\cmdline.c
# End Source File
# Begin Source File

SOURCE=..\common\combo.c
# End Source File
# Begin Source File

SOURCE=..\common\crc.c
# End Source File
# Begin Source File

SOURCE=..\common\crypto.c
# End Source File
# Begin Source File

SOURCE="..\volmount\d-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\crypto\des.c
# End Source File
# Begin Source File

SOURCE=..\common\dlgcode.c
# End Source File
# Begin Source File

SOURCE=..\crypto\ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=..\common\endian.c
# End Source File
# Begin Source File

SOURCE=..\crypto\idea.c
# End Source File
# Begin Source File

SOURCE=..\crypto\idea_386.c
# End Source File
# Begin Source File

SOURCE=..\crypto\md5.c
# End Source File
# Begin Source File

SOURCE=..\crypto\misty1.c
# End Source File
# Begin Source File

SOURCE=..\common\password.c
# End Source File
# Begin Source File

SOURCE=..\common\pkcs5.c
# End Source File
# Begin Source File

SOURCE=..\common\random.c
# End Source File
# Begin Source File

SOURCE=..\common\sdvol.c
# End Source File
# Begin Source File

SOURCE=..\crypto\set_key.c
# End Source File
# Begin Source File

SOURCE=..\crypto\sha.c
# End Source File
# Begin Source File

SOURCE=..\crypto\sha1.c
# End Source File
# Begin Source File

SOURCE=..\crypto\square.c
# End Source File
# Begin Source File

SOURCE=..\crypto\tea_asm.c
# End Source File
# Begin Source File

SOURCE=..\volmount\tree.bmp
# End Source File
# Begin Source File

SOURCE=..\volmount\volmount.c
# End Source File
# Begin Source File

SOURCE=..\volmount\volmount.rc

!IF  "$(CFG)" == "volmount - Win32 Release"

!ELSEIF  "$(CFG)" == "volmount - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\common\volumes1.c
# End Source File
# End Target
# End Project
