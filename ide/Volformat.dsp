# Microsoft Developer Studio Project File - Name="volformat" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=volformat - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Volformat.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Volformat.mak" CFG="volformat - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "volformat - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "volformat - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "volformat - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "release"
# PROP BASE Intermediate_Dir "release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "release"
# PROP Intermediate_Dir "release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W4 /O2 /I "\dev\e4meo\common" /I "\dev\e4meo\common\libbf" /I "\dev\e4meo\common\libdes" /I "\dev\e4meo\common\idea" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "VOLFORMAT" /YX"e4mdefs.h" /FD /c
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

!ELSEIF  "$(CFG)" == "volformat - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "fdebug"
# PROP BASE Intermediate_Dir "fdebug"
# PROP BASE Target_Dir "fdebug"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "fdebug"
# PROP Intermediate_Dir "fdebug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir "fdebug"
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W4 /Gm /Zi /Od /I "\dev\e4m\common\\" /I "c:\dev\e4m\crypto" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "VOLFORMAT" /FR /YX"e4mdefs.h" /FD /c
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

# Name "volformat - Win32 Release"
# Name "volformat - Win32 Debug"
# Begin Source File

SOURCE="..\volformat\b-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\crypto\Bf_skey.c
# End Source File
# Begin Source File

SOURCE="..\volformat\c-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\crypto\c_ecb.c
# End Source File
# Begin Source File

SOURCE=..\crypto\c_skey.c
# End Source File
# Begin Source File

SOURCE=..\common\combo.c
# End Source File
# Begin Source File

SOURCE=..\Common\crc.c
# End Source File
# Begin Source File

SOURCE=..\common\crypto.c
# End Source File
# Begin Source File

SOURCE="..\volformat\d-win32.obj"
# End Source File
# Begin Source File

SOURCE=..\crypto\des.c
# End Source File
# Begin Source File

SOURCE=..\common\dlgcode.c
# End Source File
# Begin Source File

SOURCE=..\common\e4m2.bmp
# End Source File
# Begin Source File

SOURCE=..\crypto\ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=..\Common\endian.c
# End Source File
# Begin Source File

SOURCE=..\common\fat.c
# End Source File
# Begin Source File

SOURCE=..\common\format.c
# End Source File
# Begin Source File

SOURCE=..\crypto\Idea.c
# End Source File
# Begin Source File

SOURCE=..\crypto\Idea_386.c
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

SOURCE=..\common\Sdvol.c
# End Source File
# Begin Source File

SOURCE=..\crypto\Set_key.c
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

SOURCE=..\volformat\uncroot.c
# End Source File
# Begin Source File

SOURCE=..\volformat\volformat.c
# End Source File
# Begin Source File

SOURCE=..\volformat\volformat.rc

!IF  "$(CFG)" == "volformat - Win32 Release"

!ELSEIF  "$(CFG)" == "volformat - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\common\volumes1.c
# End Source File
# End Target
# End Project
