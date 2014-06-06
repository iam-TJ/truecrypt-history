# Microsoft Developer Studio Project File - Name="e4msetup" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=e4msetup - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "e4msetup.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "e4msetup.mak" CFG="e4msetup - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "e4msetup - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "e4msetup - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "e4msetup - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W4 /GX- /O2 /I "..\..\common" /I "..\..\crypto" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SETUP" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386

!ELSEIF  "$(CFG)" == "e4msetup - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W4 /Gm /GX- /Zi /Od /I "..\..\common" /I "..\..\crypto" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SETUP" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "e4msetup - Win32 Release"
# Name "e4msetup - Win32 Debug"
# Begin Source File

SOURCE=..\..\Crypto\Bf_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Bf_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\C_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\C_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\C_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Des.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Des_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\Setup\Dir.c
# End Source File
# Begin Source File

SOURCE=..\..\Common\Dismount.c
# End Source File
# Begin Source File

SOURCE=..\..\Common\Dlgcode.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Idea.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Idea_386.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Md5.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Set_key.c
# End Source File
# Begin Source File

SOURCE=..\..\Setup\Setup.c
# End Source File
# Begin Source File

SOURCE=..\..\Setup\setup.rc

!IF  "$(CFG)" == "e4msetup - Win32 Release"

!ELSEIF  "$(CFG)" == "e4msetup - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Sha.c
# End Source File
# Begin Source File

SOURCE=..\..\Crypto\Sha1.c
# End Source File
# End Target
# End Project
