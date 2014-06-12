# Microsoft Developer Studio Generated NMAKE File, Format Version 4.10
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

!IF "$(CFG)" == ""
CFG=Test32 - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Test32 - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Test32 - Win32 Release" && "$(CFG)" != "Test32 - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "TEST32.MAK" CFG="Test32 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Test32 - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "Test32 - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "Test32 - Win32 Debug"
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Test32 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Test32"
# PROP BASE Intermediate_Dir "Test32"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Test32"
# PROP Intermediate_Dir "Test32"
# PROP Target_Dir ""
OUTDIR=.\Test32
INTDIR=.\Test32

ALL : "$(OUTDIR)\TEST32.exe"

CLEAN : 
	-@erase "$(INTDIR)\TESTHL.OBJ"
	-@erase "$(INTDIR)\TESTLIB.OBJ"
	-@erase "$(OUTDIR)\TEST32.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /ML /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Test32/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x1409 /d "NDEBUG"
# ADD RSC /l 0x1409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/TEST32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib shell32.lib crypt32.lib /nologo /subsystem:console /machine:I386
# SUBTRACT LINK32 /incremental:yes
LINK32_FLAGS=kernel32.lib user32.lib shell32.lib crypt32.lib /nologo\
 /subsystem:console /incremental:no /pdb:"$(OUTDIR)/TEST32.pdb" /machine:I386\
 /out:"$(OUTDIR)/TEST32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\TESTHL.OBJ" \
	"$(INTDIR)\TESTLIB.OBJ"

"$(OUTDIR)\TEST32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Test32 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Test32"
# PROP BASE Intermediate_Dir "Test32"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Test32"
# PROP Intermediate_Dir "Test32"
# PROP Target_Dir ""
OUTDIR=.\Test32
INTDIR=.\Test32

ALL : "$(OUTDIR)\TEST32.exe"

CLEAN : 
	-@erase "$(INTDIR)\TESTHL.OBJ"
	-@erase "$(INTDIR)\TESTLIB.OBJ"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\TEST32.exe"
	-@erase "$(OUTDIR)\TEST32.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /ML /W3 /Gm /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /ML /W3 /Gm /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE"\
 /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Test32/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x1409 /d "_DEBUG"
# ADD RSC /l 0x1409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/TEST32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib shell32.lib crypt32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib shell32.lib crypt32.lib /nologo\
 /subsystem:console /incremental:no /pdb:"$(OUTDIR)/TEST32.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)/TEST32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\TESTHL.OBJ" \
	"$(INTDIR)\TESTLIB.OBJ"

"$(OUTDIR)\TEST32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "Test32 - Win32 Release"
# Name "Test32 - Win32 Debug"

!IF  "$(CFG)" == "Test32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Test32 - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=\TESTLIB.C
DEP_CPP_TESTL=\
	".\..\capi.h"\
	".\..\crypt.h"\
	

"$(INTDIR)\TESTLIB.OBJ" : $(SOURCE) $(DEP_CPP_TESTL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\TESTHL.C
DEP_CPP_TESTH=\
	".\..\capi.h"\
	

"$(INTDIR)\TESTHL.OBJ" : $(SOURCE) $(DEP_CPP_TESTH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
# End Project
################################################################################
