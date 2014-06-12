# Microsoft Visual C++ Generated NMAKE File, Format Version 2.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Win32 Release" && "$(CFG)" != "Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "CRYPTNT.MAK" CFG="Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

################################################################################
# Begin Project
# PROP Target_Last_Scanned "Win32 Debug"
MTL=MkTypLib.exe
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "WinRel"
# PROP BASE Intermediate_Dir "WinRel"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "WinRel"
# PROP Intermediate_Dir "WinRel"
OUTDIR=.\WinRel
INTDIR=.\WinRel

ALL : .\cryptnt.dll $(OUTDIR)/CRYPTNT.bsc

$(OUTDIR) : 
    if not exist $(OUTDIR)/nul mkdir $(OUTDIR)

# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE CPP /nologo /MT /W3 /GX /YX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FR /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX /Fr
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "__WINDOWS__" /Fo$(INTDIR)/ /c 
CPP_OBJS=.\WinRel/
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo$(INTDIR)/"CRYPTNT.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_SBRS= \
	
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o$(OUTDIR)/"CRYPTNT.bsc" 

$(OUTDIR)/CRYPTNT.bsc : $(OUTDIR)  $(BSC32_SBRS)
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /NOLOGO /SUBSYSTEM:windows /DLL /MACHINE:I386
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib /NOLOGO /VERSION:0,99 /SUBSYSTEM:windows /DLL /PDB:none /MACHINE:I386 /OUT:"cryptnt.dll"
LINK32_FLAGS=kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib\
 shell32.lib /NOLOGO /VERSION:0,99 /SUBSYSTEM:windows /DLL /PDB:none\
 /MACHINE:I386 /DEF:".\CRYPTNT.DEF" /OUT:"cryptnt.dll"\
 /IMPLIB:$(OUTDIR)/"CRYPTNT.lib" 
DEF_FILE=.\CRYPTNT.DEF
LINK32_OBJS= \
	$(INTDIR)/SHS.OBJ \
	$(INTDIR)/LIB_IDEA.OBJ \
	$(INTDIR)/SET_KEY.OBJ \
	$(INTDIR)/CRYPTNT.res \
	$(INTDIR)/3ECB_ENC.OBJ \
	$(INTDIR)/IDEA.OBJ \
	$(INTDIR)/CRYPT.OBJ \
	$(INTDIR)/LIB_MDC.OBJ \
	$(INTDIR)/LIB_RC4.OBJ \
	$(INTDIR)/LIB_3DES.OBJ \
	$(INTDIR)/LIB_NULL.OBJ \
	$(INTDIR)/LIB_DES.OBJ \
	$(INTDIR)/RC4.OBJ \
	$(INTDIR)/ECB_ENC.OBJ \
	$(INTDIR)/PCBC_ENC.OBJ \
	$(INTDIR)/SAFER.OBJ \
	$(INTDIR)/LIB_SAFR.OBJ

.\cryptnt.dll : $(OUTDIR)  $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "WinDebug"
# PROP BASE Intermediate_Dir "WinDebug"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "WinDebug"
# PROP Intermediate_Dir "WinDebug"
OUTDIR=.\WinDebug
INTDIR=.\WinDebug

ALL : .\cryptnt.dll $(OUTDIR)/CRYPTNT.bsc

$(OUTDIR) : 
    if not exist $(OUTDIR)/nul mkdir $(OUTDIR)

# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE CPP /nologo /MT /W3 /GX /Zi /YX /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /c
# ADD CPP /nologo /MT /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX /Fr
CPP_PROJ=/nologo /MT /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "__WINDOWS__" /Fo$(INTDIR)/ /Fd$(OUTDIR)/"CRYPTNT.pdb" /c 
CPP_OBJS=.\WinDebug/
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo$(INTDIR)/"CRYPTNT.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_SBRS= \
	
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o$(OUTDIR)/"CRYPTNT.bsc" 

$(OUTDIR)/CRYPTNT.bsc : $(OUTDIR)  $(BSC32_SBRS)
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /NOLOGO /SUBSYSTEM:windows /DLL /DEBUG /MACHINE:I386
# ADD LINK32 kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib /NOLOGO /VERSION:0,99 /SUBSYSTEM:windows /DLL /PDB:none /DEBUG /MACHINE:I386 /OUT:"cryptnt.dll"
LINK32_FLAGS=kernel32.lib user32.lib winspool.lib comdlg32.lib advapi32.lib\
 shell32.lib /NOLOGO /VERSION:0,99 /SUBSYSTEM:windows /DLL /PDB:none /DEBUG\
 /MACHINE:I386 /DEF:".\CRYPTNT.DEF" /OUT:"cryptnt.dll"\
 /IMPLIB:$(OUTDIR)/"CRYPTNT.lib" 
DEF_FILE=.\CRYPTNT.DEF
LINK32_OBJS= \
	$(INTDIR)/SHS.OBJ \
	$(INTDIR)/LIB_IDEA.OBJ \
	$(INTDIR)/SET_KEY.OBJ \
	$(INTDIR)/CRYPTNT.res \
	$(INTDIR)/3ECB_ENC.OBJ \
	$(INTDIR)/IDEA.OBJ \
	$(INTDIR)/CRYPT.OBJ \
	$(INTDIR)/LIB_MDC.OBJ \
	$(INTDIR)/LIB_RC4.OBJ \
	$(INTDIR)/LIB_3DES.OBJ \
	$(INTDIR)/LIB_NULL.OBJ \
	$(INTDIR)/LIB_DES.OBJ \
	$(INTDIR)/RC4.OBJ \
	$(INTDIR)/ECB_ENC.OBJ \
	$(INTDIR)/PCBC_ENC.OBJ \
	$(INTDIR)/SAFER.OBJ \
	$(INTDIR)/LIB_SAFR.OBJ

.\cryptnt.dll : $(OUTDIR)  $(DEF_FILE) $(LINK32_OBJS)
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

################################################################################
# Begin Group "Source Files"

################################################################################
# Begin Source File

SOURCE=.\MDC\SHS.C
DEP_SHS_C=\
	.\CRYPT.H\
	.\MDC\SHS.H

$(INTDIR)/SHS.OBJ :  $(SOURCE)  $(DEP_SHS_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_IDEA.C
DEP_LIB_I=\
	.\CRYPT.H\
	.\IDEA\IDEA.H\
	.\TESTIDEA.H

$(INTDIR)/LIB_IDEA.OBJ :  $(SOURCE)  $(DEP_LIB_I) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\SET_KEY.C
DEP_SET_K=\
	.\LIBDES\DES_LOCL.H\
	.\LIBDES\PODD.H\
	.\LIBDES\SK.H\
	.\LIBDES\DES.H

$(INTDIR)/SET_KEY.OBJ :  $(SOURCE)  $(DEP_SET_K) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPTNT.RC

$(INTDIR)/CRYPTNT.res :  $(SOURCE)  $(INTDIR)
   $(RSC) $(RSC_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPTNT.DEF
# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\3ECB_ENC.C
DEP_3ECB_=\
	.\LIBDES\DES_LOCL.H\
	.\LIBDES\DES.H

$(INTDIR)/3ECB_ENC.OBJ :  $(SOURCE)  $(DEP_3ECB_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\IDEA\IDEA.C
DEP_IDEA_=\
	.\CRYPT.H\
	.\IDEA\IDEA.H

$(INTDIR)/IDEA.OBJ :  $(SOURCE)  $(DEP_IDEA_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPT.C
DEP_CRYPT=\
	.\CRYPT.H

$(INTDIR)/CRYPT.OBJ :  $(SOURCE)  $(DEP_CRYPT) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_MDC.C
DEP_LIB_M=\
	.\CRYPT.H\
	.\MDC\SHS.H

$(INTDIR)/LIB_MDC.OBJ :  $(SOURCE)  $(DEP_LIB_M) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_RC4.C
DEP_LIB_R=\
	.\CRYPT.H\
	.\RC4\RC4.H\
	.\TESTRC4.H

$(INTDIR)/LIB_RC4.OBJ :  $(SOURCE)  $(DEP_LIB_R) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_3DES.C
DEP_LIB_3=\
	.\CRYPT.H\
	.\LIBDES\DES.H

$(INTDIR)/LIB_3DES.OBJ :  $(SOURCE)  $(DEP_LIB_3) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_NULL.C
DEP_LIB_N=\
	.\CRYPT.H

$(INTDIR)/LIB_NULL.OBJ :  $(SOURCE)  $(DEP_LIB_N) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_DES.C
DEP_LIB_D=\
	.\CRYPT.H\
	.\LIBDES\DES.H\
	.\TESTDES.H

$(INTDIR)/LIB_DES.OBJ :  $(SOURCE)  $(DEP_LIB_D) $(INTDIR)

# End Source File
################################################################################
# Begin Source File

SOURCE=.\RC4\RC4.C
DEP_RC4_C=\
	.\RC4\RC4.H

$(INTDIR)/RC4.OBJ :  $(SOURCE)  $(DEP_RC4_C) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\ECB_ENC.C
DEP_ECB_E=\
	.\LIBDES\DES_LOCL.H\
	.\LIBDES\SPR.H\
	.\LIBDES\VERSION.H\
	.\LIBDES\DES.H

$(INTDIR)/ECB_ENC.OBJ :  $(SOURCE)  $(DEP_ECB_E) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIBDES\PCBC_ENC.C
DEP_PCBC_=\
	.\LIBDES\DES_LOCL.H\
	.\LIBDES\DES.H

$(INTDIR)/PCBC_ENC.OBJ :  $(SOURCE)  $(DEP_PCBC_) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\SAFER\SAFER.C
DEP_SAFER=\
	.\SAFER\SAFER.H

$(INTDIR)/SAFER.OBJ :  $(SOURCE)  $(DEP_SAFER) $(INTDIR)
   $(CPP) $(CPP_PROJ)  $(SOURCE) 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LIB_SAFR.C
DEP_LIB_S=\
	.\CRYPT.H\
	.\SAFER\SAFER.H\
	.\TESTSAFR.H

$(INTDIR)/LIB_SAFR.OBJ :  $(SOURCE)  $(DEP_LIB_S) $(INTDIR)

# End Source File
# End Group
# End Project
################################################################################
