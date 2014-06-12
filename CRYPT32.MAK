# Microsoft Developer Studio Generated NMAKE File, Format Version 4.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=Crypt32 - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Crypt32 - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Crypt32 - Win32 Release" && "$(CFG)" !=\
 "Crypt32 - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "CRYPT32.MAK" CFG="Crypt32 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Crypt32 - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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
# PROP Target_Last_Scanned "Crypt32 - Win32 Debug"
CPP=cl.exe
RSC=rc.exe
MTL=mktyplib.exe

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

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
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\CRYPT32.dll"

CLEAN : 
	-@erase ".\Release\CRYPT32.dll"
	-@erase ".\Release\LIB_RC5.OBJ"
	-@erase ".\Release\MD4.OBJ"
	-@erase ".\Release\RC4.OBJ"
	-@erase ".\Release\IDEA.OBJ"
	-@erase ".\Release\LIB_3DES.OBJ"
	-@erase ".\Release\LIB_RC4.OBJ"
	-@erase ".\Release\LIB_SHA.OBJ"
	-@erase ".\Release\LIB_BLOW.OBJ"
	-@erase ".\Release\LIB_IDEA.OBJ"
	-@erase ".\Release\LIB_RSA.OBJ"
	-@erase ".\Release\LIB_DES.OBJ"
	-@erase ".\Release\SAFER.OBJ"
	-@erase ".\Release\LIB_MDC.OBJ"
	-@erase ".\Release\BLOWFISH.OBJ"
	-@erase ".\Release\RC2.OBJ"
	-@erase ".\Release\LIB_MD5.OBJ"
	-@erase ".\Release\SHS.OBJ"
	-@erase ".\Release\LIB_SAFR.OBJ"
	-@erase ".\Release\LIB_RC2.OBJ"
	-@erase ".\Release\LIB_MD4.OBJ"
	-@erase ".\Release\SET_KEY.OBJ"
	-@erase ".\Release\ECB3_ENC.OBJ"
	-@erase ".\Release\MD5.OBJ"
	-@erase ".\Release\RC5.OBJ"
	-@erase ".\Release\LIB_NULL.OBJ"
	-@erase ".\Release\ECB_ENC.OBJ"
	-@erase ".\Release\CRYPT.OBJ"
	-@erase ".\Release\CRYPT32.res"
	-@erase ".\Release\CRYPT32.lib"
	-@erase ".\Release\CRYPT32.exp"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /O2 /D "NDEBUG" /D "WIN32" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /MT /W3 /O2 /D "NDEBUG" /D "WIN32" /D "__WINDOWS__"\
 /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/CRYPT32.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/CRYPT32.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib /nologo /subsystem:windows /dll /machine:I386
# SUBTRACT LINK32 /incremental:yes
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/CRYPT32.pdb" /machine:I386\
 /def:"\WINDOWS\CRYPT32.DEF" /out:"$(OUTDIR)/CRYPT32.dll"\
 /implib:"$(OUTDIR)/CRYPT32.lib" 
DEF_FILE= \
	"..\WINDOWS\CRYPT32.DEF"
LINK32_OBJS= \
	".\Release\LIB_RC5.OBJ" \
	".\Release\MD4.OBJ" \
	".\Release\RC4.OBJ" \
	".\Release\IDEA.OBJ" \
	".\Release\LIB_3DES.OBJ" \
	".\Release\LIB_RC4.OBJ" \
	".\Release\LIB_SHA.OBJ" \
	".\Release\LIB_BLOW.OBJ" \
	".\Release\LIB_IDEA.OBJ" \
	".\Release\LIB_RSA.OBJ" \
	".\Release\LIB_DES.OBJ" \
	".\Release\SAFER.OBJ" \
	".\Release\LIB_MDC.OBJ" \
	".\Release\BLOWFISH.OBJ" \
	".\Release\RC2.OBJ" \
	".\Release\LIB_MD5.OBJ" \
	".\Release\SHS.OBJ" \
	".\Release\LIB_SAFR.OBJ" \
	".\Release\LIB_RC2.OBJ" \
	".\Release\LIB_MD4.OBJ" \
	".\Release\SET_KEY.OBJ" \
	".\Release\ECB3_ENC.OBJ" \
	".\Release\MD5.OBJ" \
	".\Release\RC5.OBJ" \
	".\Release\LIB_NULL.OBJ" \
	".\Release\ECB_ENC.OBJ" \
	".\Release\CRYPT.OBJ" \
	".\Release\CRYPT32.res"

"$(OUTDIR)\CRYPT32.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

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
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\CRYPT32.dll"

CLEAN : 
	-@erase ".\Debug\vc40.pdb"
	-@erase ".\Debug\vc40.idb"
	-@erase ".\Debug\CRYPT32.dll"
	-@erase ".\Debug\CRYPT.OBJ"
	-@erase ".\Debug\ECB_ENC.OBJ"
	-@erase ".\Debug\SAFER.OBJ"
	-@erase ".\Debug\LIB_DES.OBJ"
	-@erase ".\Debug\LIB_MDC.OBJ"
	-@erase ".\Debug\IDEA.OBJ"
	-@erase ".\Debug\LIB_SAFR.OBJ"
	-@erase ".\Debug\LIB_MD5.OBJ"
	-@erase ".\Debug\MD5.OBJ"
	-@erase ".\Debug\LIB_3DES.OBJ"
	-@erase ".\Debug\LIB_BLOW.OBJ"
	-@erase ".\Debug\LIB_RC2.OBJ"
	-@erase ".\Debug\RC2.OBJ"
	-@erase ".\Debug\LIB_SHA.OBJ"
	-@erase ".\Debug\LIB_IDEA.OBJ"
	-@erase ".\Debug\LIB_MD4.OBJ"
	-@erase ".\Debug\MD4.OBJ"
	-@erase ".\Debug\SET_KEY.OBJ"
	-@erase ".\Debug\LIB_RSA.OBJ"
	-@erase ".\Debug\BLOWFISH.OBJ"
	-@erase ".\Debug\LIB_RC5.OBJ"
	-@erase ".\Debug\RC5.OBJ"
	-@erase ".\Debug\ECB3_ENC.OBJ"
	-@erase ".\Debug\LIB_RC4.OBJ"
	-@erase ".\Debug\RC4.OBJ"
	-@erase ".\Debug\LIB_NULL.OBJ"
	-@erase ".\Debug\SHS.OBJ"
	-@erase ".\Debug\CRYPT32.res"
	-@erase ".\Debug\CRYPT32.lib"
	-@erase ".\Debug\CRYPT32.exp"
	-@erase ".\Debug\CRYPT32.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /Zi /Od /D "_DEBUG" /D "WIN32" /D "__WINDOWS__" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /MTd /W3 /Gm /Zi /Od /D "_DEBUG" /D "WIN32" /D "__WINDOWS__"\
 /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/CRYPT32.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/CRYPT32.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/CRYPT32.pdb" /debug /machine:I386\
 /def:"\WINDOWS\CRYPT32.DEF" /out:"$(OUTDIR)/CRYPT32.dll"\
 /implib:"$(OUTDIR)/CRYPT32.lib" 
DEF_FILE= \
	"..\WINDOWS\CRYPT32.DEF"
LINK32_OBJS= \
	".\Debug\CRYPT.OBJ" \
	".\Debug\ECB_ENC.OBJ" \
	".\Debug\SAFER.OBJ" \
	".\Debug\LIB_DES.OBJ" \
	".\Debug\LIB_MDC.OBJ" \
	".\Debug\IDEA.OBJ" \
	".\Debug\LIB_SAFR.OBJ" \
	".\Debug\LIB_MD5.OBJ" \
	".\Debug\MD5.OBJ" \
	".\Debug\LIB_3DES.OBJ" \
	".\Debug\LIB_BLOW.OBJ" \
	".\Debug\LIB_RC2.OBJ" \
	".\Debug\RC2.OBJ" \
	".\Debug\LIB_SHA.OBJ" \
	".\Debug\LIB_IDEA.OBJ" \
	".\Debug\LIB_MD4.OBJ" \
	".\Debug\MD4.OBJ" \
	".\Debug\SET_KEY.OBJ" \
	".\Debug\LIB_RSA.OBJ" \
	".\Debug\BLOWFISH.OBJ" \
	".\Debug\LIB_RC5.OBJ" \
	".\Debug\RC5.OBJ" \
	".\Debug\ECB3_ENC.OBJ" \
	".\Debug\LIB_RC4.OBJ" \
	".\Debug\RC4.OBJ" \
	".\Debug\LIB_NULL.OBJ" \
	".\Debug\SHS.OBJ" \
	".\Debug\CRYPT32.res"

"$(OUTDIR)\CRYPT32.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "Crypt32 - Win32 Release"
# Name "Crypt32 - Win32 Debug"

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=\CRYPT.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_CRYPT=\
	".\..\crypt.h"\
	".\..\bnlib\bnstub.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\CRYPT.OBJ" : $(SOURCE) $(DEP_CPP_CRYPT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_CRYPT=\
	".\..\crypt.h"\
	".\..\bnlib\bnstub.h"\
	

"$(INTDIR)\CRYPT.OBJ" : $(SOURCE) $(DEP_CPP_CRYPT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_SHA.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_S=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_SHA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_S) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_S=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	

"$(INTDIR)\LIB_SHA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_S) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_SAFR.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_SA=\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	".\..\testsafr.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_SAFR.OBJ" : $(SOURCE) $(DEP_CPP_LIB_SA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_SA=\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	".\..\testsafr.h"\
	

"$(INTDIR)\LIB_SAFR.OBJ" : $(SOURCE) $(DEP_CPP_LIB_SA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RSA.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_R=\
	".\..\crypt.h"\
	".\..\bnlib\bnstub.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_RSA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_R) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_R=\
	".\..\crypt.h"\
	".\..\bnlib\bnstub.h"\
	

"$(INTDIR)\LIB_RSA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_R) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC5.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_RC=\
	".\..\crypt.h"\
	".\..\rc5\rc5.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_RC5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_RC=\
	".\..\crypt.h"\
	".\..\rc5\rc5.h"\
	

"$(INTDIR)\LIB_RC5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC4.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_RC4=\
	".\..\crypt.h"\
	".\..\rc4\rc4.h"\
	".\..\testrc4.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_RC4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_RC4=\
	".\..\crypt.h"\
	".\..\rc4\rc4.h"\
	".\..\testrc4.h"\
	

"$(INTDIR)\LIB_RC4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC2.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_RC2=\
	".\..\crypt.h"\
	".\..\rc2\rc2.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_RC2.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC2) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_RC2=\
	".\..\crypt.h"\
	".\..\rc2\rc2.h"\
	

"$(INTDIR)\LIB_RC2.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC2) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_NULL.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_N=\
	".\..\crypt.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_NULL.OBJ" : $(SOURCE) $(DEP_CPP_LIB_N) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_N=\
	".\..\crypt.h"\
	

"$(INTDIR)\LIB_NULL.OBJ" : $(SOURCE) $(DEP_CPP_LIB_N) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MDC.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_M=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_MDC.OBJ" : $(SOURCE) $(DEP_CPP_LIB_M) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_M=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	

"$(INTDIR)\LIB_MDC.OBJ" : $(SOURCE) $(DEP_CPP_LIB_M) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MD5.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_MD=\
	".\..\crypt.h"\
	".\..\md5\md5.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_MD5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_MD=\
	".\..\crypt.h"\
	".\..\md5\md5.h"\
	

"$(INTDIR)\LIB_MD5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MD4.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_MD4=\
	".\..\crypt.h"\
	".\..\md4\md4.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_MD4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_MD4=\
	".\..\crypt.h"\
	".\..\md4\md4.h"\
	

"$(INTDIR)\LIB_MD4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_IDEA.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_I=\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	".\..\testidea.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_IDEA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_I) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_I=\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	".\..\testidea.h"\
	

"$(INTDIR)\LIB_IDEA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_I) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_DES.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_D=\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	".\..\testdes.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_D) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_D=\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	".\..\testdes.h"\
	

"$(INTDIR)\LIB_DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_D) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_BLOW.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_B=\
	".\..\crypt.h"\
	".\..\blowfish\blowfish.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_BLOW.OBJ" : $(SOURCE) $(DEP_CPP_LIB_B) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_B=\
	".\..\crypt.h"\
	".\..\blowfish\blowfish.h"\
	

"$(INTDIR)\LIB_BLOW.OBJ" : $(SOURCE) $(DEP_CPP_LIB_B) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_3DES.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_LIB_3=\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	

"$(INTDIR)\LIB_3DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_3) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_LIB_3=\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	

"$(INTDIR)\LIB_3DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_3) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\BLOWFISH\BLOWFISH.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_BLOWF=\
	".\..\crypt.h"\
	".\..\blowfish\blowfish.h"\
	".\..\BLOWFISH\bf_init.c"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_BLOWF=\
	".\..\BLOWFISH\crypt.h"\
	".\..\BLOWFISH\blowfish\blowfish.h"\
	".\..\BLOWFISH\blowfish\bf_init.c"\
	

"$(INTDIR)\BLOWFISH.OBJ" : $(SOURCE) $(DEP_CPP_BLOWF) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_BLOWF=\
	".\..\crypt.h"\
	".\..\blowfish\blowfish.h"\
	".\..\BLOWFISH\bf_init.c"\
	
NODEP_CPP_BLOWF=\
	".\..\BLOWFISH\crypt.h"\
	".\..\BLOWFISH\blowfish\blowfish.h"\
	".\..\BLOWFISH\blowfish\bf_init.c"\
	

"$(INTDIR)\BLOWFISH.OBJ" : $(SOURCE) $(DEP_CPP_BLOWF) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\IDEA\IDEA.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_IDEA_=\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_IDEA_=\
	".\..\IDEA\crypt.h"\
	".\..\IDEA\idea\idea.h"\
	

"$(INTDIR)\IDEA.OBJ" : $(SOURCE) $(DEP_CPP_IDEA_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_IDEA_=\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	
NODEP_CPP_IDEA_=\
	".\..\IDEA\crypt.h"\
	".\..\IDEA\idea\idea.h"\
	

"$(INTDIR)\IDEA.OBJ" : $(SOURCE) $(DEP_CPP_IDEA_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\SET_KEY.C
DEP_CPP_SET_K=\
	".\..\LIBDES\des_locl.h"\
	".\..\LIBDES\podd.h"\
	".\..\LIBDES\sk.h"\
	".\..\libdes\des.h"\
	
NODEP_CPP_SET_K=\
	".\..\LIBDES\libdes\des_locl.h"\
	".\..\LIBDES\libdes\podd.h"\
	".\..\LIBDES\libdes\sk.h"\
	".\..\LIBDES\libdes\des.h"\
	

"$(INTDIR)\SET_KEY.OBJ" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\ECB3_ENC.C
DEP_CPP_ECB3_=\
	".\..\LIBDES\des_locl.h"\
	".\..\libdes\des.h"\
	
NODEP_CPP_ECB3_=\
	".\..\LIBDES\libdes\des_locl.h"\
	".\..\LIBDES\libdes\des.h"\
	

"$(INTDIR)\ECB3_ENC.OBJ" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\ECB_ENC.C
DEP_CPP_ECB_E=\
	".\..\LIBDES\des_locl.h"\
	".\..\LIBDES\spr.h"\
	".\..\libdes\des.h"\
	
NODEP_CPP_ECB_E=\
	".\..\LIBDES\libdes\des_locl.h"\
	".\..\LIBDES\libdes\spr.h"\
	".\..\LIBDES\libdes\des.h"\
	

"$(INTDIR)\ECB_ENC.OBJ" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\MD4\MD4.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_MD4_C=\
	".\..\crypt.h"\
	".\..\md4\md4.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_MD4_C=\
	".\..\MD4\crypt.h"\
	".\..\MD4\md4\md4.h"\
	

"$(INTDIR)\MD4.OBJ" : $(SOURCE) $(DEP_CPP_MD4_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_MD4_C=\
	".\..\crypt.h"\
	".\..\md4\md4.h"\
	
NODEP_CPP_MD4_C=\
	".\..\MD4\crypt.h"\
	".\..\MD4\md4\md4.h"\
	

"$(INTDIR)\MD4.OBJ" : $(SOURCE) $(DEP_CPP_MD4_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\MD5\MD5.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_MD5_C=\
	".\..\crypt.h"\
	".\..\md5\md5.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_MD5_C=\
	".\..\MD5\crypt.h"\
	".\..\MD5\md5\md5.h"\
	

"$(INTDIR)\MD5.OBJ" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_MD5_C=\
	".\..\crypt.h"\
	".\..\md5\md5.h"\
	
NODEP_CPP_MD5_C=\
	".\..\MD5\crypt.h"\
	".\..\MD5\md5\md5.h"\
	

"$(INTDIR)\MD5.OBJ" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\RC2\RC2.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_RC2_C=\
	".\..\crypt.h"\
	".\..\rc2\rc2.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_RC2_C=\
	".\..\RC2\crypt.h"\
	".\..\RC2\rc2\rc2.h"\
	

"$(INTDIR)\RC2.OBJ" : $(SOURCE) $(DEP_CPP_RC2_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_RC2_C=\
	".\..\crypt.h"\
	".\..\rc2\rc2.h"\
	
NODEP_CPP_RC2_C=\
	".\..\RC2\crypt.h"\
	".\..\RC2\rc2\rc2.h"\
	

"$(INTDIR)\RC2.OBJ" : $(SOURCE) $(DEP_CPP_RC2_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\RC4\RC4.C
DEP_CPP_RC4_C=\
	".\..\rc4\rc4.h"\
	
NODEP_CPP_RC4_C=\
	".\..\RC4\rc4\rc4.h"\
	

"$(INTDIR)\RC4.OBJ" : $(SOURCE) $(DEP_CPP_RC4_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\RC5\RC5.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_RC5_C=\
	".\..\crypt.h"\
	".\..\rc5\rc5.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_RC5_C=\
	".\..\RC5\crypt.h"\
	".\..\RC5\rc5\rc5.h"\
	

"$(INTDIR)\RC5.OBJ" : $(SOURCE) $(DEP_CPP_RC5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_RC5_C=\
	".\..\crypt.h"\
	".\..\rc5\rc5.h"\
	
NODEP_CPP_RC5_C=\
	".\..\RC5\crypt.h"\
	".\..\RC5\rc5\rc5.h"\
	

"$(INTDIR)\RC5.OBJ" : $(SOURCE) $(DEP_CPP_RC5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\SAFER\SAFER.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_SAFER=\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_SAFER=\
	".\..\SAFER\crypt.h"\
	".\..\SAFER\safer\safer.h"\
	

"$(INTDIR)\SAFER.OBJ" : $(SOURCE) $(DEP_CPP_SAFER) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_SAFER=\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	
NODEP_CPP_SAFER=\
	".\..\SAFER\crypt.h"\
	".\..\SAFER\safer\safer.h"\
	

"$(INTDIR)\SAFER.OBJ" : $(SOURCE) $(DEP_CPP_SAFER) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\SHA\SHS.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_SHS_C=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	".\..\capi.h"\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_SHS_C=\
	".\..\SHA\crypt.h"\
	".\..\SHA\sha\shs.h"\
	

"$(INTDIR)\SHS.OBJ" : $(SOURCE) $(DEP_CPP_SHS_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_SHS_C=\
	".\..\crypt.h"\
	".\..\sha\shs.h"\
	
NODEP_CPP_SHS_C=\
	".\..\SHA\crypt.h"\
	".\..\SHA\sha\shs.h"\
	

"$(INTDIR)\SHS.OBJ" : $(SOURCE) $(DEP_CPP_SHS_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\WINDOWS\CRYPT32.RC

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

NODEP_RSC_CRYPT3=\
	".\Release\file"\
	

"$(INTDIR)\CRYPT32.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/CRYPT32.res" /i "\WINDOWS" /d "NDEBUG"\
 $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

NODEP_RSC_CRYPT3=\
	".\Debug\file"\
	

"$(INTDIR)\CRYPT32.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/CRYPT32.res" /i "\WINDOWS" /d "_DEBUG"\
 $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\WINDOWS\CRYPT32.DEF

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
