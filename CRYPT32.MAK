# Microsoft Developer Studio Generated NMAKE File, Format Version 4.10
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
	-@erase "$(INTDIR)\ASN1.OBJ"
	-@erase "$(INTDIR)\ASN1KEYS.OBJ"
	-@erase "$(INTDIR)\ASN1OBJS.OBJ"
	-@erase "$(INTDIR)\BLOWFISH.OBJ"
	-@erase "$(INTDIR)\BN.OBJ"
	-@erase "$(INTDIR)\BN00.OBJ"
	-@erase "$(INTDIR)\CRYPT.OBJ"
	-@erase "$(INTDIR)\CRYPT32.res"
	-@erase "$(INTDIR)\CRYPTAPI.OBJ"
	-@erase "$(INTDIR)\CRYPTCAP.OBJ"
	-@erase "$(INTDIR)\CRYPTDBX.OBJ"
	-@erase "$(INTDIR)\CRYPTOBJ.OBJ"
	-@erase "$(INTDIR)\ECB3_ENC.OBJ"
	-@erase "$(INTDIR)\ECB_ENC.OBJ"
	-@erase "$(INTDIR)\IDEA.OBJ"
	-@erase "$(INTDIR)\LBN00.OBJ"
	-@erase "$(INTDIR)\LBNMEM.OBJ"
	-@erase "$(INTDIR)\LEGAL.OBJ"
	-@erase "$(INTDIR)\LIB_3DES.OBJ"
	-@erase "$(INTDIR)\LIB_BLOW.OBJ"
	-@erase "$(INTDIR)\LIB_CERT.OBJ"
	-@erase "$(INTDIR)\LIB_DES.OBJ"
	-@erase "$(INTDIR)\LIB_DH.OBJ"
	-@erase "$(INTDIR)\LIB_DSA.OBJ"
	-@erase "$(INTDIR)\LIB_IDEA.OBJ"
	-@erase "$(INTDIR)\LIB_MD2.OBJ"
	-@erase "$(INTDIR)\LIB_MD4.OBJ"
	-@erase "$(INTDIR)\LIB_MD5.OBJ"
	-@erase "$(INTDIR)\LIB_MDC.OBJ"
	-@erase "$(INTDIR)\LIB_NULL.OBJ"
	-@erase "$(INTDIR)\LIB_PKCS.OBJ"
	-@erase "$(INTDIR)\LIB_RAND.OBJ"
	-@erase "$(INTDIR)\LIB_RC2.OBJ"
	-@erase "$(INTDIR)\LIB_RC4.OBJ"
	-@erase "$(INTDIR)\LIB_RC5.OBJ"
	-@erase "$(INTDIR)\LIB_RIPE.OBJ"
	-@erase "$(INTDIR)\LIB_RSA.OBJ"
	-@erase "$(INTDIR)\LIB_SAFR.OBJ"
	-@erase "$(INTDIR)\LIB_SHA.OBJ"
	-@erase "$(INTDIR)\MD2.OBJ"
	-@erase "$(INTDIR)\MD4.OBJ"
	-@erase "$(INTDIR)\MD5.OBJ"
	-@erase "$(INTDIR)\PGP_IDEA.OBJ"
	-@erase "$(INTDIR)\PGP_KEY.OBJ"
	-@erase "$(INTDIR)\RC2.OBJ"
	-@erase "$(INTDIR)\RC4.OBJ"
	-@erase "$(INTDIR)\RC5.OBJ"
	-@erase "$(INTDIR)\RIPEMD.OBJ"
	-@erase "$(INTDIR)\SAFER.OBJ"
	-@erase "$(INTDIR)\SET_KEY.OBJ"
	-@erase "$(INTDIR)\SHA.OBJ"
	-@erase "$(INTDIR)\SHA1.OBJ"
	-@erase "$(INTDIR)\STREAM.OBJ"
	-@erase "$(INTDIR)\X509_KEY.OBJ"
	-@erase "$(OUTDIR)\CRYPT32.dll"
	-@erase "$(OUTDIR)\CRYPT32.exp"
	-@erase "$(OUTDIR)\CRYPT32.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

F90=fl32.exe
# ADD BASE F90 /I "Release/"
# ADD F90 /I "Release/"
F90_OBJS=.\Release/
F90_PROJ=/I "Release/" /Fo"Release/" 

.for{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f90{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /O2 /D "NDEBUG" /D HAVE_CONFIG_H=1 /D BNINCLUDE=lbn80386.h /D "INC_CHILD" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /MD /W3 /O2 /D "NDEBUG" /D HAVE_CONFIG_H=1 /D\
 BNINCLUDE=lbn80386.h /D "INC_CHILD" /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
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
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib odbc32.lib /nologo /subsystem:windows /dll /pdb:none /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib odbc32.lib /nologo /subsystem:windows /dll\
 /pdb:none /machine:I386 /out:"$(OUTDIR)/CRYPT32.dll"\
 /implib:"$(OUTDIR)/CRYPT32.lib" 
LINK32_OBJS= \
	"$(INTDIR)\ASN1.OBJ" \
	"$(INTDIR)\ASN1KEYS.OBJ" \
	"$(INTDIR)\ASN1OBJS.OBJ" \
	"$(INTDIR)\BLOWFISH.OBJ" \
	"$(INTDIR)\BN.OBJ" \
	"$(INTDIR)\BN00.OBJ" \
	"$(INTDIR)\CRYPT.OBJ" \
	"$(INTDIR)\CRYPT32.res" \
	"$(INTDIR)\CRYPTAPI.OBJ" \
	"$(INTDIR)\CRYPTCAP.OBJ" \
	"$(INTDIR)\CRYPTDBX.OBJ" \
	"$(INTDIR)\CRYPTOBJ.OBJ" \
	"$(INTDIR)\ECB3_ENC.OBJ" \
	"$(INTDIR)\ECB_ENC.OBJ" \
	"$(INTDIR)\IDEA.OBJ" \
	"$(INTDIR)\LBN00.OBJ" \
	"$(INTDIR)\LBNMEM.OBJ" \
	"$(INTDIR)\LEGAL.OBJ" \
	"$(INTDIR)\LIB_3DES.OBJ" \
	"$(INTDIR)\LIB_BLOW.OBJ" \
	"$(INTDIR)\LIB_CERT.OBJ" \
	"$(INTDIR)\LIB_DES.OBJ" \
	"$(INTDIR)\LIB_DH.OBJ" \
	"$(INTDIR)\LIB_DSA.OBJ" \
	"$(INTDIR)\LIB_IDEA.OBJ" \
	"$(INTDIR)\LIB_MD2.OBJ" \
	"$(INTDIR)\LIB_MD4.OBJ" \
	"$(INTDIR)\LIB_MD5.OBJ" \
	"$(INTDIR)\LIB_MDC.OBJ" \
	"$(INTDIR)\LIB_NULL.OBJ" \
	"$(INTDIR)\LIB_PKCS.OBJ" \
	"$(INTDIR)\LIB_RAND.OBJ" \
	"$(INTDIR)\LIB_RC2.OBJ" \
	"$(INTDIR)\LIB_RC4.OBJ" \
	"$(INTDIR)\LIB_RC5.OBJ" \
	"$(INTDIR)\LIB_RIPE.OBJ" \
	"$(INTDIR)\LIB_RSA.OBJ" \
	"$(INTDIR)\LIB_SAFR.OBJ" \
	"$(INTDIR)\LIB_SHA.OBJ" \
	"$(INTDIR)\MD2.OBJ" \
	"$(INTDIR)\MD4.OBJ" \
	"$(INTDIR)\MD5.OBJ" \
	"$(INTDIR)\PGP_IDEA.OBJ" \
	"$(INTDIR)\PGP_KEY.OBJ" \
	"$(INTDIR)\RC2.OBJ" \
	"$(INTDIR)\RC4.OBJ" \
	"$(INTDIR)\RC5.OBJ" \
	"$(INTDIR)\RIPEMD.OBJ" \
	"$(INTDIR)\SAFER.OBJ" \
	"$(INTDIR)\SET_KEY.OBJ" \
	"$(INTDIR)\SHA.OBJ" \
	"$(INTDIR)\SHA1.OBJ" \
	"$(INTDIR)\STREAM.OBJ" \
	"$(INTDIR)\X509_KEY.OBJ" \
	"\BNLIB\LBN80386.OBJ"

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
	-@erase "$(INTDIR)\ASN1.OBJ"
	-@erase "$(INTDIR)\ASN1KEYS.OBJ"
	-@erase "$(INTDIR)\ASN1OBJS.OBJ"
	-@erase "$(INTDIR)\BLOWFISH.OBJ"
	-@erase "$(INTDIR)\BN.OBJ"
	-@erase "$(INTDIR)\BN00.OBJ"
	-@erase "$(INTDIR)\CRYPT.OBJ"
	-@erase "$(INTDIR)\CRYPT32.res"
	-@erase "$(INTDIR)\CRYPTAPI.OBJ"
	-@erase "$(INTDIR)\CRYPTCAP.OBJ"
	-@erase "$(INTDIR)\CRYPTDBX.OBJ"
	-@erase "$(INTDIR)\CRYPTOBJ.OBJ"
	-@erase "$(INTDIR)\ECB3_ENC.OBJ"
	-@erase "$(INTDIR)\ECB_ENC.OBJ"
	-@erase "$(INTDIR)\IDEA.OBJ"
	-@erase "$(INTDIR)\LBN00.OBJ"
	-@erase "$(INTDIR)\LBNMEM.OBJ"
	-@erase "$(INTDIR)\LEGAL.OBJ"
	-@erase "$(INTDIR)\LIB_3DES.OBJ"
	-@erase "$(INTDIR)\LIB_BLOW.OBJ"
	-@erase "$(INTDIR)\LIB_CERT.OBJ"
	-@erase "$(INTDIR)\LIB_DES.OBJ"
	-@erase "$(INTDIR)\LIB_DH.OBJ"
	-@erase "$(INTDIR)\LIB_DSA.OBJ"
	-@erase "$(INTDIR)\LIB_IDEA.OBJ"
	-@erase "$(INTDIR)\LIB_MD2.OBJ"
	-@erase "$(INTDIR)\LIB_MD4.OBJ"
	-@erase "$(INTDIR)\LIB_MD5.OBJ"
	-@erase "$(INTDIR)\LIB_MDC.OBJ"
	-@erase "$(INTDIR)\LIB_NULL.OBJ"
	-@erase "$(INTDIR)\LIB_PKCS.OBJ"
	-@erase "$(INTDIR)\LIB_RAND.OBJ"
	-@erase "$(INTDIR)\LIB_RC2.OBJ"
	-@erase "$(INTDIR)\LIB_RC4.OBJ"
	-@erase "$(INTDIR)\LIB_RC5.OBJ"
	-@erase "$(INTDIR)\LIB_RIPE.OBJ"
	-@erase "$(INTDIR)\LIB_RSA.OBJ"
	-@erase "$(INTDIR)\LIB_SAFR.OBJ"
	-@erase "$(INTDIR)\LIB_SHA.OBJ"
	-@erase "$(INTDIR)\MD2.OBJ"
	-@erase "$(INTDIR)\MD4.OBJ"
	-@erase "$(INTDIR)\MD5.OBJ"
	-@erase "$(INTDIR)\PGP_IDEA.OBJ"
	-@erase "$(INTDIR)\PGP_KEY.OBJ"
	-@erase "$(INTDIR)\RC2.OBJ"
	-@erase "$(INTDIR)\RC4.OBJ"
	-@erase "$(INTDIR)\RC5.OBJ"
	-@erase "$(INTDIR)\RIPEMD.OBJ"
	-@erase "$(INTDIR)\SAFER.OBJ"
	-@erase "$(INTDIR)\SET_KEY.OBJ"
	-@erase "$(INTDIR)\SHA.OBJ"
	-@erase "$(INTDIR)\SHA1.OBJ"
	-@erase "$(INTDIR)\STREAM.OBJ"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(INTDIR)\X509_KEY.OBJ"
	-@erase "$(OUTDIR)\CRYPT32.dll"
	-@erase "$(OUTDIR)\CRYPT32.exp"
	-@erase "$(OUTDIR)\CRYPT32.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
F90_OBJS=.\Debug/
F90_PROJ=/I "Release/" /Fo"Release/" 

.for{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f90{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /Gm /Zi /Od /D "_DEBUG" /D HAVE_CONFIG_H=1 /D BNINCLUDE=lbn80386.h /D "INC_CHILD" /c
# SUBTRACT CPP /YX
CPP_PROJ=/nologo /MD /W3 /Gm /Zi /Od /D "_DEBUG" /D HAVE_CONFIG_H=1 /D\
 BNINCLUDE=lbn80386.h /D "INC_CHILD" /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
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
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib odbc32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib odbc32.lib /nologo /subsystem:windows /dll\
 /pdb:none /debug /machine:I386 /out:"$(OUTDIR)/CRYPT32.dll"\
 /implib:"$(OUTDIR)/CRYPT32.lib" 
LINK32_OBJS= \
	"$(INTDIR)\ASN1.OBJ" \
	"$(INTDIR)\ASN1KEYS.OBJ" \
	"$(INTDIR)\ASN1OBJS.OBJ" \
	"$(INTDIR)\BLOWFISH.OBJ" \
	"$(INTDIR)\BN.OBJ" \
	"$(INTDIR)\BN00.OBJ" \
	"$(INTDIR)\CRYPT.OBJ" \
	"$(INTDIR)\CRYPT32.res" \
	"$(INTDIR)\CRYPTAPI.OBJ" \
	"$(INTDIR)\CRYPTCAP.OBJ" \
	"$(INTDIR)\CRYPTDBX.OBJ" \
	"$(INTDIR)\CRYPTOBJ.OBJ" \
	"$(INTDIR)\ECB3_ENC.OBJ" \
	"$(INTDIR)\ECB_ENC.OBJ" \
	"$(INTDIR)\IDEA.OBJ" \
	"$(INTDIR)\LBN00.OBJ" \
	"$(INTDIR)\LBNMEM.OBJ" \
	"$(INTDIR)\LEGAL.OBJ" \
	"$(INTDIR)\LIB_3DES.OBJ" \
	"$(INTDIR)\LIB_BLOW.OBJ" \
	"$(INTDIR)\LIB_CERT.OBJ" \
	"$(INTDIR)\LIB_DES.OBJ" \
	"$(INTDIR)\LIB_DH.OBJ" \
	"$(INTDIR)\LIB_DSA.OBJ" \
	"$(INTDIR)\LIB_IDEA.OBJ" \
	"$(INTDIR)\LIB_MD2.OBJ" \
	"$(INTDIR)\LIB_MD4.OBJ" \
	"$(INTDIR)\LIB_MD5.OBJ" \
	"$(INTDIR)\LIB_MDC.OBJ" \
	"$(INTDIR)\LIB_NULL.OBJ" \
	"$(INTDIR)\LIB_PKCS.OBJ" \
	"$(INTDIR)\LIB_RAND.OBJ" \
	"$(INTDIR)\LIB_RC2.OBJ" \
	"$(INTDIR)\LIB_RC4.OBJ" \
	"$(INTDIR)\LIB_RC5.OBJ" \
	"$(INTDIR)\LIB_RIPE.OBJ" \
	"$(INTDIR)\LIB_RSA.OBJ" \
	"$(INTDIR)\LIB_SAFR.OBJ" \
	"$(INTDIR)\LIB_SHA.OBJ" \
	"$(INTDIR)\MD2.OBJ" \
	"$(INTDIR)\MD4.OBJ" \
	"$(INTDIR)\MD5.OBJ" \
	"$(INTDIR)\PGP_IDEA.OBJ" \
	"$(INTDIR)\PGP_KEY.OBJ" \
	"$(INTDIR)\RC2.OBJ" \
	"$(INTDIR)\RC4.OBJ" \
	"$(INTDIR)\RC5.OBJ" \
	"$(INTDIR)\RIPEMD.OBJ" \
	"$(INTDIR)\SAFER.OBJ" \
	"$(INTDIR)\SET_KEY.OBJ" \
	"$(INTDIR)\SHA.OBJ" \
	"$(INTDIR)\SHA1.OBJ" \
	"$(INTDIR)\STREAM.OBJ" \
	"$(INTDIR)\X509_KEY.OBJ" \
	"\BNLIB\LBN80386.OBJ"

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
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_CRYPT=\
	"\bn.h"\
	

"$(INTDIR)\CRYPT.OBJ" : $(SOURCE) $(DEP_CPP_CRYPT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_CRYPT=\
	".\..\crypt.h"\
	

"$(INTDIR)\CRYPT.OBJ" : $(SOURCE) $(DEP_CPP_CRYPT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_SHA.C
DEP_CPP_LIB_S=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\sha.h"\
	
NODEP_CPP_LIB_S=\
	"\bn.h"\
	"\sha.h"\
	

"$(INTDIR)\LIB_SHA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_S) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_SAFR.C
DEP_CPP_LIB_SA=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	".\..\testsafr.h"\
	
NODEP_CPP_LIB_SA=\
	"\bn.h"\
	"\safer.h"\
	

"$(INTDIR)\LIB_SAFR.OBJ" : $(SOURCE) $(DEP_CPP_LIB_SA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RSA.C
DEP_CPP_LIB_R=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_LIB_R=\
	"\bn.h"\
	

"$(INTDIR)\LIB_RSA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_R) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC5.C
DEP_CPP_LIB_RC=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\rc\rc5.h"\
	
NODEP_CPP_LIB_RC=\
	"\bn.h"\
	"\rc5.h"\
	

"$(INTDIR)\LIB_RC5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC4.C
DEP_CPP_LIB_RC4=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\rc\rc4.h"\
	".\..\testrc4.h"\
	
NODEP_CPP_LIB_RC4=\
	"\bn.h"\
	"\rc4.h"\
	

"$(INTDIR)\LIB_RC4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RC2.C
DEP_CPP_LIB_RC2=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\rc\rc2.h"\
	
NODEP_CPP_LIB_RC2=\
	"\bn.h"\
	"\rc2.h"\
	

"$(INTDIR)\LIB_RC2.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RC2) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_NULL.C
DEP_CPP_LIB_N=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_LIB_N=\
	"\bn.h"\
	

"$(INTDIR)\LIB_NULL.OBJ" : $(SOURCE) $(DEP_CPP_LIB_N) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MDC.C
DEP_CPP_LIB_M=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\sha.h"\
	
NODEP_CPP_LIB_M=\
	"\bn.h"\
	"\sha.h"\
	

"$(INTDIR)\LIB_MDC.OBJ" : $(SOURCE) $(DEP_CPP_LIB_M) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MD5.C
DEP_CPP_LIB_MD=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\md5.h"\
	
NODEP_CPP_LIB_MD=\
	"\bn.h"\
	"\md5.h"\
	

"$(INTDIR)\LIB_MD5.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MD4.C
DEP_CPP_LIB_MD4=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\md4.h"\
	
NODEP_CPP_LIB_MD4=\
	"\bn.h"\
	"\md4.h"\
	

"$(INTDIR)\LIB_MD4.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_IDEA.C
DEP_CPP_LIB_I=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	".\..\testidea.h"\
	
NODEP_CPP_LIB_I=\
	"\bn.h"\
	"\idea.h"\
	

"$(INTDIR)\LIB_IDEA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_I) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_DES.C
DEP_CPP_LIB_D=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	".\..\testdes.h"\
	
NODEP_CPP_LIB_D=\
	"\bn.h"\
	"\des.h"\
	

"$(INTDIR)\LIB_DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_D) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_BLOW.C
DEP_CPP_LIB_B=\
	".\..\blowfish\blowfish.h"\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_LIB_B=\
	"\blowfish.h"\
	"\bn.h"\
	

"$(INTDIR)\LIB_BLOW.OBJ" : $(SOURCE) $(DEP_CPP_LIB_B) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_3DES.C
DEP_CPP_LIB_3=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\libdes\des.h"\
	
NODEP_CPP_LIB_3=\
	"\bn.h"\
	"\des.h"\
	

"$(INTDIR)\LIB_3DES.OBJ" : $(SOURCE) $(DEP_CPP_LIB_3) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BLOWFISH\BLOWFISH.C
DEP_CPP_BLOWF=\
	".\..\BLOWFISH\bf_init.c"\
	".\..\blowfish\blowfish.h"\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_BLOWF=\
	".\..\BLOWFISH\blowfish\bf_init.c"\
	".\..\BLOWFISH\blowfish\blowfish.h"\
	".\..\BLOWFISH\crypt.h"\
	"\bn.h"\
	

"$(INTDIR)\BLOWFISH.OBJ" : $(SOURCE) $(DEP_CPP_BLOWF) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\IDEA\IDEA.C
DEP_CPP_IDEA_=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\idea\idea.h"\
	
NODEP_CPP_IDEA_=\
	".\..\IDEA\crypt.h"\
	".\..\IDEA\idea\idea.h"\
	"\bn.h"\
	

"$(INTDIR)\IDEA.OBJ" : $(SOURCE) $(DEP_CPP_IDEA_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\SET_KEY.C
DEP_CPP_SET_K=\
	".\..\libdes\des.h"\
	".\..\LIBDES\des_locl.h"\
	".\..\LIBDES\podd.h"\
	".\..\LIBDES\sk.h"\
	
NODEP_CPP_SET_K=\
	".\..\LIBDES\libdes\des.h"\
	".\..\LIBDES\libdes\des_locl.h"\
	".\..\LIBDES\libdes\podd.h"\
	".\..\LIBDES\libdes\sk.h"\
	"\LIBDES\crypt.h"\
	

"$(INTDIR)\SET_KEY.OBJ" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\ECB3_ENC.C
DEP_CPP_ECB3_=\
	".\..\libdes\des.h"\
	".\..\LIBDES\des_locl.h"\
	
NODEP_CPP_ECB3_=\
	".\..\LIBDES\libdes\des.h"\
	".\..\LIBDES\libdes\des_locl.h"\
	"\LIBDES\crypt.h"\
	

"$(INTDIR)\ECB3_ENC.OBJ" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIBDES\ECB_ENC.C
DEP_CPP_ECB_E=\
	".\..\libdes\des.h"\
	".\..\LIBDES\des_locl.h"\
	".\..\LIBDES\spr.h"\
	
NODEP_CPP_ECB_E=\
	".\..\LIBDES\libdes\des.h"\
	".\..\LIBDES\libdes\des_locl.h"\
	".\..\LIBDES\libdes\spr.h"\
	"\LIBDES\crypt.h"\
	

"$(INTDIR)\ECB_ENC.OBJ" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\SAFER\SAFER.C
DEP_CPP_SAFER=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\safer\safer.h"\
	
NODEP_CPP_SAFER=\
	".\..\SAFER\crypt.h"\
	".\..\SAFER\safer\safer.h"\
	"\bn.h"\
	

"$(INTDIR)\SAFER.OBJ" : $(SOURCE) $(DEP_CPP_SAFER) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\CRYPT32.RC

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

NODEP_RSC_CRYPT3=\
	".\Release\file"\
	

"$(INTDIR)\CRYPT32.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

NODEP_RSC_CRYPT3=\
	".\Debug\file"\
	

"$(INTDIR)\CRYPT32.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_PKCS.C
DEP_CPP_LIB_P=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_LIB_P=\
	"\asn1objs.h"\
	"\bn.h"\
	

"$(INTDIR)\LIB_PKCS.OBJ" : $(SOURCE) $(DEP_CPP_LIB_P) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\BN.C
DEP_CPP_BN_C17=\
	".\..\bnlib\bn.h"\
	
NODEP_CPP_BN_C17=\
	".\..\BNLIB\bnlib\bn.h"\
	

"$(INTDIR)\BN.OBJ" : $(SOURCE) $(DEP_CPP_BN_C17) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\BN00.C
DEP_CPP_BN00_=\
	".\..\bnlib\bn.h"\
	".\..\BNLIB\bn16.c"\
	".\..\BNLIB\bn16.h"\
	".\..\BNLIB\bn32.c"\
	".\..\BNLIB\bn32.h"\
	".\..\BNLIB\bn64.c"\
	".\..\BNLIB\bn64.h"\
	".\..\BNLIB\bninit16.c"\
	".\..\BNLIB\bninit32.c"\
	".\..\BNLIB\bninit64.c"\
	".\..\BNLIB\bnsize00.h"\
	".\..\BNLIB\config.h"\
	".\..\BNLIB\kludge.h"\
	".\..\BNLIB\lbn.h"\
	".\..\BNLIB\lbn16.h"\
	".\..\BNLIB\lbn32.h"\
	".\..\BNLIB\lbn64.h"\
	".\..\BNLIB\lbnmem.h"\
	
NODEP_CPP_BN00_=\
	".\..\BNLIB\bnlib\bn.h"\
	".\..\BNLIB\bnlib\bn16.c"\
	".\..\BNLIB\bnlib\bn16.h"\
	".\..\BNLIB\bnlib\bn32.c"\
	".\..\BNLIB\bnlib\bn32.h"\
	".\..\BNLIB\bnlib\bn64.c"\
	".\..\BNLIB\bnlib\bn64.h"\
	".\..\BNLIB\bnlib\bninit16.c"\
	".\..\BNLIB\bnlib\bninit32.c"\
	".\..\BNLIB\bnlib\bninit64.c"\
	".\..\BNLIB\bnlib\bnsize00.h"\
	".\..\BNLIB\bnlib\config.h"\
	".\..\BNLIB\bnlib\kludge.h"\
	".\..\BNLIB\bnlib\lbn.h"\
	".\..\BNLIB\bnlib\lbn16.h"\
	".\..\BNLIB\bnlib\lbn32.h"\
	".\..\BNLIB\bnlib\lbn64.h"\
	".\..\BNLIB\bnlib\lbnmem.h"\
	".\..\dbmalloc\malloc.h"\
	

"$(INTDIR)\BN00.OBJ" : $(SOURCE) $(DEP_CPP_BN00_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\LBN00.C
DEP_CPP_LBN00=\
	".\..\BNLIB\bnsize00.h"\
	".\..\BNLIB\config.h"\
	".\..\BNLIB\kludge.h"\
	".\..\BNLIB\lbn.h"\
	".\..\BNLIB\lbn16.c"\
	".\..\BNLIB\lbn16.h"\
	".\..\BNLIB\lbn32.c"\
	".\..\BNLIB\lbn32.h"\
	".\..\BNLIB\lbn64.c"\
	".\..\BNLIB\lbn64.h"\
	".\..\BNLIB\lbnmem.h"\
	".\..\BNLIB\legal.h"\
	
NODEP_CPP_LBN00=\
	".\..\BNLIB\bnlib\config.h"\
	".\..\BNLIB\bnlib\kludge.h"\
	".\..\BNLIB\bnlib\lbn.h"\
	".\..\BNLIB\bnlib\lbn16.h"\
	".\..\BNLIB\bnlib\lbn32.h"\
	".\..\BNLIB\bnlib\lbn64.h"\
	".\..\BNLIB\bnlib\lbnmem.h"\
	".\..\BNLIB\bnlib\legal.h"\
	

"$(INTDIR)\LBN00.OBJ" : $(SOURCE) $(DEP_CPP_LBN00) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\LBNMEM.C
DEP_CPP_LBNME=\
	".\..\BNLIB\config.h"\
	".\..\BNLIB\kludge.h"\
	".\..\BNLIB\lbn.h"\
	".\..\BNLIB\lbnmem.h"\
	
NODEP_CPP_LBNME=\
	".\..\BNLIB\bnlib\config.h"\
	".\..\BNLIB\bnlib\kludge.h"\
	".\..\BNLIB\bnlib\lbn.h"\
	".\..\BNLIB\bnlib\lbnmem.h"\
	".\..\dbmalloc\malloc.h"\
	

"$(INTDIR)\LBNMEM.OBJ" : $(SOURCE) $(DEP_CPP_LBNME) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\LEGAL.C
DEP_CPP_LEGAL=\
	".\..\BNLIB\config.h"\
	".\..\BNLIB\legal.h"\
	
NODEP_CPP_LEGAL=\
	".\..\BNLIB\bnlib\config.h"\
	".\..\BNLIB\bnlib\legal.h"\
	

"$(INTDIR)\LEGAL.OBJ" : $(SOURCE) $(DEP_CPP_LEGAL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\BNLIB\LBN80386.OBJ

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\ASN1.C
DEP_CPP_ASN1_=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1.h"\
	".\..\KEYMGMT\ber.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_ASN1_=\
	".\..\keymgmt\crypt.h"\
	".\..\KEYMGMT\keymgmt\asn1.h"\
	".\..\KEYMGMT\keymgmt\ber.h"\
	".\..\keymgmt\keymgmt\stream.h"\
	"\bn.h"\
	

"$(INTDIR)\ASN1.OBJ" : $(SOURCE) $(DEP_CPP_ASN1_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\STREAM.C
DEP_CPP_STREA=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_STREA=\
	".\..\keymgmt\keymgmt\stream.h"\
	"\bn.h"\
	

"$(INTDIR)\STREAM.OBJ" : $(SOURCE) $(DEP_CPP_STREA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RAND.C
DEP_CPP_LIB_RA=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\sha.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_LIB_RA=\
	"\bn.h"\
	"\sha.h"\
	

"$(INTDIR)\LIB_RAND.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_DH.C
DEP_CPP_LIB_DH=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\testdh.h"\
	
NODEP_CPP_LIB_DH=\
	"\bn.h"\
	

"$(INTDIR)\LIB_DH.OBJ" : $(SOURCE) $(DEP_CPP_LIB_DH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\MD4.C
DEP_CPP_MD4_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\md4.h"\
	
NODEP_CPP_MD4_C=\
	".\..\HASH\crypt.h"\
	".\..\HASH\hash\md4.h"\
	"\bn.h"\
	

"$(INTDIR)\MD4.OBJ" : $(SOURCE) $(DEP_CPP_MD4_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\MD5.C
DEP_CPP_MD5_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\md5.h"\
	
NODEP_CPP_MD5_C=\
	".\..\HASH\crypt.h"\
	".\..\HASH\hash\md5.h"\
	"\bn.h"\
	

"$(INTDIR)\MD5.OBJ" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\ASN1KEYS.C

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

DEP_CPP_ASN1K=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1.h"\
	".\..\KEYMGMT\asn1keys.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\ber.h"\
	".\..\keymgmt\stream.h"\
	"\KEYMGMT\asn1oid.h"\
	
NODEP_CPP_ASN1K=\
	".\..\keymgmt\crypt.h"\
	".\..\KEYMGMT\keymgmt\asn1.h"\
	".\..\KEYMGMT\keymgmt\asn1keys.h"\
	".\..\KEYMGMT\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\keymgmt\ber.h"\
	".\..\keymgmt\keymgmt\stream.h"\
	"\bn.h"\
	"\KEYMGMT\keymgmt\asn1oid.h"\
	

"$(INTDIR)\ASN1KEYS.OBJ" : $(SOURCE) $(DEP_CPP_ASN1K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

DEP_CPP_ASN1K=\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1.h"\
	".\..\KEYMGMT\asn1keys.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\ber.h"\
	".\..\keymgmt\stream.h"\
	"\KEYMGMT\asn1oid.h"\
	
NODEP_CPP_ASN1K=\
	".\..\KEYMGMT\keymgmt\asn1.h"\
	".\..\KEYMGMT\keymgmt\asn1keys.h"\
	".\..\KEYMGMT\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\keymgmt\ber.h"\
	".\..\keymgmt\keymgmt\stream.h"\
	"\KEYMGMT\keymgmt\asn1oid.h"\
	

"$(INTDIR)\ASN1KEYS.OBJ" : $(SOURCE) $(DEP_CPP_ASN1K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\CRYPTAPI.C
DEP_CPP_CRYPTA=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\md4.h"\
	".\..\hash\md5.h"\
	".\..\hash\sha.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\keymgmt\stream.h"\
	"\hash\md2.h"\
	"\hash\ripemd.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_CRYPTA=\
	"\asn1objs.h"\
	"\bn.h"\
	"\md2.h"\
	"\md4.h"\
	"\md5.h"\
	"\ripemd.h"\
	"\sha.h"\
	

"$(INTDIR)\CRYPTAPI.OBJ" : $(SOURCE) $(DEP_CPP_CRYPTA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\CRYPTCAP.C
DEP_CPP_CRYPTC=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_CRYPTC=\
	"\bn.h"\
	

"$(INTDIR)\CRYPTCAP.OBJ" : $(SOURCE) $(DEP_CPP_CRYPTC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\RC\RC4.C
DEP_CPP_RC4_C=\
	".\..\rc\rc4.h"\
	
NODEP_CPP_RC4_C=\
	".\..\RC\rc\rc4.h"\
	

"$(INTDIR)\RC4.OBJ" : $(SOURCE) $(DEP_CPP_RC4_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\RC\RC2.C
DEP_CPP_RC2_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\rc\rc2.h"\
	
NODEP_CPP_RC2_C=\
	".\..\RC\crypt.h"\
	".\..\RC\rc\rc2.h"\
	"\bn.h"\
	

"$(INTDIR)\RC2.OBJ" : $(SOURCE) $(DEP_CPP_RC2_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\RC\RC5.C
DEP_CPP_RC5_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\rc\rc5.h"\
	
NODEP_CPP_RC5_C=\
	".\..\RC\crypt.h"\
	".\..\RC\rc\rc5.h"\
	"\bn.h"\
	

"$(INTDIR)\RC5.OBJ" : $(SOURCE) $(DEP_CPP_RC5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\SHA1.C
DEP_CPP_SHA1_=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\sha.h"\
	".\..\HASH\shacore.c"\
	
NODEP_CPP_SHA1_=\
	".\..\HASH\crypt.h"\
	".\..\HASH\hash\sha.h"\
	".\..\HASH\hash\shacore.c"\
	"\bn.h"\
	

"$(INTDIR)\SHA1.OBJ" : $(SOURCE) $(DEP_CPP_SHA1_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\SHA.C
DEP_CPP_SHA_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\hash\sha.h"\
	".\..\HASH\shacore.c"\
	
NODEP_CPP_SHA_C=\
	".\..\HASH\crypt.h"\
	".\..\HASH\hash\sha.h"\
	".\..\HASH\hash\shacore.c"\
	"\bn.h"\
	

"$(INTDIR)\SHA.OBJ" : $(SOURCE) $(DEP_CPP_SHA_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\CRYPTOBJ.C
DEP_CPP_CRYPTO=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_CRYPTO=\
	"\asn1objs.h"\
	"\bn.h"\
	

"$(INTDIR)\CRYPTOBJ.OBJ" : $(SOURCE) $(DEP_CPP_CRYPTO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\ASN1OBJS.C
DEP_CPP_ASN1O=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1.h"\
	".\..\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\ber.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_ASN1O=\
	".\..\KEYMGMT\keymgmt\asn1.h"\
	".\..\KEYMGMT\keymgmt\asn1objs.h"\
	".\..\KEYMGMT\keymgmt\ber.h"\
	".\..\keymgmt\keymgmt\stream.h"\
	"\bn.h"\
	

"$(INTDIR)\ASN1OBJS.OBJ" : $(SOURCE) $(DEP_CPP_ASN1O) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\PGP_IDEA.C
DEP_CPP_PGP_I=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\pgp_idea.h"\
	
NODEP_CPP_PGP_I=\
	".\..\keymgmt\crypt.h"\
	".\..\KEYMGMT\keymgmt\pgp_idea.h"\
	"\bn.h"\
	

"$(INTDIR)\PGP_IDEA.OBJ" : $(SOURCE) $(DEP_CPP_PGP_I) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\CRYPTDBX.C
DEP_CPP_CRYPTD=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\keymgmt\keymgmt.h"\
	
NODEP_CPP_CRYPTD=\
	"\bn.h"\
	"\keymgmt.h"\
	

"$(INTDIR)\CRYPTDBX.OBJ" : $(SOURCE) $(DEP_CPP_CRYPTD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\PGP_KEY.C
DEP_CPP_PGP_K=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\keymgmt\keymgmt.h"\
	".\..\KEYMGMT\pgp_idea.h"\
	
NODEP_CPP_PGP_K=\
	".\..\keymgmt\crypt.h"\
	".\..\KEYMGMT\keymgmt\keymgmt.h"\
	".\..\KEYMGMT\keymgmt\pgp_idea.h"\
	"\bn.h"\
	

"$(INTDIR)\PGP_KEY.OBJ" : $(SOURCE) $(DEP_CPP_PGP_K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\KEYMGMT\X509_KEY.C
DEP_CPP_X509_=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1.h"\
	".\..\KEYMGMT\asn1keys.h"\
	".\..\KEYMGMT\ber.h"\
	".\..\keymgmt\keymgmt.h"\
	".\..\keymgmt\stream.h"\
	"\KEYMGMT\asn1oid.h"\
	
NODEP_CPP_X509_=\
	".\..\KEYMGMT\keymgmt\asn1.h"\
	".\..\KEYMGMT\keymgmt\asn1keys.h"\
	".\..\KEYMGMT\keymgmt\ber.h"\
	".\..\KEYMGMT\keymgmt\keymgmt.h"\
	".\..\keymgmt\keymgmt\stream.h"\
	"\bn.h"\
	"\KEYMGMT\keymgmt\asn1oid.h"\
	

"$(INTDIR)\X509_KEY.OBJ" : $(SOURCE) $(DEP_CPP_X509_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_CERT.C
DEP_CPP_LIB_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	".\..\KEYMGMT\asn1keys.h"\
	".\..\keymgmt\stream.h"\
	
NODEP_CPP_LIB_C=\
	".\..\keymgmt\keymgmt\stream.h"\
	"\asn1keys.h"\
	"\bn.h"\
	

"$(INTDIR)\LIB_CERT.OBJ" : $(SOURCE) $(DEP_CPP_LIB_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_DSA.C
DEP_CPP_LIB_DS=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	
NODEP_CPP_LIB_DS=\
	"\bn.h"\
	

"$(INTDIR)\LIB_DSA.OBJ" : $(SOURCE) $(DEP_CPP_LIB_DS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_MD2.C
DEP_CPP_LIB_MD2=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	"\hash\md2.h"\
	
NODEP_CPP_LIB_MD2=\
	"\bn.h"\
	"\md2.h"\
	

"$(INTDIR)\LIB_MD2.OBJ" : $(SOURCE) $(DEP_CPP_LIB_MD2) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\LIB_RIPE.C
DEP_CPP_LIB_RI=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	"\hash\ripemd.h"\
	
NODEP_CPP_LIB_RI=\
	"\bn.h"\
	"\ripemd.h"\
	

"$(INTDIR)\LIB_RIPE.OBJ" : $(SOURCE) $(DEP_CPP_LIB_RI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\MD2.C
DEP_CPP_MD2_C=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	"\hash\md2.h"\
	
NODEP_CPP_MD2_C=\
	".\..\HASH\crypt.h"\
	"\bn.h"\
	"\HASH\hash\md2.h"\
	

"$(INTDIR)\MD2.OBJ" : $(SOURCE) $(DEP_CPP_MD2_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=\HASH\RIPEMD.C
DEP_CPP_RIPEM=\
	".\..\bnlib\bn.h"\
	".\..\capi.h"\
	".\..\crypt.h"\
	"\hash\ripemd.h"\
	
NODEP_CPP_RIPEM=\
	".\..\HASH\crypt.h"\
	"\bn.h"\
	"\HASH\hash\ripemd.h"\
	

"$(INTDIR)\RIPEMD.OBJ" : $(SOURCE) $(DEP_CPP_RIPEM) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
# End Project
################################################################################
