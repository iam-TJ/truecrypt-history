# Microsoft Visual C++ generated build script - Do not modify

PROJ = CRYPT
DEBUG = 0
PROGTYPE = 1
CALLER = testwin.exe
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = C:\WORK\CRYPT\WINDOWS\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = CRYPT.C     
FIRSTCPP =             
RC = rc
CFLAGS_D_WDLL = /nologo /G2 /W3 /Zi /ALw /Od /D "_DEBUG" /D "__WINDOWS__" /D "HAVE_CONFIG_H" /I "..\." /GD /Fd"CRYPT.PDB"
CFLAGS_R_WDLL = /nologo /G3 /W3 /ALw /O2 /D "NDEBUG" /D "__WINDOWS__" /D "HAVE_CONFIG_H" /GD 
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /CO
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE
LIBS_D_WDLL = oldnames libw ldllcew
LIBS_R_WDLL = oldnames libw ldllcew
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = CRYPT.DEF
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WDLL)
LFLAGS = $(LFLAGS_D_WDLL)
LIBS = $(LIBS_D_WDLL)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WDLL)
LFLAGS = $(LFLAGS_R_WDLL)
LIBS = $(LIBS_R_WDLL)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = CRYPT.SBR \
		LIB_3DES.SBR \
		LIB_BLOW.SBR \
		LIB_DES.SBR \
		LIB_IDEA.SBR \
		LIB_MD4.SBR \
		LIB_MD5.SBR \
		LIB_MDC.SBR \
		LIB_NULL.SBR \
		LIB_RC4.SBR \
		LIB_RC5.SBR \
		LIB_SAFR.SBR \
		LIB_SHA.SBR \
		BLOWFISH.SBR \
		IDEA.SBR \
		ECB_ENC.SBR \
		SET_KEY.SBR \
		MD4.SBR \
		MD5.SBR \
		RC4.SBR \
		RC5.SBR \
		SAFER.SBR \
		SHS.SBR \
		ECB3_ENC.SBR \
		LIB_RSA.SBR \
		RC2.SBR \
		LIB_RC2.SBR


CRYPT_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\bnlib/bnstub.h


LIB_3DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\libdes/des.h


LIB_BLOW_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\blowfish/blowfish.h


LIB_DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\libdes/des.h \
	c:\work\crypt\testdes.h


LIB_IDEA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\idea/idea.h \
	c:\work\crypt\testidea.h


LIB_MD4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\md4/md4.h


LIB_MD5_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\md5/md5.h


LIB_MDC_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\sha/shs.h


LIB_NULL_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h


LIB_RC4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\rc4/rc4.h \
	c:\work\crypt\testrc4.h


LIB_RC5_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\rc5/rc5.h


LIB_SAFR_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\safer/safer.h \
	c:\work\crypt\testsafr.h


LIB_SHA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\sha/shs.h


BLOWFISH_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\blowfish\blowfish.h \
	blowfish/blowfish.h \
	c:\work\crypt\blowfish\bf_init.c \
	blowfish/bf_init.c


IDEA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\idea\idea.h \
	idea/idea.h


ECB_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	c:\work\crypt\libdes\spr.h \
	libdes/des_locl.h \
	libdes/spr.h


SET_KEY_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	c:\work\crypt\libdes\podd.h \
	c:\work\crypt\libdes\sk.h \
	libdes/des_locl.h \
	libdes/podd.h \
	libdes/sk.h


MD4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\md4\md4.h \
	md4/md4.h


MD5_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\md5\md5.h \
	md5/md5.h


RC4_DEP = c:\work\crypt\rc4\rc4.h \
	rc4/rc4.h


RC5_DEP = rc5/rc5.h


SAFER_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\safer\safer.h \
	safer/safer.h


SHS_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\sha\shs.h \
	sha/shs.h


CRYPT_RCDEP = 

ECB3_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	libdes/des_locl.h


LIB_RSA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\bnlib/bnstub.h


RC2_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\rc2\rc2.h \
	rc2/rc2.h


LIB_RC2_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	sys/machine.h \
	sys/isa_defs.h \
	c:\work\crypt\rc2/rc2.h


all:	$(PROJ).DLL

CRYPT.OBJ:	..\CRYPT.C $(CRYPT_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ..\CRYPT.C

LIB_3DES.OBJ:	..\LIB_3DES.C $(LIB_3DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_3DES.C

LIB_BLOW.OBJ:	..\LIB_BLOW.C $(LIB_BLOW_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_BLOW.C

LIB_DES.OBJ:	..\LIB_DES.C $(LIB_DES_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DES.C

LIB_IDEA.OBJ:	..\LIB_IDEA.C $(LIB_IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_IDEA.C

LIB_MD4.OBJ:	..\LIB_MD4.C $(LIB_MD4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD4.C

LIB_MD5.OBJ:	..\LIB_MD5.C $(LIB_MD5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD5.C

LIB_MDC.OBJ:	..\LIB_MDC.C $(LIB_MDC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MDC.C

LIB_NULL.OBJ:	..\LIB_NULL.C $(LIB_NULL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_NULL.C

LIB_RC4.OBJ:	..\LIB_RC4.C $(LIB_RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC4.C

LIB_RC5.OBJ:	..\LIB_RC5.C $(LIB_RC5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC5.C

LIB_SAFR.OBJ:	..\LIB_SAFR.C $(LIB_SAFR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SAFR.C

LIB_SHA.OBJ:	..\LIB_SHA.C $(LIB_SHA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_SHA.C

BLOWFISH.OBJ:	..\BLOWFISH\BLOWFISH.C $(BLOWFISH_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BLOWFISH\BLOWFISH.C

IDEA.OBJ:	..\IDEA\IDEA.C $(IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\IDEA\IDEA.C

ECB_ENC.OBJ:	..\LIBDES\ECB_ENC.C $(ECB_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBDES\ECB_ENC.C

SET_KEY.OBJ:	..\LIBDES\SET_KEY.C $(SET_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBDES\SET_KEY.C

MD4.OBJ:	..\MD4\MD4.C $(MD4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MD4\MD4.C

MD5.OBJ:	..\MD5\MD5.C $(MD5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MD5\MD5.C

RC4.OBJ:	..\RC4\RC4.C $(RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC4\RC4.C

RC5.OBJ:	..\RC5\RC5.C $(RC5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC5\RC5.C

SAFER.OBJ:	..\SAFER\SAFER.C $(SAFER_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SAFER\SAFER.C

SHS.OBJ:	..\SHA\SHS.C $(SHS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SHA\SHS.C

CRYPT.RES:	CRYPT.RC $(CRYPT_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r CRYPT.RC

ECB3_ENC.OBJ:	..\LIBDES\ECB3_ENC.C $(ECB3_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBDES\ECB3_ENC.C

LIB_RSA.OBJ:	..\LIB_RSA.C $(LIB_RSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RSA.C

RC2.OBJ:	..\RC2\RC2.C $(RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC2\RC2.C

LIB_RC2.OBJ:	..\LIB_RC2.C $(LIB_RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC2.C


$(PROJ).DLL::	CRYPT.RES

$(PROJ).DLL::	CRYPT.OBJ LIB_3DES.OBJ LIB_BLOW.OBJ LIB_DES.OBJ LIB_IDEA.OBJ LIB_MD4.OBJ \
	LIB_MD5.OBJ LIB_MDC.OBJ LIB_NULL.OBJ LIB_RC4.OBJ LIB_RC5.OBJ LIB_SAFR.OBJ LIB_SHA.OBJ \
	BLOWFISH.OBJ IDEA.OBJ ECB_ENC.OBJ SET_KEY.OBJ MD4.OBJ MD5.OBJ RC4.OBJ RC5.OBJ SAFER.OBJ \
	SHS.OBJ ECB3_ENC.OBJ LIB_RSA.OBJ RC2.OBJ LIB_RC2.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
CRYPT.OBJ +
LIB_3DES.OBJ +
LIB_BLOW.OBJ +
LIB_DES.OBJ +
LIB_IDEA.OBJ +
LIB_MD4.OBJ +
LIB_MD5.OBJ +
LIB_MDC.OBJ +
LIB_NULL.OBJ +
LIB_RC4.OBJ +
LIB_RC5.OBJ +
LIB_SAFR.OBJ +
LIB_SHA.OBJ +
BLOWFISH.OBJ +
IDEA.OBJ +
ECB_ENC.OBJ +
SET_KEY.OBJ +
MD4.OBJ +
MD5.OBJ +
RC4.OBJ +
RC5.OBJ +
SAFER.OBJ +
SHS.OBJ +
ECB3_ENC.OBJ +
LIB_RSA.OBJ +
RC2.OBJ +
LIB_RC2.OBJ +
$(OBJS_EXT)
$(PROJ).DLL
$(MAPFILE)
G:\MSVC15\LIB\+
G:\MSVC15\MFC\LIB\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) CRYPT.RES $@
	@copy $(PROJ).CRF MSVC.BND
	implib /nowep $(PROJ).LIB $(PROJ).DLL

$(PROJ).DLL::	CRYPT.RES
	if not exist MSVC.BND 	$(RC) $(RESFLAGS) CRYPT.RES $@

run: $(PROJ).DLL
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
