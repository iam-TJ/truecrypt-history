# Microsoft Visual C++ generated build script - Do not modify

PROJ = CRYPT
DEBUG = 0
PROGTYPE = 1
CALLER = 
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
CFLAGS_D_WDLL = /nologo /G2 /W3 /Zi /ALw /Od /D "HAVE_CONFIG_H"="1" /D "BNINCLUDE"="lbn8086.h" /D "_DEBUG" /D "INC_CHILD" /I "..\." /GD /Fd"CRYPT.PDB"
CFLAGS_R_WDLL = /nologo /G3 /W3 /ALw /O2 /D "HAVE_CONFIG_H"="1" /D "BNINCLUDE"="lbn8086.h" /D "NDEBUG" /D "INC_CHILD" /GD 
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /CO  
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE  
LIBS_D_WDLL = oldnames libw ldllcew odbc toolhelp.lib 
LIBS_R_WDLL = oldnames libw ldllcew odbc toolhelp.lib 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = CRYPT.DEF
OBJS_EXT = ..\BNLIB\LBN8086.OBJ 
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
		SAFER.SBR \
		ECB3_ENC.SBR \
		LIB_RSA.SBR \
		LIB_RC2.SBR \
		BN.SBR \
		BN00.SBR \
		LBN00.SBR \
		LBNMEM.SBR \
		LEGAL.SBR \
		LIB_PKCS.SBR \
		ASN1.SBR \
		STREAM.SBR \
		LIB_RAND.SBR \
		LIB_DH.SBR \
		ASN1KEYS.SBR \
		MD4.SBR \
		MD5.SBR \
		RC2.SBR \
		RC4.SBR \
		RC5.SBR \
		SHA1.SBR \
		SHA.SBR \
		CRYPTOBJ.SBR \
		CRYPTCAP.SBR \
		CRYPTAPI.SBR \
		CRYPTDBX.SBR \
		ASN1OBJS.SBR \
		MD2.SBR \
		RIPEMD.SBR \
		LIB_MD2.SBR \
		LIB_RIPE.SBR \
		X509_KEY.SBR \
		PGP_KEY.SBR \
		PGP_IDEA.SBR \
		LIB_CERT.SBR \
		LIB_DSA.SBR


LBN8086_DEP = 

CRYPT_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h


LIB_3DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\libdes/des.h


LIB_BLOW_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\blowfish/blowfish.h


LIB_DES_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\libdes/des.h \
	c:\work\crypt\testdes.h


LIB_IDEA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\idea/idea.h \
	c:\work\crypt\testidea.h


LIB_MD4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/md4.h


LIB_MD5_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/md5.h


LIB_MDC_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/sha.h


LIB_NULL_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h


LIB_RC4_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\rc/rc4.h \
	c:\work\crypt\testrc4.h


LIB_RC5_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\rc/rc5.h


LIB_SAFR_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\safer/safer.h \
	c:\work\crypt\testsafr.h


LIB_SHA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/sha.h


BLOWFISH_DEP = c:\work\crypt\blowfish\blowfish.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	blowfish/blowfish.h \
	c:\work\crypt\blowfish\bf_init.c \
	blowfish/bf_init.c


IDEA_DEP = c:\work\crypt\idea\idea.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
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


SAFER_DEP = c:\work\crypt\safer\safer.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	safer/safer.h


CRYPT_RCDEP = 

ECB3_ENC_DEP = c:\work\crypt\libdes\des_locl.h \
	c:\work\crypt\libdes\des.h \
	libdes/des.h \
	libdes/des_locl.h


LIB_RSA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h


LIB_RC2_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\rc/rc2.h


BN_DEP = c:\work\crypt\bnlib\bn.h \
	bnlib/bn.h


BN00_DEP = c:\work\crypt\bnlib\bnsize00.h \
	c:\work\crypt\bnlib\lbn.h \
	c:\work\crypt\bnlib\config.h \
	bnlib/config.h \
	bnlib/bnsize00.h \
	c:\work\crypt\bnlib\bn64.c \
	c:\work\crypt\bnlib\lbn64.h \
	bnlib/lbn.h \
	c:\work\crypt\bnlib\lbnmem.h \
	c:\work\crypt\bnlib\bn64.h \
	c:\work\crypt\bnlib\bn.h \
	c:\work\crypt\bnlib\kludge.h \
	bnlib/lbn64.h \
	bnlib/lbnmem.h \
	bnlib/bn64.h \
	bnlib/bn.h \
	bnlib/kludge.h \
	c:\work\crypt\bnlib\bninit64.c \
	bnlib/bn64.c \
	bnlib/bninit64.c \
	c:\work\crypt\bnlib\bn32.c \
	c:\work\crypt\bnlib\lbn32.h \
	c:\work\crypt\bnlib\bn32.h \
	bnlib/lbn32.h \
	bnlib/bn32.h \
	c:\work\crypt\bnlib\bninit32.c \
	bnlib/bn32.c \
	bnlib/bninit32.c \
	c:\work\crypt\bnlib\bn16.c \
	c:\work\crypt\bnlib\lbn16.h \
	c:\work\crypt\bnlib\bn16.h \
	bnlib/lbn16.h \
	bnlib/bn16.h \
	c:\work\crypt\bnlib\bninit16.c \
	bnlib/bn16.c \
	bnlib/bninit16.c


LBN00_DEP = c:\work\crypt\bnlib\bnsize00.h \
	c:\work\crypt\bnlib\lbn.h \
	c:\work\crypt\bnlib\config.h \
	bnlib/config.h \
	c:\work\crypt\bnlib\lbn64.c \
	c:\work\crypt\bnlib\lbn64.h \
	bnlib/lbn.h \
	c:\work\crypt\bnlib\lbnmem.h \
	c:\work\crypt\bnlib\legal.h \
	c:\work\crypt\bnlib\kludge.h \
	bnlib/lbn64.h \
	bnlib/lbnmem.h \
	bnlib/legal.h \
	bnlib/kludge.h \
	c:\work\crypt\bnlib\lbn32.c \
	c:\work\crypt\bnlib\lbn32.h \
	bnlib/lbn32.h \
	c:\work\crypt\bnlib\lbn16.c \
	c:\work\crypt\bnlib\lbn16.h \
	bnlib/lbn16.h


LBNMEM_DEP = c:\work\crypt\bnlib\config.h \
	bnlib/config.h \
	c:\work\crypt\bnlib\lbn.h \
	c:\work\crypt\bnlib\lbnmem.h \
	c:\work\crypt\bnlib\kludge.h \
	bnlib/lbn.h \
	bnlib/lbnmem.h \
	bnlib/kludge.h


LEGAL_DEP = c:\work\crypt\bnlib\config.h \
	bnlib/config.h \
	c:\work\crypt\bnlib\legal.h \
	bnlib/legal.h


LIB_PKCS_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt/asn1objs.h \
	c:\work\crypt\keymgmt/\stream.h \
	c:\work\crypt\keymgmt/stream.h


ASN1_DEP = c:\work\crypt\keymgmt\asn1.h \
	c:\work\crypt\keymgmt\stream.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	keymgmt/asn1.h


STREAM_DEP = c:\work\crypt\keymgmt\stream.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	keymgmt/stream.h


LIB_RAND_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/sha.h \
	sys/ipc.h \
	sys/resource.h \
	sys/select.h \
	sys/shm.h \
	sys/wait.h


LIB_DH_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\testdh.h


ASN1KEYS_DEP = c:\work\crypt\keymgmt\asn1.h \
	c:\work\crypt\keymgmt\stream.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	c:\work\crypt\keymgmt\asn1keys.h \
	c:\work\crypt\keymgmt\asn1objs.h \
	c:\work\crypt\keymgmt\asn1oid.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1objs.h \
	keymgmt/asn1oid.h


MD4_DEP = c:\work\crypt\hash\md4.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/md4.h


MD5_DEP = c:\work\crypt\hash\md5.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/md5.h


RC2_DEP = c:\work\crypt\rc\rc2.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	rc/rc2.h


RC4_DEP = c:\work\crypt\rc\rc4.h \
	rc/rc4.h


RC5_DEP = c:\work\crypt\rc\rc5.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	rc/rc5.h


SHA1_DEP = c:\work\crypt\hash\sha.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/sha.h \
	c:\work\crypt\hash\shacore.c \
	hash/shacore.c


SHA_DEP = c:\work\crypt\hash\sha.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/sha.h \
	c:\work\crypt\hash\shacore.c \
	hash/shacore.c


CRYPTOBJ_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt/asn1objs.h \
	c:\work\crypt\keymgmt/\stream.h \
	c:\work\crypt\keymgmt/stream.h


CRYPTCAP_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h


CRYPTAPI_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/md2.h \
	c:\work\crypt\hash/md4.h \
	c:\work\crypt\hash/md5.h \
	c:\work\crypt\hash/ripemd.h \
	c:\work\crypt\hash/sha.h \
	c:\work\crypt\keymgmt/asn1objs.h \
	c:\work\crypt\keymgmt/\stream.h \
	c:\work\crypt\keymgmt/stream.h \
	sys/mman.h


CRYPTDBX_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt/keymgmt.h


ASN1OBJS_DEP = c:\work\crypt\keymgmt\asn1.h \
	c:\work\crypt\keymgmt\stream.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	c:\work\crypt\keymgmt\asn1objs.h \
	keymgmt/asn1.h \
	keymgmt/asn1objs.h


MD2_DEP = c:\work\crypt\hash\md2.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/md2.h


RIPEMD_DEP = c:\work\crypt\hash\ripemd.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	hash/ripemd.h


LIB_MD2_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/md2.h


LIB_RIPE_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\hash/ripemd.h


X509_KEY_DEP = c:\work\crypt\keymgmt\asn1.h \
	c:\work\crypt\keymgmt\stream.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt\ber.h \
	keymgmt/stream.h \
	keymgmt/ber.h \
	c:\work\crypt\keymgmt\asn1keys.h \
	c:\work\crypt\keymgmt\asn1oid.h \
	c:\work\crypt\keymgmt\keymgmt.h \
	keymgmt/asn1.h \
	keymgmt/asn1keys.h \
	keymgmt/asn1oid.h \
	keymgmt/keymgmt.h


PGP_KEY_DEP = c:\work\crypt\keymgmt\keymgmt.h \
	c:\work\crypt\keymgmt\pgp_idea.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	keymgmt/keymgmt.h \
	keymgmt/pgp_idea.h


PGP_IDEA_DEP = c:\work\crypt\keymgmt\pgp_idea.h \
	c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	keymgmt/pgp_idea.h


LIB_CERT_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h \
	c:\work\crypt\keymgmt/asn1keys.h \
	c:\work\crypt\keymgmt/\stream.h \
	c:\work\crypt\keymgmt/stream.h


LIB_DSA_DEP = c:\work\crypt\crypt.h \
	c:\work\crypt\capi.h \
	c:\work\crypt\bnlib/bn.h


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

SAFER.OBJ:	..\SAFER\SAFER.C $(SAFER_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SAFER\SAFER.C

CRYPT.RES:	CRYPT.RC $(CRYPT_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r CRYPT.RC

ECB3_ENC.OBJ:	..\LIBDES\ECB3_ENC.C $(ECB3_ENC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBDES\ECB3_ENC.C

LIB_RSA.OBJ:	..\LIB_RSA.C $(LIB_RSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RSA.C

LIB_RC2.OBJ:	..\LIB_RC2.C $(LIB_RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RC2.C

BN.OBJ:	..\BNLIB\BN.C $(BN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BNLIB\BN.C

BN00.OBJ:	..\BNLIB\BN00.C $(BN00_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BNLIB\BN00.C

LBN00.OBJ:	..\BNLIB\LBN00.C $(LBN00_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BNLIB\LBN00.C

LBNMEM.OBJ:	..\BNLIB\LBNMEM.C $(LBNMEM_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BNLIB\LBNMEM.C

LEGAL.OBJ:	..\BNLIB\LEGAL.C $(LEGAL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\BNLIB\LEGAL.C

LIB_PKCS.OBJ:	..\LIB_PKCS.C $(LIB_PKCS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_PKCS.C

ASN1.OBJ:	..\KEYMGMT\ASN1.C $(ASN1_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1.C

STREAM.OBJ:	..\KEYMGMT\STREAM.C $(STREAM_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\STREAM.C

LIB_RAND.OBJ:	..\LIB_RAND.C $(LIB_RAND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RAND.C

LIB_DH.OBJ:	..\LIB_DH.C $(LIB_DH_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DH.C

ASN1KEYS.OBJ:	..\KEYMGMT\ASN1KEYS.C $(ASN1KEYS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1KEYS.C

MD4.OBJ:	..\HASH\MD4.C $(MD4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD4.C

MD5.OBJ:	..\HASH\MD5.C $(MD5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD5.C

RC2.OBJ:	..\RC\RC2.C $(RC2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC\RC2.C

RC4.OBJ:	..\RC\RC4.C $(RC4_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC\RC4.C

RC5.OBJ:	..\RC\RC5.C $(RC5_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\RC\RC5.C

SHA1.OBJ:	..\HASH\SHA1.C $(SHA1_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\SHA1.C

SHA.OBJ:	..\HASH\SHA.C $(SHA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\SHA.C

CRYPTOBJ.OBJ:	..\CRYPTOBJ.C $(CRYPTOBJ_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTOBJ.C

CRYPTCAP.OBJ:	..\CRYPTCAP.C $(CRYPTCAP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTCAP.C

CRYPTAPI.OBJ:	..\CRYPTAPI.C $(CRYPTAPI_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTAPI.C

CRYPTDBX.OBJ:	..\CRYPTDBX.C $(CRYPTDBX_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\CRYPTDBX.C

ASN1OBJS.OBJ:	..\KEYMGMT\ASN1OBJS.C $(ASN1OBJS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\ASN1OBJS.C

MD2.OBJ:	..\HASH\MD2.C $(MD2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\MD2.C

RIPEMD.OBJ:	..\HASH\RIPEMD.C $(RIPEMD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\HASH\RIPEMD.C

LIB_MD2.OBJ:	..\LIB_MD2.C $(LIB_MD2_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_MD2.C

LIB_RIPE.OBJ:	..\LIB_RIPE.C $(LIB_RIPE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_RIPE.C

X509_KEY.OBJ:	..\KEYMGMT\X509_KEY.C $(X509_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\X509_KEY.C

PGP_KEY.OBJ:	..\KEYMGMT\PGP_KEY.C $(PGP_KEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\PGP_KEY.C

PGP_IDEA.OBJ:	..\KEYMGMT\PGP_IDEA.C $(PGP_IDEA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\KEYMGMT\PGP_IDEA.C

LIB_CERT.OBJ:	..\LIB_CERT.C $(LIB_CERT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_CERT.C

LIB_DSA.OBJ:	..\LIB_DSA.C $(LIB_DSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIB_DSA.C


$(PROJ).DLL::	CRYPT.RES

$(PROJ).DLL::	CRYPT.OBJ LIB_3DES.OBJ LIB_BLOW.OBJ LIB_DES.OBJ LIB_IDEA.OBJ LIB_MD4.OBJ \
	LIB_MD5.OBJ LIB_MDC.OBJ LIB_NULL.OBJ LIB_RC4.OBJ LIB_RC5.OBJ LIB_SAFR.OBJ LIB_SHA.OBJ \
	BLOWFISH.OBJ IDEA.OBJ ECB_ENC.OBJ SET_KEY.OBJ SAFER.OBJ ECB3_ENC.OBJ LIB_RSA.OBJ \
	LIB_RC2.OBJ BN.OBJ BN00.OBJ LBN00.OBJ LBNMEM.OBJ LEGAL.OBJ LIB_PKCS.OBJ ASN1.OBJ \
	STREAM.OBJ LIB_RAND.OBJ LIB_DH.OBJ ASN1KEYS.OBJ MD4.OBJ MD5.OBJ RC2.OBJ RC4.OBJ RC5.OBJ \
	SHA1.OBJ SHA.OBJ CRYPTOBJ.OBJ CRYPTCAP.OBJ CRYPTAPI.OBJ CRYPTDBX.OBJ ASN1OBJS.OBJ \
	MD2.OBJ RIPEMD.OBJ LIB_MD2.OBJ LIB_RIPE.OBJ X509_KEY.OBJ PGP_KEY.OBJ PGP_IDEA.OBJ \
	LIB_CERT.OBJ LIB_DSA.OBJ $(OBJS_EXT) $(DEFFILE)
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
SAFER.OBJ +
ECB3_ENC.OBJ +
LIB_RSA.OBJ +
LIB_RC2.OBJ +
BN.OBJ +
BN00.OBJ +
LBN00.OBJ +
LBNMEM.OBJ +
LEGAL.OBJ +
LIB_PKCS.OBJ +
ASN1.OBJ +
STREAM.OBJ +
LIB_RAND.OBJ +
LIB_DH.OBJ +
ASN1KEYS.OBJ +
MD4.OBJ +
MD5.OBJ +
RC2.OBJ +
RC4.OBJ +
RC5.OBJ +
SHA1.OBJ +
SHA.OBJ +
CRYPTOBJ.OBJ +
CRYPTCAP.OBJ +
CRYPTAPI.OBJ +
CRYPTDBX.OBJ +
ASN1OBJS.OBJ +
MD2.OBJ +
RIPEMD.OBJ +
LIB_MD2.OBJ +
LIB_RIPE.OBJ +
X509_KEY.OBJ +
PGP_KEY.OBJ +
PGP_IDEA.OBJ +
LIB_CERT.OBJ +
LIB_DSA.OBJ +
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
