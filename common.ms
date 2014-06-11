#
# THIS MAKEFILE WORKS WITH MICROSOFT NMAKE ONLY
#


CC = cl
ASM = ml

!IFNDEF RELEASE
ASMFLAGS = /coff /Zm /c /Cp /Zi /D_DEBUG
!ELSE
ASMFLAGS = /coff /Zm /c /Cp /DNDEBUG
!ENDIF

# GUI DEFINES

!IFNDEF RELEASE
CFLAGS_G = -D_DEBUG -DWIN32 -D_WINDOWS -DLITTLE_ENDIAN /Zi /Od /MTd /GX- /Zp8 /W4
LFLAGS_G = /incremental:yes /pdbtype:sept /pdb:$(BASENAME).pdb /debug /debugtype:cv
!ELSE
CFLAGS_G = -DNDEBUG -DWIN32 -D_WINDOWS -DLITTLE_ENDIAN /O2 /MT /GX- /Zp8 /W4
LFLAGS_G = /incremental:no /pdb:none /machine:I386
!ENDIF

LINK_G = link $(LFLAGS_G) /nologo /out:$(BASENAME).exe /machine:I386 \
   kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib shell32.lib \
   comctl32.lib advapi32.lib

# NT4 DRIVER DEFINES

!IFNDEF RELEASE

# Original debug build options from build.exe was
# DFPO=0
DEFINES_D = -D_X86_=1 -Di386=1 -DSTD_CALL -DCONDITION_HANDLING=1 \
-DNT_UP=1 -DNT_INST=0 -DWIN32=100 -D_NT1X_=100 \
-DWINNT=1 -D_WIN32_WINNT=0x0400 -DWIN32_LEAN_AND_MEAN=1 -DDBG=1 -DDEBUG -DDEVL=1 \
-DFPO=0 -D_DLL=1 -D_IDWBUILD -DRDRDBG -DSRVDBG -DDBG_MESSAGES=1 \
-D_UNICODE -DLITTLE_ENDIAN

CFLAGS_D = $(DEFINES_D) /Zel /Zp8 /Gy -cbstring /Gz /QIfdiv- /QIf /Gi- /Gm- /GX- \
/GR- /GF -FI$(DDK)\inc\warning.h -Z7 /Od /Oi /Oy- /W4

LFLAGS_D = -MERGE:_PAGE=PAGE -MERGE:_TEXT=.text -SECTION:INIT,d \
-INCREMENTAL:NO -FORCE:MULTIPLE -RELEASE -FULLBUILD \
-IGNORE:4001,4037,4039,4065,4070,4078,4087,4089,4096 -NODEFAULTLIB \
-debug:notmapped,FULL -debugtype:both -version:4.00 -osversion:4.00 \
-PDB:NONE -MERGE:.rdata=.text -MAP:$(BASENAME).map -optidata -driver -align:0x20 \
-subsystem:native,4.00 -base:0x10000 -entry:DriverEntry@8

!ELSE

DEFINES_D = -D_X86_=1 -Di386=1 -DSTD_CALL -DCONDITION_HANDLING=1 \
-DNT_UP=1 -DNO_DISK_ACCESS -DNT_INST=0 -DWIN32=100 -D_NT1X_=100 \
-DWINNT=1 -D_WIN32_WINNT=0x0400 -DWIN32_LEAN_AND_MEAN=1 -DDEVL=1 \
-DFPO=1 -DNDEBUG -D_DLL=1 -D_IDWBUILD -D_UNICODE \
-DLITTLE_ENDIAN

# /W warning level /Gz calling convention is __stdcall /QIfdiv- disable pentium bug fix
# /QIf emit FPO records for every function /Gi- disable incremental compile
# /Gm- disable min. rebuild /GX- disable exception handling /GR- disable RTTI
# /GF eliminate duplicate strings /Oxs /Oy Frame-Pointer omission

CFLAGS_D = $(DEFINES_D) /Zel /Zp8 /Gy -cbstring /Gz /QIfdiv- /QIf /Gi- /Gm- /GX- \
/GR- /GF /Oxs /Oy -FI$(DDK)\inc\warning.h /W4

LFLAGS_D = -MERGE:_PAGE=PAGE -MERGE:_TEXT=.text -SECTION:INIT,d \
-INCREMENTAL:NO -FORCE:MULTIPLE -RELEASE -FULLBUILD \
-IGNORE:4001,4037,4039,4065,4070,4078,4087,4089,4096 -NODEFAULTLIB -version:4.00 \
-osversion:4.00 -PDB:NONE -MERGE:.rdata=.text -MAP:$(BASENAME).map -optidata -driver \
-align:0x20 -subsystem:native,4.00 -base:0x10000 -entry:DriverEntry@8

!ENDIF

LINK_D = link $(LFLAGS_D) /nologo /out:$(BASENAME).sys -machine:IX86 \
   $(DDK)\lib\i386\free\ntoskrnl.lib \
   $(DDK)\lib\i386\free\hal.lib

CRYPTOOBJ = bf_skey.obj d-win32.obj des.obj idea.obj idea_386.obj \
	misty1.obj  b-win32.obj set_key.obj sha1.obj sha.obj \
	square.obj tea_asm.obj md5.obj ecb3_enc.obj c-win32.obj \
	c_skey.obj c_ecb.obj  
	
# RULES

.c.obj :
	$(CC) -c $(CFLAGS) /I../common /I../crypto/ 	$<

{../common}.c{}.obj :
	$(CC) -c $(CFLAGS) /I../common /I../crypto/ 	$<

{../crypto}.c{}.obj :
	$(CC) -c $(CFLAGS) /I../common /I../crypto/ 	$<

{../crypto}.asm{}.obj :
	$(ASM) $(ASMFLAGS) $<

.rc.res :
	rc -l 409 -r -D_X86_ $<

crypto.lib : $(CRYPTOOBJ)
	LIB /OUT:crypto.lib $(CRYPTOOBJ)

clean:  
	del /f *.ilk
	del /f *.o
	del /f *.res
	del /f RC*. 
	del /f *.map       
	del /f *.sbr
	del /f *.bsc
	del /f *.aps
	del /f *.dbg
	del /f *.pdb
	del /f *.sys
	del /f *.pch
	del /f *.cod
	del /f *.d
	del /f *.obj
	del /f *orig
	del /f *.org
	del /f *.bak
        del /f *.lib
	del /f ..\common\*orig
	del /f ..\common\*.org
	del /f ..\*.org

