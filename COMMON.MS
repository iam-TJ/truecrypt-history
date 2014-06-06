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

# GUI DEFINES ###################################################################

!IFNDEF RELEASE
CFLAGS_G = -D_DEBUG -DWIN32 -D_WINDOWS -DLITTLE_ENDIAN /Zi /Od /MTd /GX- /Zp8 /W3 /WX
LFLAGS_G = /incremental:yes /pdbtype:sept /pdb:$(BASENAME).pdb /debug /debugtype:cv
!ELSE
CFLAGS_G = -DNDEBUG -DWIN32 -D_WINDOWS -DLITTLE_ENDIAN /O2 /MT /GX- /Zp8 /W3 /WX
LFLAGS_G = /incremental:no /pdb:none /machine:I386
!ENDIF

LINK_G = link $(LFLAGS_G) /nologo /out:$(BASENAME).exe /machine:I386 \
   kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib shell32.lib \
   comctl32.lib advapi32.lib


CRYPTOOBJ = bf_skey.obj d-win32.obj des.obj idea.obj idea_386.obj \
        b-win32.obj set_key.obj sha1.obj sha.obj \
        md5.obj ecb3_enc.obj c-win32.obj \
	c_skey.obj c_ecb.obj  bf_ecb.obj
	
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
        del  *.ilk
        del  *.o
        del  *.res
        del  RC*. 
        del  *.map       
        del  *.sbr
        del  *.bsc
        del  *.aps
        del  *.dbg
        del  *.pdb
        del  *.sys
        del  *.pch
        del  *.cod
        del  *.d
        del  *.obj
        del  *orig
        del  *.org
        del  *.bak
        del  *.lib
        del  *.nms
        
