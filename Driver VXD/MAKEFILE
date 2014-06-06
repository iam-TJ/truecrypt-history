#
# THIS MAKEFILE WORKS WITH MICROSOFT NMAKE ONLY
#

# This points to the windows ddk
DDK = c:\ddk95

BASENAME = e4m9x

all: $(BASENAME).vxd

OBJECTS = e4m9x.obj volumes1.obj crypto.obj endian.obj crc.obj pkcs5.obj devdcl.obj \
       ifshook.obj queue.obj cache.obj

CFLAGS = -D_X86_ -DDEBLEVEL=1  -DBLD_COFF -DDEBUG -DIS_32 -DWIN32 -Gs -Zdpl -Od -YX -W3 -WX \
      /DWIN9X_DRIVER /I$(DDK)\inc32 /I$(DDK)\BLOCK\INC /YXe4mdefs.h /FAcs /I.

LFLAGS = -machine:i386  -out:$@  -def:$*.def -debug -debugtype:map -map:$*.map \
      -vxd vxdwraps.clb -nodefaultlib /LIBPATH:$(DDK)\lib

#
#These flags are unsafe to use, /zi provides structure & automatic
#variable support, but will eventually crash windows. I don't know why.
#Normally these flags can be used with softice to trace through the
#code until atleast the partfilerequest function. Note older softice
#versions did not support anything more that /zd. Use softice 3.24 +
#

#CFLAGS = -D_X86_ -DDEBLEVEL=1 -DBLD_COFF -DDEBUG -DIS_32 -DWIN32 -Gs -Zi -Od -YX -W3 -WX \
#       /DWIN9X_DRIVER /I$(DDK)\inc32 /I$(DDK)\BLOCK\INC /YXe4mdefs.h /I.

#LFLAGS = -machine:i386  -out:$@  -def:$*.def -debug -debugtype:cv -pdbtype:con \
#        -pdb:$*.pdb -vxd vxdwraps.clb -nodefaultlib /LIBPATH:$(DDK)\lib

!include ..\common.ms

ASMFLAGS = /I\$(DDK)\inc32 -coff -DBLD_COFF -DIS_32 -W2 -c -Cx -DMASM6

$(BASENAME).vxd : $(OBJECTS) crypto.lib
	link $(LFLAGS) $(OBJECTS) crypto.lib
#       softice support
        nmsym /TRANSLATE:SOURCE,PACKAGE,ALWAYS $@

devdcl.obj :
	$(ASM) /I$(DDK)\INC32 $(ASMFLAGS) devdcl.asm

install:
        copy e4m9x.vxd c:\win95b\system\iosubsys

uninstall:
        del c:\win95b\system\iosubsys\e4m9x.vxd

verify:
	fc /b c:\win95b\system\iosubsys\e4m9x.vxd e4m9x.vxd
