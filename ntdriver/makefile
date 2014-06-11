#
# THIS MAKEFILE WORKS WITH MICROSOFT NMAKE ONLY
#

# change this to point to your DDK
DDK = d:\ddk

BASENAME = e4mnt4

all: $(BASENAME).sys

OBJECTS = ntdriver.obj ntvol.obj ntrawdv.obj ntfiledv.obj \
	volumes1.obj crypto.obj endian.obj sdvol.obj crc.obj pkcs5.obj

#add this for asm listings /FAcs 

CFLAGS = $(CFLAGS_D) /DNT4_DRIVER /I$(DDK)\inc /YXe4mdefs.h

!include ..\common.ms

$(BASENAME).sys : $(OBJECTS) crypto.lib
	$(LINK_D) $(OBJECTS) crypto.lib

install:
	copy $(BASENAME).sys c:\nt4\system32\drivers\$(BASENAME).sys

uninstall:
	del c:\nt4\system32\drivers\$(BASENAME).sys

