#
# THIS MAKEFILE WORKS WITH MICROSOFT NMAKE ONLY
#

TARGETOS=WINNT

!include <ntwin32.mak>

all: e4mserv.exe

.c.obj:
    $(cc) /I..\common $(crelease) /DNTSERVICE /I..\crypto $(cflags) $(cvarsmt) $*.c

dismount.obj: 
    $(cc) /I..\common $(crelease) /DNTSERVICE /I..\crypto $(cflags) $(cvarsmt) \
	..\common\dismount.c

## dependencies

ntservice.obj: ntservice.c ntservice.h

dismount.obj: ..\common\dismount.c ..\common\dismount.h

ntservice_libs = $(conlibsmt) advapi32.lib shell32.lib

e4mserv.exe: ntservice.obj dismount.obj
    $(link) $(linkrelease) $(conflags) -out:e4mserv.exe $(ntservice_libs) \
	ntservice.obj dismount.obj

clean:  
	del *.ilk
	del *.o
	del *.res
	del RC*. 
	del *.map       
	del *.sbr
	del *.bsc
	del *.aps
	del *.dbg
	del *.pdb
	del *.sys
	del *.pch
	del *.cod
	del *.d
	del *.obj
	del *orig
	del *.org
	del *.bak

install:        
	copy e4mserv.exe c:\nt4\system32

uninstall:
	del c:\nt4\system32\e4mserv.exe

