#
# THIS MAKEFILE WORKS WITH MICROSOFT NMAKE ONLY
#

TARGETOS=WINNT

!include <ntwin32.mak>

all: e4mservice.exe

.c.obj:
    $(cc) /I..\common $(crelease) /DNTSERVICE /I..\crypto $(cflags) $(cvarsmt) $*.c

dismount.obj: 
    $(cc) /I..\common $(crelease) /DNTSERVICE /I..\crypto $(cflags) $(cvarsmt) \
	..\common\dismount.c

## dependencies

ntservice.obj: ntservice.c ntservice.h

dismount.obj: ..\common\dismount.c ..\common\dismount.h

ntservice_libs = $(conlibsmt) advapi32.lib shell32.lib

e4mservice.exe: ntservice.obj dismount.obj
    $(link) $(linkrelease) $(conflags) -out:e4mservice.exe $(ntservice_libs) \
   	ntservice.obj dismount.obj

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
	del /f ..\common\*orig
	del /f ..\common\*.org
	del /f ..\*.org

	