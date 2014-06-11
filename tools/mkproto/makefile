CC      = cl
CFLAGS  = /O1 /W3 /Za

mkproto.exe: mkproto.obj
	link /out:..\mkproto.exe -machine:IX86 mkproto.obj

%.obj : %.c
	$(CC) -c $(CFLAGS) $< /link /release

clean:  
	del *.obj
