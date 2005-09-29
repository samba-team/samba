INCLUDES=-I.
CFLAGS=$(INCLUDES) 

all: npecho_client.exe npecho_server.exe

CC = i586-mingw32msvc-gcc

.SUFFIXES: .c .obj

.c.obj: 
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del *~ *.obj *.exe 

npecho_client.exe: npecho_client.obj
npecho_server.exe: npecho_server.obj

%.exe: 
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
