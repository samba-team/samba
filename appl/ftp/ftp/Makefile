CC=cc -std1
#CC=gcc
CFLAGS=-g -DHAVE_CONFIG_H -I.. -I../libmissing -I$(ATHENA)/include -I.

ATHENA = /usr/athena

ftp_OBJS = cmds.o cmdtab.o ftp.o main.o ruserpass.o domacro.o globals.o

ftp: $(ftp_OBJS)
	$(CC) -o ftp $(ftp_OBJS) ../libmissing/libmissing.a -L$(ATHENA)/lib -lkrb -ldes

clean:
	rm -f *~ *.o core ftpd ftpcmd.c \#*
