CC=cc
CFLAGS=-g


YFLAGS = -d

SOURCES = principal.c principal_p.c data.c context.c misc.c string2key.c \
	  krbhst.c getport.c send_to_kdc.c

OBJECTS = $(SOURCES:%.c=%.o) config_file.o


tt: test.o libkrb5.a
	$(CC) -o tt test.o libkrb5.a

test.o: krb5.h

libkrb5.a: $(OBJECTS)
	ar cr libkrb5.a $(OBJECTS)
	ranlib libkrb5.a 

config_file.o: config_file.c

config_file.c: config_file.y
	yacc -b y -p __k5cf_ $<
	mv -f y.tab.c config_file.c

clean:
	rm -f *.o *~ libkrb5.a tt core \#* config_file.c



$(OBJECTS): krb5_locl.h krb5.h

