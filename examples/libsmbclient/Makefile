#
CC = gcc

SAMBA_INCL = ../../source/include
EXTLIB_INCL = -I/usr/include/gtk-1.2 \
	      -I/usr/include/glib-1.2 \
	      -I/usr/lib/glib/include

CFLAGS = -I$(SAMBA_INCL) $(EXTLIB_INCL)

LDFLAGS = -L/usr/lib

all: testsmbc tree testacl testbrowse

testsmbc: testsmbc.o 
	@echo Linking testsmbc
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lsmbclient -L/usr/local/lib

testsmbc-static: testsmbc.o 
	@echo Linking testsmbc
	@$(CC) $(CFLAGS) -static $(LDFLAGS) -o $@ $< -lsmbclient -ldl -lnsl

tree: tree.o
	@echo Linking tree
	@$(CC) `gtk-config --cflags` $(CFLAGS) $(LDFLAGS) -o $@ `gtk-config --libs` -lsmbclient $<

testacl: testacl.o
	@echo Linking testacl
	@$(CC) `gtk-config --cflags` $(CFLAGS) $(LDFLAGS) -o $@ `gtk-config --libs` -lsmbclient -lpopt $<

testbrowse: testbrowse.o
	@echo Linking testbrowse
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -lsmbclient -lpopt $<

clean:
	@rm -f *.o *~
