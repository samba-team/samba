#
CC = gcc

SAMBA_INCL = ../../source/include

CFLAGS = -I$(SAMBA_INCL)

LDFLAGS = -L/usr/lib

all: testsmbc tree

testsmbc: testsmbc.o 
	@echo Linking testsmbc
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lsmbclient -L/usr/local/lib

testsmbc-static: testsmbc.o 
	@echo Linking testsmbc
	@$(CC) $(CFLAGS) -static $(LDFLAGS) -o $@ $< -lsmbclient -ldl -lnsl

tree: tree.o
	@echo Linking tree
	@$(CC) `gtk-config --cflags` $(CFLAGS) $(LDFLAGS) -o $@ `gtk-config --libs` -lsmbclient $<

clean:
	@rm -f *.o *~
