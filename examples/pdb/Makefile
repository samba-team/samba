# Makefile for samba-pdb examples
# Variables

CC = gcc
LIBTOOL = libtool

SAMBA_SRC = ../../source
SAMBA_INCL = ../../source/include
UBIQX_SRC = ../../source/ubiqx
SMBWR_SRC = ../../source/smbwrapper
CFLAGS = -I$(SAMBA_SRC) -I$(SAMBA_INCL) -I$(UBIQX_SRC) -I$(SMBWR_SRC) -Wall -g -I/usr/include/heimdal -fPIC
PDB_OBJS = pdb_test.so

# Default target

default: $(PDB_OBJS)

# Pattern rules

%.so: %.lo
	$(LIBTOOL) $(CC) -shared -o $@ $< $(LDFLAGS)

%.lo: %.c
	$(LIBTOOL) $(CC) $(CPPFLAGS) $(CFLAGS) -c $<

# Misc targets

clean:
	rm -rf .libs
	rm -f core *~ *% *.bak \
		$(PDB_OBJS) $(PDB_OBJS:.so=.o) $(PDB_OBJS:.so=.lo) 
