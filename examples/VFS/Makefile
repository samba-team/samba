# Generated automatically from Makefile.in by configure.
MAKEFILE	= Makefile.vfs

include	$(MAKEFILE)

CC		= gcc
LIBTOOL		= libtool
CFLAGS		= -O -Wall -g -O2 -march=i386 -mcpu=i686 -I/usr/kerberos/include $(VFS_CFLAGS)
CPPFLAGS	= -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE  -I/usr/kerberos/include $(VFS_CPPFLAGS)
LDFLAGS		=  -Wl,-rpath,/usr/lib -L/usr/kerberos/lib $(VFS_LDFLAGS)
LDSHFLAGS	= -shared
srcdir		= /home/sorce/devel/samba/cascaded-vfs/samba/source
FLAGS		=  $(CFLAGS) -Iinclude -I$(srcdir)/include -I$(srcdir)/ubiqx -I$(srcdir)/smbwrapper  -I. $(CPPFLAGS) -I$(srcdir)

# Default target

default: $(VFS_OBJS)

# if file doesn't exist try to create one; 
# it is possible that some variables will be 
# defined correctly
Makefile.vfs:
	@echo -ne "VFS_OBJS\t= " > $(MAKEFILE); \
	for i in *.c; do \
	echo -n $$i" " | sed -e 's/\(.*\)\.c\(.*\)/\1\.so\2/g' >> $(MAKEFILE); \
	done; \
	echo -ne "\nVFS_CFLAGS\t= \nVFS_CPPFLAGS\t= \nVFS_LDFLAGS\t= \n" >> $(MAKEFILE)
	make

# Pattern rules

%.so: %.lo
	$(LIBTOOL) $(CC) $(LDSHFLAGS) $(LDFLAGS) -o $@ $< 

%.lo: %.c
	$(LIBTOOL) $(CC) $(FLAGS) -c $<

# Misc targets

clean:
	rm -rf .libs
	rm -f core *~ *% *.bak \
	$(VFS_OBJS) $(VFS_OBJS:.so=.o) $(VFS_OBJS:.so=.lo) 
