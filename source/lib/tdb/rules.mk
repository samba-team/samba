.SUFFIXES: .i _wrap.c

.i_wrap.c: 
	$(SWIG) -O -Wall -python -keyword $<

showflags::
	@echo 'tdb will be compiled with flags:'
	@echo '  CFLAGS = $(CFLAGS)'
	@echo '  CPPFLAGS = $(CPPFLAGS)'
	@echo '  LDFLAGS = $(LDFLAGS)'
	@echo '  LIBS = $(LIBS)'

.SUFFIXES: .c .o

.c.o:
	@echo Compiling $*.c
	@mkdir -p `dirname $@`
	@$(CC) $(PICFLAG) $(CFLAGS) -c $< -o $@

distclean::
	rm -f *~ */*~
