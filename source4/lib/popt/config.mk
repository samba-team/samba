[SUBSYSTEM::LIBPOPT]
CFLAGS = -Ilib/popt

LIBPOPT_OBJ_FILES = $(addprefix $(poptsrcdir)/, findme.o popt.o poptconfig.o popthelp.o poptparse.o)

