CFLAGS=-Wall -g
CC=gcc

OBJ = vluke.o parser.o 
AWKPROGS=dump.awk harness.awk header.awk parsefn.awk main.awk parsetree.awk template.awk util.awk

all: test.h vluke

test.h : $(AWKPROGS)
	igawk -f main.awk srvsvc.struct

vluke: test.h $(OBJ) 
	$(CC) $(CFLAGS) -o vluke $(OBJ)

clean:
	rm -f *.o test.h prs_*.[ch]

