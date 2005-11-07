SAMBA_SRC_DIR=../../source
TDB_SRC_DIR=$(SAMBA_SRC_DIR)/tdb

CFLAGS = -g -I$(SAMBA_SRC_DIR)/include -I$(TDB_SRC_DIR)
CC = gcc

PROGS = perf_writer
TDB_OBJ = $(TDB_SRC_DIR)/tdb.o $(TDB_SRC_DIR)/spinlock.o $(TDB_SRC_DIR)/tdbback.o
PERF_WRITER_OBJ = perf_writer.o perf_writer_mem.o perf_writer_util.o perf_writer_cpu.o perf_writer_process.o perf_writer_disk.o

default: $(PROGS)

$(TDB_OBJ):
	cd $(TDB_SRC_DIR) && make

perf_writer: $(PERF_WRITER_OBJ) $(TDB_OBJ)
	$(CC) $(CFLAGS) -o perf_writer $(PERF_WRITER_OBJ) $(TDB_OBJ)

clean:
	rm -f $(PROGS) *.o *~ *% core
