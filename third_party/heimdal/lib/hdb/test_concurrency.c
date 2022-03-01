/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This test tries to test reader/writer concurrency for the SQLite3 and LMDB
 * HDB backends.  We're hoping to find that one thread or process can dump the
 * HDB while another writes -- this way backups and ipropd-master need not
 * block write transactions when dumping a huge HDB.
 *
 * It has two modes: threaded, and forked.
 *
 * Apparently, neither LMDB nor SQLite3 give us the desired level of
 * concurrency in threaded mode, with this test not making progress.  This is
 * surprising, at least for SQLite3, which is supposed to support N readers, 1
 * writer and be thread-safe.  LMDB also is supposed to support N readers, 1
 * writers, but perhaps not all in one process?
 */

#include "hdb_locl.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <getarg.h>

struct tsync {
    pthread_mutex_t lock;
    pthread_cond_t rcv;
    pthread_cond_t wcv;
    const char *hdb_name;
    const char *fname;
    volatile int writer_go;
    volatile int reader_go;
    int writer_go_pipe[2];
    int reader_go_pipe[2];
};

static void *
threaded_reader(void *d)
{
    krb5_error_code ret;
    krb5_context context;
    struct tsync *s = d;
    hdb_entry entr;
    HDB *dbr = NULL;

    printf("Reader thread opening HDB\n");

    if ((krb5_init_context(&context)))
	errx(1, "krb5_init_context failed");

    printf("Reader thread waiting for writer to create the HDB\n");
    (void) pthread_mutex_lock(&s->lock);
    s->writer_go = 1;
    (void) pthread_cond_signal(&s->wcv);
    while (!s->reader_go)
        (void) pthread_cond_wait(&s->rcv, &s->lock);
    s->reader_go = 0;
    (void) pthread_mutex_unlock(&s->lock);

    /* Open a new HDB handle to read */
    if ((ret = hdb_create(context, &dbr, s->hdb_name))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not get a handle for HDB %s (read)",
                 s->hdb_name);
    }
    if ((ret = dbr->hdb_open(context, dbr, O_RDONLY, 0))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not open HDB %s", s->hdb_name);
    }
    if ((ret = dbr->hdb_firstkey(context, dbr, 0, &entr))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not iterate HDB %s", s->hdb_name);
    }
    free_HDB_entry(&entr);

    /* Tell the writer to go ahead and write */
    printf("Reader thread iterated one entry; telling writer to write more\n");
    s->writer_go = 1;
    (void) pthread_mutex_lock(&s->lock);
    (void) pthread_cond_signal(&s->wcv);

    /* Wait for the writer to have written one more entry to the HDB */
    printf("Reader thread waiting for writer\n");
    while (!s->reader_go)
        (void) pthread_cond_wait(&s->rcv, &s->lock);
    s->reader_go = 0;
    (void) pthread_mutex_unlock(&s->lock);

    /* Iterate the rest */
    printf("Reader thread iterating another entry\n");
    if ((ret = dbr->hdb_nextkey(context, dbr, 0, &entr))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret,
                 "Could not iterate while writing to HDB %s", s->hdb_name);
    }
    printf("Reader thread iterated another entry\n");
    free_HDB_entry(&entr);
    if ((ret = dbr->hdb_nextkey(context, dbr, 0, &entr)) == 0) {
        //(void) unlink(s->fname);
        krb5_warn(context, ret,
                 "HDB %s sees writes committed since starting iteration",
                 s->hdb_name);
    } else if (ret != HDB_ERR_NOENTRY) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret,
                 "Could not iterate while writing to HDB %s (2)", s->hdb_name);
    }

    /* Tell the writer we're done */
    printf("Reader thread telling writer to go\n");
    s->writer_go = 1;
    (void) pthread_cond_signal(&s->wcv);
    (void) pthread_mutex_unlock(&s->lock);

    dbr->hdb_close(context, dbr);
    dbr->hdb_destroy(context, dbr);
    krb5_free_context(context);
    printf("Reader thread exiting\n");
    return 0;
}

static void
forked_reader(struct tsync *s)
{
    krb5_error_code ret;
    krb5_context context;
    hdb_entry entr;
    ssize_t bytes;
    char b[1];
    HDB *dbr = NULL;

    printf("Reader process opening HDB\n");

    (void) close(s->writer_go_pipe[0]);
    (void) close(s->reader_go_pipe[1]);
    s->writer_go_pipe[0] = -1;
    s->reader_go_pipe[1] = -1;
    if ((krb5_init_context(&context)))
	errx(1, "krb5_init_context failed");

    printf("Reader process waiting for writer\n");
    while ((bytes = read(s->reader_go_pipe[0], b, sizeof(b))) == -1 &&
           errno == EINTR)
        ;
    if (bytes == -1)
        err(1, "Could not read from reader-go pipe (error)");

    /* Open a new HDB handle to read */
    if ((ret = hdb_create(context, &dbr, s->hdb_name))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not get a handle for HDB %s (read)",
                 s->hdb_name);
    }
    if ((ret = dbr->hdb_open(context, dbr, O_RDONLY, 0))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not open HDB %s", s->hdb_name);
    }
    if ((ret = dbr->hdb_firstkey(context, dbr, 0, &entr))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret, "Could not iterate HDB %s", s->hdb_name);
    }
    printf("Reader process iterated one entry\n");
    free_HDB_entry(&entr);

    /* Tell the writer to go ahead and write */
    printf("Reader process iterated one entry; telling writer to write more\n");
    while ((bytes = write(s->writer_go_pipe[1], "", sizeof(""))) == -1 &&
           errno == EINTR)
        ;
    if (bytes == -1)
        err(1, "Could not write to writer-go pipe (error)");


    /* Wait for the writer to have written one more entry to the HDB */
    printf("Reader process waiting for writer\n");
    while ((bytes = read(s->reader_go_pipe[0], b, sizeof(b))) == -1 &&
           errno == EINTR)
        ;
    if (bytes == -1)
        err(1, "Could not read from reader-go pipe (error)");
    if (bytes == 0)
        errx(1, "Could not read from reader-go pipe (EOF)");

    /* Iterate the rest */
    if ((ret = dbr->hdb_nextkey(context, dbr, 0, &entr))) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret,
                 "Could not iterate while writing to HDB %s", s->hdb_name);
    }
    free_HDB_entry(&entr);
    printf("Reader process iterated another entry\n");
    if ((ret = dbr->hdb_nextkey(context, dbr, 0, &entr)) == 0) {
        //(void) unlink(s->fname);
        krb5_warn(context, ret,
                 "HDB %s sees writes committed since starting iteration (%s)",
                 s->hdb_name, entr.principal->name.name_string.val[0]);
    } else if (ret != HDB_ERR_NOENTRY) {
        //(void) unlink(s->fname);
        krb5_err(context, 1, ret,
                 "Could not iterate while writing to HDB %s (2)", s->hdb_name);
    }

    /* Tell the writer we're done */
    printf("Reader process done; telling writer to go\n");
    while ((bytes = write(s->writer_go_pipe[1], "", sizeof(""))) == -1 &&
           errno == EINTR)
        ;
    if (bytes == -1)
        err(1, "Could not write to writer-go pipe (error)");

    dbr->hdb_close(context, dbr);
    dbr->hdb_destroy(context, dbr);
    krb5_free_context(context);
    (void) close(s->writer_go_pipe[1]);
    (void) close(s->reader_go_pipe[0]);
    printf("Reader process exiting\n");
    _exit(0);
}

static krb5_error_code
make_entry(krb5_context context, hdb_entry *entry, const char *name)
{
    krb5_error_code ret;

    memset(entry, 0, sizeof(*entry));
    entry->kvno = 2;
    entry->keys.len = 0;
    entry->keys.val = NULL;
    entry->created_by.time = time(NULL);
    entry->modified_by = NULL;
    entry->valid_start = NULL;
    entry->valid_end = NULL;
    entry->max_life = NULL;
    entry->max_renew = NULL;
    entry->etypes = NULL;
    entry->generation = NULL;
    entry->extensions = NULL;
    if ((ret = krb5_make_principal(context, &entry->principal,
                                   "TEST.H5L.SE", name, NULL)))
        return ret;
    if ((ret = krb5_make_principal(context, &entry->created_by.principal,
                                   "TEST.H5L.SE", "tester", NULL)))
        return ret;
    return 0;
}

static void
readers_turn(struct tsync *s, pid_t child, int threaded)
{
    if (threaded) {
        (void) pthread_mutex_lock(&s->lock);
        s->reader_go = 1;
        (void) pthread_cond_signal(&s->rcv);

        while (!s->writer_go)
            (void) pthread_cond_wait(&s->wcv, &s->lock);
        s->writer_go = 0;
        (void) pthread_mutex_unlock(&s->lock);
    } else {
        ssize_t bytes;
        char b[1];

        while ((bytes = write(s->reader_go_pipe[1], "", sizeof(""))) == -1 &&
               errno == EINTR)
            ;
        if (bytes == -1) {
            kill(child, SIGKILL);
            err(1, "Could not write to reader-go pipe (error)");
        }
        if (bytes == 0) {
            kill(child, SIGKILL);
            err(1, "Could not write to reader-go pipe (EOF?)");
        }

        while ((bytes = read(s->writer_go_pipe[0], b, sizeof(b))) == -1 &&
               errno == EINTR)
            ;
        if (bytes == -1) {
            kill(child, SIGKILL);
            err(1, "Could not read from writer-go pipe");
        }
        if (bytes == 0) {
            kill(child, SIGKILL);
            errx(1, "Child errored");
        }
        s->writer_go = 0;
    }
}

static void
test_hdb_concurrency(char *name, const char *ext, int threaded)
{
    krb5_error_code ret;
    krb5_context context;
    char *fname = strchr(name, ':') + 1;
    char *fname_ext = NULL;
    pthread_t reader_thread;
    struct tsync ts;
    hdb_entry entw;
    pid_t child = getpid();
    HDB *dbw = NULL;
    int status;
    int fd;

    memset(&ts, 0, sizeof(ts));
    (void) pthread_cond_init(&ts.rcv, NULL);
    (void) pthread_cond_init(&ts.wcv, NULL);
    (void) pthread_mutex_init(&ts.lock, NULL);

    if ((krb5_init_context(&context)))
	errx(1, "krb5_init_context failed");

    /* Use mkstemp() then unlink() to avoid warnings about mktemp(); ugh */
    if ((fd = mkstemp(fname)) == -1)
        err(1, "mkstemp(%s)", fname);
    (void) close(fd);
    (void) unlink(fname);
    if (asprintf(&fname_ext, "%s%s", fname, ext ? ext : "") == -1 ||
        fname_ext == NULL)
        err(1, "Out of memory");
    ts.hdb_name = name;
    ts.fname = fname_ext;

    if (threaded) {
        printf("Starting reader thread\n");
        (void) pthread_mutex_lock(&ts.lock);
        if ((errno = pthread_create(&reader_thread, NULL, threaded_reader, &ts))) {
            (void) unlink(fname_ext);
            krb5_err(context, 1, errno, "Could not create a thread to read HDB");
        }

        /* Wait for reader */
        while (!ts.writer_go)
            (void) pthread_cond_wait(&ts.wcv, &ts.lock);
        (void) pthread_mutex_unlock(&ts.lock);
    } else {
        printf("Starting reader process\n");
        if (pipe(ts.writer_go_pipe) == -1)
            err(1, "Could not create a pipe");
        if (pipe(ts.reader_go_pipe) == -1)
            err(1, "Could not create a pipe");
        switch ((child = fork())) {
        case -1: err(1, "Could not fork a child");
        case  0: forked_reader(&ts); _exit(0);
        default: break;
        }
        (void) close(ts.writer_go_pipe[1]);
        ts.writer_go_pipe[1] = -1;
    }

    printf("Writing two entries into HDB\n");
    if ((ret = hdb_create(context, &dbw, name)))
        krb5_err(context, 1, ret, "Could not get a handle for HDB %s (write)",
                 name);
    if ((ret = dbw->hdb_open(context, dbw, O_RDWR | O_CREAT, 0600)))
        krb5_err(context, 1, ret, "Could not create HDB %s", name);

    /* Add two entries */
    memset(&entw, 0, sizeof(entw));
    if ((ret = make_entry(context, &entw, "foo")) ||
        (ret = dbw->hdb_store(context, dbw, 0, &entw))) {
        (void) unlink(fname_ext);
        krb5_err(context, 1, ret,
                 "Could not store entry for \"foo\" in HDB %s", name);
    }
    free_HDB_entry(&entw);
    if ((ret = make_entry(context, &entw, "bar")) ||
        (ret = dbw->hdb_store(context, dbw, 0, &entw))) {
        (void) unlink(fname_ext);
        krb5_err(context, 1, ret,
                 "Could not store entry for \"foo\" in HDB %s", name);
    }
    free_HDB_entry(&entw);

    /* Tell the reader to start reading */
    readers_turn(&ts, child, threaded);

    /* Store one more entry */
    if ((ret = make_entry(context, &entw, "foobar")) ||
        (ret = dbw->hdb_store(context, dbw, 0, &entw))) {
        (void) unlink(fname_ext);
        krb5_err(context, 1, ret,
                 "Could not store entry for \"foobar\" in HDB %s "
                 "while iterating it", name);
    }
    free_HDB_entry(&entw);

    /* Tell the reader to go again */
    readers_turn(&ts, child, threaded);

    dbw->hdb_close(context, dbw);
    dbw->hdb_destroy(context, dbw);
    if (threaded) {
        (void) pthread_join(reader_thread, NULL);
    } else {
        (void) close(ts.writer_go_pipe[1]);
        (void) close(ts.reader_go_pipe[0]);
        (void) close(ts.reader_go_pipe[1]);
        while (wait(&status) == -1 && errno == EINTR)
            ;
        (void) close(ts.writer_go_pipe[0]);
        if (!WIFEXITED(status))
            errx(1, "Child reader died");
        if (WEXITSTATUS(status) != 0)
            errx(1, "Child reader errored");
    }
    (void) unlink(fname_ext);
    krb5_free_context(context);
}

static int use_fork;
static int use_threads;
static int help_flag;
static int version_flag;

struct getargs args[] = {
    { "use-fork",	'f',	arg_flag,   &use_fork,  NULL, NULL },
    { "use-threads",	't',	arg_flag,   &use_threads,  NULL, NULL },
    { "help",		'h',	arg_flag,   &help_flag,    NULL, NULL },
    { "version",	0,	arg_flag,   &version_flag, NULL, NULL }
};

static int num_args = sizeof(args) / sizeof(args[0]);

int
main(int argc, char **argv)
{
    char stemplate[sizeof("sqlite:testhdb-XXXXXX")];
#ifdef HAVE_LMDB
    char ltemplate[sizeof("lmdb:testhdb-XXXXXX")];
#endif
    int o = 0;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &o))
	krb5_std_usage(1, args, num_args);

    if (help_flag)
	krb5_std_usage(0, args, num_args);

    if (version_flag){
	print_version(NULL);
	return 0;
    }

    if (!use_fork && !use_threads)
        use_threads = use_fork = 1;

#ifdef HAVE_FORK
    if (use_fork) {
        printf("Testing SQLite3 HDB backend (multi-process)\n");
        memcpy(stemplate, "sqlite:testhdb-XXXXXX", sizeof("sqlite:testhdb-XXXXXX"));
        test_hdb_concurrency(stemplate, "", 0);

#ifdef HAVE_LMDB
        printf("Testing LMDB HDB backend (multi-process)\n");
        memcpy(ltemplate, "lmdb:testhdb-XXXXXX", sizeof("lmdb:testhdb-XXXXXX"));
        test_hdb_concurrency(ltemplate, ".lmdb", 0);
#endif
    }
#endif

    if (use_threads) {
        printf("Testing SQLite3 HDB backend (multi-process)\n");
        memcpy(stemplate, "sqlite:testhdb-XXXXXX", sizeof("sqlite:testhdb-XXXXXX"));
        test_hdb_concurrency(stemplate, "", 1);

#ifdef HAVE_LMDB
        printf("Testing LMDB HDB backend (multi-process)\n");
        memcpy(ltemplate, "lmdb:testhdb-XXXXXX", sizeof("lmdb:testhdb-XXXXXX"));
        test_hdb_concurrency(ltemplate, ".lmdb", 1);
#endif
    }
    return 0;
}
