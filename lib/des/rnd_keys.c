#ifdef HAVE_CONFIG_H
#include "config.h"
#include "protos.h"

RCSID("$Id$");
#endif

#include <des.h>

#include <sys/bitypes.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

/*
 * Generate "random" data by checksumming a file.
 *
 * Returns -1 if there were any problems with permissions or I/O
 * errors.
 */
static
int
sumFile (const char *name, int len, void *sum_)
{
  int32_t *sum = sum_;
  int32_t buf[1024*2];
  int fd, i;

  fd = open (name, 0);
  if (fd < 0)
    return -1;

  while (len > 0)
    {
      int n = read(fd, buf, sizeof(buf));
      if (n < 0)
	{
	  close(fd);
	  return n;
	}
      for (i = 0; i < (n/sizeof(buf[0])); i++)
	{
	  sum[0] += buf[i];
	  i++;
	  sum[1] += buf[i];
	}
      len -= n;
    }
  close (fd);
  return 0;
}

#if 0
static
int
md5sumFile (const char *name, int len, int32_t sum[4])
{
  int32_t buf[1024*2];
  int fd, cnt;
  struct md5 md5;

  fd = open (name, 0);
  if (fd < 0)
    return -1;

  md5_init(&md5);
  while (len > 0)
    {
      int n = read(fd, buf, sizeof(buf));
      if (n < 0)
	{
	  close(fd);
	  return n;
	}
      md5_update(&md5, buf, n);
      len -= n;
    }
  md5_finito(&md5, (unsigned char *)sum);
  close (fd);
  return 0;
}
#endif

/*
 * Create a sequence of random 64 bit blocks.
 * The sequence is indexed with a long long and 
 * based on an initial des key used as a seed.
 */
static des_key_schedule sequence_seed;
static u_int32_t sequence_index[2];

/* 
 * Random number generator based on ideas from truerand in cryptolib
 * as described on page 424 in Applied Cryptography 2 ed. by Bruce
 * Schneier.
 */

static volatile int counter;
static volatile unsigned char *gdata; /* Global data */
static volatile int igdata;	/* Index into global data */
static int gsize;

static
RETSIGTYPE
sigALRM(int sig)
{
    if (igdata < gsize)
	gdata[igdata++] ^= counter & 0xff;

    SIGRETURN(0);
}

/*
 * Generate size bytes of "random" data using timed interrupts.
 * It takes about 40ms/byte random data.
 * It's not neccessary to be root to run it.
 */
static
void
des_rand_data(unsigned char *data, int size)
{
    struct itimerval tv, otv;
    struct sigaction sa, osa;
    int i, j;
  
    /*
     * If there is a /dev/random it's use is preferred.
     */
    {
      int fd = open("/dev/random", O_RDONLY);
      if (fd != -1 && read(fd, data, size) == size)
	  return;
      if (fd != -1)
	  close(fd);
    }

    /* Paranoia? Initialize data from /dev/mem if we can read it. */
    if (size >= 8)
      sumFile("/dev/mem", (1024*1024*2), data);

    gdata = data;
    gsize = size;
    igdata = 0;

    /* Setup signal handler */
    sa.sa_handler = sigALRM;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, &osa);
  
    /* Start timer */
    tv.it_value.tv_sec = 0;
    tv.it_value.tv_usec = 10 * 1000; /* 10 ms */
    tv.it_interval = tv.it_value;
    setitimer(ITIMER_REAL, &tv, &otv);

    for(i = 0; i < 4; i++) {
	for (igdata = 0; igdata < size;) /* igdata++ in sigALRM */
	    counter++;
	for (j = 0; j < size; j++) /* Only use 2 bits each lap */
	    gdata[j] = (gdata[j]>>2) | (gdata[j]<<6);
    }
    setitimer(ITIMER_REAL, &otv, 0);
    sigaction(SIGALRM, &osa, 0);
}

void
des_generate_random_block(des_cblock *block)
{
  des_rand_data((unsigned char *)block, sizeof(*block));
}

#if 0
/*
 * Generate a "random" DES key.
 */
void
des_rand_data_key(des_cblock *key)
{
    unsigned char data[8];
    des_key_schedule sched;
    do {
	des_rand_data(data, sizeof(data));
	des_rand_data((unsigned char*)key, sizeof(des_cblock));
	des_set_odd_parity(key);
	des_key_sched(key, sched);
	des_ecb_encrypt(&data, key, sched, DES_ENCRYPT);
	memset(&data, 0, sizeof(data));
	memset(&sched, 0, sizeof(sched));
	des_set_odd_parity(key);
    } while(des_is_weak_key(key));
}

/*
 * Generate "random" data by checksumming /dev/mem
 *
 * It's neccessary to be root to run it. Returns -1 if there were any
 * problems with permissions.
 */
int
des_mem_rand8(unsigned char *data)
{
  return 1;
}
#endif

/*
 * In case the generator does not get initialized use this as fallback.
 */
static int initialized;

static void
do_initialize(void)
{
    des_cblock default_seed;
    do {
	des_generate_random_block(&default_seed);
	des_set_odd_parity(&default_seed);
    } while (des_is_weak_key(&default_seed));
    des_init_random_number_generator(&default_seed);
}

#define zero_long_long(ll) do { ll[0] = ll[1] = 0; } while (0)

#define incr_long_long(ll) do { if (++ll[0] == 0) ++ll[1]; } while (0)

#define set_sequence_number(ll) \
memcpy((char *)sequence_index, (ll), sizeof(sequence_index));

/*
 * Set the sequnce number to this value (a long long).
 */
void
des_set_sequence_number(unsigned char *ll)
{
    set_sequence_number(ll);
}

/*
 * Set the generator seed and reset the sequence number to 0.
 */
void
des_set_random_generator_seed(des_cblock *seed)
{
    des_key_sched(seed, sequence_seed);
    zero_long_long(sequence_index);
    initialized = 1;
}

/*
 * Generate a sequence of random des keys
 * using the random block sequence, fixup
 * parity and skip weak keys.
 */
int
des_new_random_key(des_cblock *key)
{
    if (!initialized)
	do_initialize();

    do {
	des_ecb_encrypt((des_cblock *) sequence_index,
			key,
			sequence_seed,
			DES_ENCRYPT);
	incr_long_long(sequence_index);
	/* random key must have odd parity and not be weak */
	des_set_odd_parity(key);
    } while (des_is_weak_key(key));
    return(0);
}

/*
 * des_init_random_number_generator:
 *
 * Initialize the sequence of random 64 bit blocks.  The input seed
 * can be a secret key since it should be well hidden and is also not
 * kept.
 *
 */
void 
des_init_random_number_generator(des_cblock *seed)
{
    struct timeval now;
    des_cblock uniq;
    des_cblock new_key;

    gettimeofday(&now, (struct timezone *)0);
    des_generate_random_block(&uniq);

    /* Pick a unique random key from the shared sequence. */
    des_set_random_generator_seed(seed);
    set_sequence_number((unsigned char *)&uniq);
    des_new_random_key(&new_key);

    /* Select a new nonshared sequence, */
    des_set_random_generator_seed(&new_key);

    /* and use the current time to pick a key for the new sequence. */
    set_sequence_number((unsigned char *)&now);
    des_new_random_key(&new_key);
    des_set_random_generator_seed(&new_key);
}

/* This is for backwards compatibility. */
void
des_random_key(des_cblock ret)
{
    des_new_random_key((des_cblock *)ret);
}

#ifdef TESTRUN
int
main()
{
    unsigned char data[8];
    int i;

    while (1)
        {
	    if (sumFile("/dev/mem", (1024*1024*8), data) != 0)
	      { perror("sumFile"); exit(1); }
            for (i = 0; i < 8; i++)
                printf("%02x", data[i]);
            printf("\n");
        }
}
#endif

#ifdef TESTRUN2
int
main()
{
    des_cblock data;
    int i;

    while (1)
        {
	    do_initialize();
            des_random_key(data);
            for (i = 0; i < 8; i++)
                printf("%02x", data[i]);
            printf("\n");
        }
}
#endif
