#include "des_locl.h"

RCSID("$Id$");

#include <sys/time.h>

#include <unistd.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* this is for broken Solaris */
#ifndef HAVE_GETHOSTID 

#include <sys/systeminfo.h>

static long
gethostid(void)
{
    static int flag=0;
    static long hostid;
    if(!flag){
	char s[32];
	sysinfo(SI_HW_SERIAL, s, 32);
	sscanf(s, "%u", &hostid);
	flag=1;
    }
    return hostid;
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
 * In case the generator does not get inited use this for backup.
 */
static int initialized;
static des_cblock default_seed = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
static void
do_initialize(void)
{
    des_set_odd_parity(&default_seed);
    des_set_random_generator_seed(&default_seed);
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
 * keept.
 *
 */
void 
des_init_random_number_generator(des_cblock *seed)
{
    struct timeval now;
    static long uniq[2];
    des_cblock new_key;

    gettimeofday(&now, (struct timezone *)0);
    if (!uniq[0])
	{
	    struct hostent *hent;
	    char hostname[100];
	    gethostname(hostname, sizeof(hostname));
	    hent = gethostbyname(hostname);
	    if (hent != NULL)
		bcopy(hent->h_addr_list[0], &uniq[0], sizeof(uniq[0]));
	    else
		uniq[0] = gethostid();
#ifdef MSDOS
	    uniq[1] = 1;
#else
	    uniq[1] = getpid();
#endif
	}

    /* Pick a unique random key from the shared sequence. */
    des_set_random_generator_seed(seed);
    set_sequence_number((unsigned char *)uniq);
    des_new_random_key(&new_key);

    /* Select a new nonshared sequence, */
    des_set_random_generator_seed(&new_key);

    /* and use the current time to pick a key for the new sequence. */
    set_sequence_number((unsigned char *)&now);
    des_new_random_key(&new_key);
    des_set_random_generator_seed(&new_key);
}

/*
 * Generate 8 bytes of "random" data by checksumming the first 2
 * megabytes of /dev/mem.
 */
void
des_mem_rand8(unsigned char *data)
{
}

/*
 * These guys are for clocked "non crypto" randomness.
 *
 * The method used is described on page 424 in
 * Applied Cryptography 2 ed. by Bruce Schneier.
 */
static volatile int counter;
static volatile unsigned char *gdata; /* Global data */
static volatile int igdata;	/* Index into global data */

static
RETSIGTYPE
sigALRM(int sig)
{
    if (igdata < sizeof(des_cblock))
	gdata[igdata++] ^= counter & 0xff;

#ifdef VOID_RETSIGTYPE
    return;
#else
    return (RETSIGTYPE)0;
#endif
}

/*
 * Generate size bytes of "random" data using timed interrupts.
 * This is a slooow routine but it's meant to be slow.
 * It's not neccessary to be root to run it.
 */
void
des_clock_rand(unsigned char *data, int size)
{
    struct itimerval tv, otv;
    struct sigaction sa, osa;
    int i;
  
    gdata = data;
    igdata = 0;
    counter = 0;

    /* Setup signal handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigALRM;
    sigaction(SIGALRM, &sa, &osa);
  
    /* Start timer */
    tv.it_value.tv_sec = 0;
    tv.it_value.tv_usec = 50 * 1000; /* 50 ms */
    tv.it_interval = tv.it_value;
    setitimer(ITIMER_REAL, &tv, &otv);

    for(i = 0; i < 4; i++)
	{
	    for (igdata = 0; igdata < size;)
		counter++;
	    for (igdata = 0; igdata < size; igdata++)
		gdata[igdata] = (gdata[igdata]>>2) | (gdata[igdata]<<6);
	}
    setitimer(ITIMER_REAL, &otv, 0);
    sigaction(SIGALRM, &osa, 0);
}

/*
 * Generate a "random" DES key.
 */
void
des_clock_rand_key(des_cblock *key)
{
    do {
	des_clock_rand((unsigned char*)key, sizeof(des_cblock));
	des_set_odd_parity(key);
    } while(des_is_weak_key(key));
}

/* This is for backwards compatibility. */
int
des_random_key(unsigned char *ret)
{
    return des_new_random_key((des_cblock *) ret);
}

#ifdef TESTRUN
int
main()
{
    unsigned char data[8];
    int i;

    while (1)
        {
            des_clock_rand(data, 8);
            for (i = 0; i < 8; i++)
                printf("%02x", data[i]);
            printf("\n");
        }
}
#endif
