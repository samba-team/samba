#include "krb5_locl.h"

static void
rr13(unsigned char *buf, size_t len)
{
    unsigned char *tmp;
    int bytes = (len + 7) / 8;
    int i;
    const int bits = 13 % len;
    const int lbit = len % 8;
    
    tmp = malloc(bytes);
    memcpy(tmp, buf, bytes);
    if(lbit) {
	/* pad final byte with inital bits */
	tmp[bytes - 1] &= 0xff << (8 - lbit);
	for(i = lbit; i < 8; i += len)
	    tmp[bytes - 1] |= buf[0] >> i;
    }
    for(i = 0; i < bytes; i++) {
	int bb;
	int b1, s1, b2, s2;
	/* calculate first bit position of this byte */
	bb = 8 * i - bits;
	while(bb < 0)
	    bb += len;
	/* byte offset and shift count */
	b1 = bb / 8;
	s1 = bb % 8;
	
	if(bb + 8 > bytes * 8) 
	    /* watch for wraparound */
	    s2 = (len + 8 - s1) % 8;
	else 
	    s2 = 8 - s1;
	b2 = (b1 + 1) % bytes;
	buf[i] = (tmp[b1] << s1) | (tmp[b2] >> s2);
    }
    free(tmp);
}

/* Add `b' to `a', both beeing one's complement numbers. */
static void
add1(unsigned char *a, unsigned char *b, size_t len)
{
    int i;
    int carry = 0;
    for(i = len - 1; i >= 0; i--){
	int x = a[i] + b[i] + carry;
	carry = x > 0xff;
	a[i] = x & 0xff;
    }
    for(i = len - 1; carry && i >= 0; i--){
	int x = a[i] + carry;
	carry = x > 0xff;
	a[i] = carry & 0xff;
    }
}

void
n_fold(const void *str, size_t len, void *key, size_t size)
{
    /* if len < size we need at most N * len bytes, ie < 2 * size;
       if len > size we need at most 2 * len */
    size_t maxlen = 2 * max(size, len);
    size_t l = 0;
    unsigned char *tmp = malloc(maxlen);
    unsigned char *buf = malloc(len);
    
    memcpy(buf, str, len);
    memset(key, 0, size);
    do {
	memcpy(tmp + l, buf, len);
	l += len;
	rr13(buf, len * 8);
	while(l >= size) {
	    add1(key, tmp, size);
	    l -= size;
	    if(l == 0)
		break;
	    memmove(tmp, tmp + size, l);
	}
    } while(l != 0);
    memset(buf, 0, len);
    free(buf);
    memset(tmp, 0, maxlen);
    free(tmp);
}
