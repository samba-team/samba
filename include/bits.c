#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void strupr(char *s)
{
    char *p = s;
    while(*p){
	if(islower(*p))
	    *p = toupper(*p);
	p++;
    }	
}


#define BITSIZE(TYPE)						\
{								\
    int b = 0; TYPE x = 1; char *pre = "u_";			\
    char tmp[128], tmp2[128];					\
    while(x){ x <<= 1; b++; if(x < 0) pre=""; }			\
    if(b >= len){						\
        int tabs;						\
	sprintf(tmp, "%sint%d_t" , pre, len);			\
	sprintf(tmp2, "typedef %s %s;", #TYPE, tmp);		\
	strupr(tmp);						\
	tabs = 5 - strlen(tmp2) / 8;				\
	printf("#ifndef HAVE_%s\n", tmp);			\
	printf("#define HAVE_%s\n", tmp);			\
        printf("%s", tmp2);					\
	while(tabs-- > 0) printf("\t");				\
	printf("/* %2d bits */\n", b);				\
	printf("#endif /* HAVE_%s */\n", tmp);			\
	continue;						\
    }								\
}

int main()
{
    int i, b, len;
    int sizes[] = { 8, 16, 32, 64 };
    printf("#ifndef __BITS_H__\n");
    printf("#define __BITS_H__\n");
    printf("\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(char);
	BITSIZE(short);
	BITSIZE(int);
	BITSIZE(long);
#ifdef HAVE_LONG_LONG
	BITSIZE(long long);
#endif
	printf("/* There is no %d bit type */\n", len);
	break;
    }
    printf("\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(unsigned char);
	BITSIZE(unsigned short);
	BITSIZE(unsigned int);
	BITSIZE(unsigned long);
#ifdef HAVE_LONG_LONG
	BITSIZE(unsigned long long);
#endif
	printf("/* There is no %d bit type */\n", len);
	break;
    }
    printf("\n");
    printf("#endif /* __BITS_H__ */\n");
    return 0;
}
