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
    int b = 0; TYPE x = 1, zero = 0; char *pre = "u_";		\
    char tmp[128], tmp2[128];					\
    while(x){ x <<= 1; b++; if(x < zero) pre=""; }		\
    if(b >= len){						\
        int tabs;						\
	sprintf(tmp, "%sint%d_t" , pre, len);			\
	sprintf(tmp2, "typedef %s %s;", #TYPE, tmp);		\
	strupr(tmp);						\
	tabs = 5 - strlen(tmp2) / 8;				\
	fprintf(f, "#ifndef HAVE_%s\n", tmp);			\
	fprintf(f, "#define HAVE_%s\n", tmp);			\
        fprintf(f, "%s", tmp2);					\
	while(tabs-- > 0) fprintf(f, "\t");			\
	fprintf(f, "/* %2d bits */\n", b);			\
	fprintf(f, "#endif /* HAVE_%s */\n", tmp);		\
	continue;						\
    }								\
}

int main(int argc, char **argv)
{
    int i, b, len;
    FILE *f;
    int sizes[] = { 8, 16, 32, 64 };
    
    if(argc < 2)
	f = stdout;
    else
	f = fopen(argv[1], "w");
    fprintf(f, "/*\n");
    fprintf(f, " * bits.h -- this file was generated for %s\n", HOST); 
    fprintf(f, " */\n\n");
    fprintf(f, "#ifndef __BITS_H__\n");
    fprintf(f, "#define __BITS_H__\n");
    fprintf(f, "\n");
    fprintf(f, "/* For compatibility with various type definitions */\n");
    fprintf(f, "#ifndef __BIT_TYPES_DEFINED__\n");
    fprintf(f, "#define __BIT_TYPES_DEFINED__\n");
    fprintf(f, "\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(signed char);
	BITSIZE(short);
	BITSIZE(int);
	BITSIZE(long);
#ifdef HAVE_LONG_LONG
	BITSIZE(long long);
#endif
	fprintf(f, "/* There is no %d bit type */\n", len);
	break;
    }
    fprintf(f, "\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(unsigned char);
	BITSIZE(unsigned short);
	BITSIZE(unsigned int);
	BITSIZE(unsigned long);
#ifdef HAVE_LONG_LONG
	BITSIZE(unsigned long long);
#endif
	fprintf(f, "/* There is no %d bit type */\n", len);
	break;
    }
    fprintf(f, "\n");
    fprintf(f, "#endif /* __BIT_TYPES_DEFINED__ */\n");
    fprintf(f, "\n");
    fprintf(f, "#endif /* __BITS_H__ */\n");
    return 0;
}
