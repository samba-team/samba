/* rpw.c */
/* Copyright (C) 1993 Eric Young - see README for more details */
#include <stdio.h>
#include "des.h"

void
main(void)
{
  des_cblock k,k1;
  int i;

  printf("read passwd\n");
  if ((i=des_read_password((des_cblock *)k,"Enter password:",0)) == 0)
    {
      printf("password = ");
      for (i=0; i<8; i++)
	printf("%02x ",k[i]);
    }
  else
    printf("error %d\n",i);
  printf("\n");
  printf("read 2passwds and verify\n");
  if ((i=des_read_2passwords((des_cblock *)k,(des_cblock *)k1,
			     "Enter verified password:",1)) == 0)
    {
      printf("password1 = ");
      for (i=0; i<8; i++)
	printf("%02x ",k[i]);
      printf("\n");
      printf("password2 = ");
      for (i=0; i<8; i++)
	printf("%02x ",k1[i]);
      printf("\n");
    }
  else
    printf("error %d\n",i);
}
