#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include "sma.h"

int
main(void)
{
  SMA_REGION *region;
  void *address[50];
  unsigned long size;
  int n;
  struct timeval time_before, time_after;
  unsigned long sma_time = 0, os_time = 0;

  region = sma_alloc_region(20000, 50); /* sma_alloc_region() will round this up to the next power of 2 */

  /* force the system to adapt to our expected requirements */
  sma_init_page(region, 256);
  sma_init_page(region, 512);
  sma_init_page(region, 1024);
  sma_init_page(region, 2048);
  sma_init_page(region, 4096);
  sma_init_page(region, 4096);
  sma_init_page(region, 8192);
  sma_init_page(region, 8192);
  sma_init_page(region, 8192);
  sma_init_page(region, 16384);
  sma_init_page(region, 16384);
  sma_init_page(region, 16384);
  sma_init_page(region, 16384);
  sma_init_page(region, 16384);

  printf("Tests are done on a region of 24 pages of 32768 bytes\n");

  if (region == NULL)
  {
    return 1;
  }

  sma_set_threshold(region, 200);

  /* malloc(), free() */

  printf("malloc(), free()\n");

  /* Test 1 */
  printf("\nTest 1: allocate and free 1 block of size 200, 2 times\n");

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 200);
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(200);
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 30);
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(30);
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 2 */
  printf("\nTest 2: allocate and free 10 block of size 200\n");

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = sma_alloc(region, 200);
  }
  for (n = 0; n < 10; n++)
  {
    sma_free(region, address[n]);
  }
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = malloc(200);
  }
  for (n = 0; n < 10; n++)
  {
    free(address[n]);
  }
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 3 */
  printf("\nTest 3: allocate and free 50 block of size 200\n");

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 50; n++)
  {
    address[n] = sma_alloc(region, 200);
  }
  for (n = 0; n < 50; n++)
  {
    sma_free(region, address[n]);
  }
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 50; n++)
  {
    address[n] = malloc(200);
  }
  for (n = 0; n < 50; n++)
  {
    free(address[n]);
  }
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 4 */
  printf("\nTest 4: allocate and free 1 block of size 20000\n");

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 20000);
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(20000);
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* realloc() */

  printf("\nmalloc(), multiple realloc()s, free()\n");

  /* Test 1 */
  printf("\nTest 1: allocate 1 block, initial size 4, realloc() to 20000 and free the block, 2 times\n");

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 4);
  for (size = 8; size < 20000; size += 4)
  {
    address[0] = sma_realloc(region, address[0], size);
  }
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(4);
  for (size = 8; size < 20000; size += 4)
  {
    address[0] = realloc(address[0], size);
  }
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 4);
  for (size = 8; size < 20000; size += 4)
  {
    address[0] = sma_realloc(region, address[0], size);
  }
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(4);
  for (size = 8; size < 20000; size += 4)
  {
    address[0] = realloc(address[0], size);
  }
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 2 */
  printf("\nTest 2: allocate 10 blocks, initial size 4, realloc() to 20000 and free the blocks\n");

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = sma_alloc(region, 4);
  }
  for (size = 8; size < 20000; size += 4)
  {
    for (n = 0; n < 10; n++)
    {
      address[n] = sma_realloc(region, address[n], size);
    }
  }
  for (n = 0; n < 10; n++)
  {
    sma_free(region, address[n]);
  }
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = malloc(4);
  }
  for (size = 8; size < 20000; size += 4)
  {
    for (n = 0; n < 10; n++)
    {
      address[n] = realloc(address[n], size);
    }
  }
  for (n = 0; n < 10; n++)
  {
    free(address[n]);
  }
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 4 */
  printf("\nTest 4: allocate 1 block, initial size 4, realloc() to 500000 and free the block\n");

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 4);
  for (size = 8; size < 500000; size += 4)
  {
    address[0] = sma_realloc(region, address[0], size);
  }
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(4);
  for (size = 8; size < 500000; size += 4)
  {
    address[0] = realloc(address[0], size);
  }
  free(address[0]);
  gettimeofday(&time_after, NULL);

  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 5 */
  printf("\nTest 5: allocate 10 blocks, initial size 4, realloc() to 500000 and free the blocks\n");

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = sma_alloc(region, 4);
  }
  for (size = 8; size < 500000; size += 4)
  {
    for (n = 0; n < 10; n++)
    {
      address[n] = sma_realloc(region, address[n], size);
    }
  }
  for (n = 0; n < 10; n++)
  {
    sma_free(region, address[n]);
  }
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  for (n = 0; n < 10; n++)
  {
    address[n] = malloc(4);
  }
  for (size = 8; size < 500000; size += 4)
  {
    for (n = 0; n < 10; n++)
    {
      address[n] = realloc(address[n], size);
    }
  }
  for (n = 0; n < 10; n++)
  {
    free(address[n]);
  }
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* Test 7 */
  printf("\nTest 7: allocate 1 block, initial size 4, realloc() to 200 and free the block, 2 times\n");

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 4);
  for (size = 8; size < 200; size += 4)
  {
    address[0] = sma_realloc(region, address[0], size);
  }
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(4);
  for (size = 8; size < 200; size += 4)
  {
    address[0] = realloc(address[0], size);
  }
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  gettimeofday(&time_before, NULL);
  address[0] = sma_alloc(region, 4);
  for (size = 8; size < 200; size += 4)
  {
    address[0] = sma_realloc(region, address[0], size);
  }
  sma_free(region, address[0]);
  gettimeofday(&time_after, NULL);
  sma_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  gettimeofday(&time_before, NULL);
  address[0] = malloc(4);
  for (size = 8; size < 200; size += 4)
  {
    address[0] = realloc(address[0], size);
  }
  free(address[0]);
  gettimeofday(&time_after, NULL);
  os_time = ((time_after.tv_sec - time_before.tv_sec) * 1000000) + time_after.tv_usec - time_before.tv_usec;

  printf("sma time %lu, os time %lu, difference %li, percentage %+li\n", sma_time, os_time, os_time - sma_time, sma_time * 100 / os_time - 100);

  /* End */

  sma_free_region(region);

  return 0;
}
