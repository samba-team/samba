/* 
 *  
 *
 *  Copyright (C) Sander Striker                    2000.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef SMA_H
#define SMA_H

typedef struct _SMA_BLOCK
{
  struct _SMA_BLOCK  *next_entry_block;     /* The order of the fields do matter! */
  struct _SMA_BLOCK  *next_page;
  struct _SMA_BLOCK  *previous_entry_block;
  struct _SMA_BLOCK  *previous_page;
  struct _SMA_BLOCK  *next_block;
  int                 used_blocks;
} SMA_BLOCK;

typedef struct _SMA_LIST
{
  SMA_BLOCK          *entry_block_head;     /* The order of the fields do matter! */
  SMA_BLOCK          *page_head;
  SMA_BLOCK          *entry_block_dummy;
  SMA_BLOCK          *page_dummy;
  SMA_BLOCK          *entry_block_tail;
  SMA_BLOCK          *page_tail;
} SMA_LIST;

typedef struct _SMA_REGION
{
  void         *start_address;
  size_t        region_size;
  size_t        page_size;
  int           page_shift;
  int           block_shift;
  int           threshold_index;
  int           page_index;
  unsigned long index_mask;
  unsigned long offset_mask;
  int           pages;
  int           used_pages;
  SMA_LIST      free_pages;
  SMA_LIST     *free_blocks;
  unsigned long offset_table[1];
} SMA_REGION;

typedef struct _SMA_HEADER
{
  size_t        size;
} SMA_HEADER;

SMA_REGION *sma_alloc_region(size_t page_size, int num_pages);
void sma_set_threshold(SMA_REGION *region, size_t size);
int sma_free_region(SMA_REGION *region);
void * sma_alloc(SMA_REGION *region, size_t size);
void * sma_realloc(SMA_REGION *region, void *address, size_t size);
void sma_free(SMA_REGION *region, void *address);
void sma_init_page(SMA_REGION *region, size_t size);

#endif /* SMA_H */