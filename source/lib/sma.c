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

#include <assert.h>
#include <stdlib.h>
#include "sma.h"

SMA_REGION *
sma_alloc_region(size_t page_size, int num_pages)
{
  SMA_REGION *region;
  SMA_BLOCK *page;
  void *address;
  size_t region_size, info_size;
  size_t block_size, minimal_block_size;
  size_t real_size;
  int page_shift;
  int block_shift;
  int index_mask, index, n;

  assert (page_size > 0);
  assert (num_pages > 0);

  /* calculate next power of 2 page size */
  for (page_shift = 0, block_size = page_size; block_size > 1; block_size >>= 1, page_shift++);
  if (page_size > (1 << page_shift))
  {
    page_shift++;
  }
  page_size = 1 << page_shift;

  /* calculate the region size */
  region_size = page_size * num_pages;  

  /* calculate the minimum block size */
  block_size = page_shift;
  for (block_shift = 0; block_size > 0; block_size >>= 1, block_shift++);
  block_size = 1 << block_shift;

  minimal_block_size = 0;
  while (minimal_block_size != block_size)
  {
    minimal_block_size = block_size;
    block_size = page_shift - block_shift;
    for (block_shift = 0; block_size > 0; block_size >>= 1, block_shift++);
    block_size = 1 << block_shift;
  }

  block_size = 1 << block_shift;

  info_size = sizeof(SMA_REGION);
  info_size += sizeof(SMA_LIST) * block_size;     /* size of free list section */
  info_size += sizeof(unsigned long) * num_pages; /* size of offset table */

  region = malloc(info_size + region_size);
  if (region == NULL)
  {
    return NULL;
  }  

  address = (void*)region;
  address += info_size;

  memset(region, 0, info_size);
  region->region_size = region_size;
  region->start_address = address;
  region->page_size = page_size;
  region->page_shift = page_shift;
  region->block_shift = block_shift;
  region->page_index = page_shift - block_shift;
  region->pages = num_pages;
  region->used_pages = 0;
  region->free_blocks = (SMA_LIST *)(&region->offset_table[num_pages]);
  region->free_pages.page_head = (SMA_BLOCK *)&(region->free_pages.entry_block_dummy);
  region->free_pages.page_dummy = NULL;
  region->free_pages.page_tail = (SMA_BLOCK *)&(region->free_pages.entry_block_head);

  for (index_mask = 1; block_shift > 0; block_shift >>=1, index_mask <<=1, index_mask |= 1);

  region->index_mask = index_mask;
  region->offset_mask = ~index_mask;

  /* link the pages and point to them in the region */
  page = (SMA_BLOCK *)address;
  while (num_pages-- > 0)
  {
    page->next_page = region->free_pages.page_head;
    page->previous_page = page->next_page->previous_page;
    region->free_pages.page_head = page;
    page->next_page->previous_page = page;

    page->next_entry_block = NULL; /* compatibility */
    page = (SMA_BLOCK *)(((void*)page) + page_size);
  }

  /* initialize the free lists */
  for (n = 0; n < block_size; n++)
  {
    region->free_blocks[n].entry_block_head = (SMA_BLOCK *)&(region->free_blocks[n].entry_block_dummy);
    region->free_blocks[n].entry_block_dummy = NULL;
    region->free_blocks[n].entry_block_tail = (SMA_BLOCK *)&(region->free_blocks[n].entry_block_head);
  }

  /* set the threshold index */
  block_size = sizeof(SMA_BLOCK);
  index = region->block_shift;
  real_size = block_size >> index;
  while (real_size > 1)
  {
    real_size >>= 1;
    index++;
  }

  if (block_size > (1 << index))
  {
    index++;
  }

  index -= region->block_shift;
  region->threshold_index = index;

  return region;
}

int
sma_free_region(SMA_REGION *region)
{
  assert (region != NULL);

  if (region->used_pages > 0)
  {
    return -1;
  }

  free(region);
  return 0;
}

void
sma_set_threshold(SMA_REGION *region, size_t size)
{
  int index;
  size_t real_size;

  assert (region != NULL && size > 0);

  index = region->block_shift + region->threshold_index;
  real_size = size >> index;
  while (real_size > 1)
  {
    real_size >>= 1;
    index++;
  }

  if (size > (1 << index))
  {
    index++;
  }

  index -= region->block_shift;
  region->threshold_index = index;
}

void *
sma_alloc(SMA_REGION *region, size_t size)
{
  int index, page, num_blocks;
  unsigned long offset;
  size_t real_size;
  SMA_BLOCK *entry_block, *block;
  SMA_HEADER *header;

  assert (region != NULL && size > 0);

  /* Calculate the index that will give us the actual
   * size of the blocks. The formula for the actual
   * block size is 1 << (region->block_shift + index)
   */
  index = region->block_shift + region->threshold_index;
  real_size = size >> index;
  while (real_size > 1)
  {
    real_size >>= 1;
    index++;
  }
  real_size = 1 << index; 

  if (size > real_size)
  {
    real_size <<= 1;
    index++;
  }
  index -= region->block_shift;

  /* Case 0: the size is bigger than our page !!!
   * - Let the os handle it
   */
  if (index > region->page_index)
  {
    header = (SMA_HEADER *)malloc(real_size + sizeof(SMA_HEADER));
    if (header != NULL)
    {
      header->size = real_size;
      header++;
    }
    return (void *)header;
  }

  entry_block = region->free_blocks[index].entry_block_head;

  /* Case 1: there is no entry block in the slot for the given size
   * - Get a new empty page; if no page is available fall back to the OS
   * - Increase the number pages in use
   * - Remove the page from the free page list
   * - If the page is prepared for another blocksize, remove its
   *   entry block from its slot
   * - Calculate the start address of the page
   * - Devide the page into blocks of the requested size, or return an
       entire page (which concludes this case)
   * - Add the entry block to the free blocks list in the slot for
   *   the given size
   * - Return the last block on the page
   */
  if (entry_block->next_entry_block == NULL)
  {
    /* get a new page */
    entry_block = region->free_pages.page_head;
    if (entry_block->next_page == NULL)
    {
      /* TODO: we could check for a bigger free block :-) */
      header = (SMA_HEADER *)malloc(real_size + sizeof(SMA_HEADER));
      if (header != NULL)
      {
        header->size = real_size;
        header++;
      }
      return (void *)header;
    }

    region->used_pages++;

    /* remove the page from the page free list */
    entry_block->next_page->previous_page = entry_block->previous_page;
    entry_block->previous_page->next_page = entry_block->next_page;

    page = ((void *)entry_block - region->start_address) >> region->page_shift;

    /* If the page was devided in other block sizes, remove the entry block from the
     * free blocks list _and_ calculate the actual page offset 
     */
    if (entry_block->next_entry_block != NULL)
    {
      /* remove the entry block from its list */
      entry_block->next_entry_block->previous_entry_block = entry_block->previous_entry_block;
      entry_block->previous_entry_block->next_entry_block = entry_block->next_entry_block;
    }

    offset = (unsigned long)page << region->page_shift;
    block = entry_block = (SMA_BLOCK *)(region->start_address + offset);

    /* return a full page */
    if (index == region->page_index)
    {
      region->offset_table[page] = region->offset_mask | index;
      return (void *)entry_block;
    }

    num_blocks = (1 << (region->page_index - index)) - 1;
    while (--num_blocks > 0)
    {
      block->next_block = (SMA_BLOCK *)(((void *)block) + real_size);
      block = block->next_block;
    }
    block->next_block = NULL;
    block = (SMA_BLOCK *)(((void *)block) + real_size);

    entry_block->used_blocks = 1;

    entry_block->next_entry_block = region->free_blocks[index].entry_block_head;
    entry_block->previous_entry_block = entry_block->next_entry_block->previous_entry_block;
    region->free_blocks[index].entry_block_head = entry_block;
    entry_block->next_entry_block->previous_entry_block = entry_block;

    region->offset_table[page] = offset | index;

    return (void *)block;
  }

  /* Case 2: There is an entry block, but that's also the last block of the given size.
   * - Remove the entry block from the offset table for this page
   * - Remove the entry block from the free blocks list in the slot for the given size
   * - Return the entry block
   */
  block = entry_block->next_block;
  if (block == NULL)
  {
    page = ((void *)entry_block - region->start_address) >> region->page_shift;
    region->offset_table[page] = region->offset_mask | index;

    /* remove the entry block from its list */
    entry_block->next_entry_block->previous_entry_block = entry_block->previous_entry_block;
    entry_block->previous_entry_block->next_entry_block = entry_block->next_entry_block;

    return (void *)entry_block;
  }

  /* Case 3: There is an entry block, and it has more free blocks to give away :-)
   * - Remove the first block from the free list of the entry block
   * - Increase the number of used blocks for this page
   * - If the block is the first used block of this size, remove the page from
   *   the free page list
   * - Return the block
   */
  entry_block->next_block = block->next_block;
  if (entry_block->used_blocks++ == 0)
  {
    /* remove the page from the page free list */
    entry_block->next_page->previous_page = entry_block->previous_page;
    entry_block->previous_page->next_page = entry_block->next_page;
  }

  return (void *)block;
}

void
sma_free(SMA_REGION *region, void *address)
{
  int index, page;
  SMA_BLOCK *entry_block;
  unsigned long offset;
  SMA_HEADER *header;

  assert (region != NULL && address != NULL);

  /* Case 1: the address is not in our region
   * - Let the OS handle it and exit
   */
  if (address < region->start_address)
  {
    /* address is out of region */
    header = (SMA_HEADER *)address;
    header--;
    free(header);
    return;
  }

  offset = address - region->start_address;
  if (offset > region->region_size)
  {
    /* address is out of region */
    header = (SMA_HEADER *)address;
    header--;
    free(header);
    return;
  }

  page = offset >> region->page_shift;

  /*
   * Find the index representing the block size of the given
   * address
   */
  index = region->offset_table[page] & region->index_mask;
  entry_block = (SMA_BLOCK *)address;

  /* Calculate the offset of the entry block from the start address
   * of the region
   */
  offset = region->offset_table[page] & region->offset_mask;

  /* Case 3: there is no entry block present for this page
   * - Become the new entry block and exit
   */
  if (offset == region->offset_mask)
  {
    /* Case 2: the address is a full page (index has all bits set)
     * - Clear the offset table
     * - Return the page to the free page list and exit
     */
    if (index == region->page_index)
    {
      entry_block->next_entry_block = NULL;
      region->offset_table[page] = 0;
      entry_block->next_page = region->free_pages.page_head;
      entry_block->previous_page = entry_block->next_page->previous_page;
      region->free_pages.page_head = entry_block;
      entry_block->next_page->previous_page = entry_block;
      return;
    }

    /* become new entry block */
    entry_block->next_entry_block = region->free_blocks[index].entry_block_head;
    entry_block->previous_entry_block = entry_block->next_entry_block->previous_entry_block;
    region->free_blocks[index].entry_block_head = entry_block;
    entry_block->next_entry_block->previous_entry_block = entry_block;

    entry_block->next_block = NULL;
    entry_block->used_blocks = (1 << (region->page_index - index)) - 1;
    region->offset_table[page] = (address - region->start_address) | index;

    return;
  }

  /* Case 3: there is an entry block present for this page, but this block isn't the
   *         last block on the page to be returned
   * - Add our block to the free blocks list of the entry block
   */
  entry_block = (SMA_BLOCK *)(region->start_address + offset);
  ((SMA_BLOCK *)address)->next_block = entry_block->next_block;
  entry_block->next_block = (SMA_BLOCK *)address;
  entry_block->used_blocks--;

  if (entry_block->used_blocks > 0)
  {
    return;
  }

  /* Case 4: there is an entry block present for this page and this block is the
   *         last block on the page to be returned
   * - Add our block to the free blocks list of the entry block (this was taken care
   *   of at case 3)
   * - Return the page to the free list (still maintaining a list of free blocks of
   *   the same size)
   * - Reduce the count of pages in use
   */
  entry_block->previous_page = region->free_pages.page_tail;
  entry_block->next_page = entry_block->previous_page->next_page;
  region->free_pages.page_tail = entry_block;
  entry_block->previous_page->next_page = entry_block;

  region->used_pages--;
}

void *
sma_realloc(SMA_REGION *region, void *address, size_t size)
{
  int index, new_index;
  int page, new_page;
  void *new_address;
  size_t real_size;
  unsigned long offset;
  SMA_BLOCK *entry_block, *block;
  SMA_HEADER *header;
  int num_blocks;

  assert (region != NULL && size >= 0);

  /* Case 1: the size is 0, so we guess that the caller is trying to free a block
   * - call sma_free() and return NULL
   */
  if (size == 0)
  {
    sma_free(region, address);
    return NULL;
  }

  /* Case 2: the address is NULL, so we guess the caller requests a free block
   * - call sma_alloc() and return the result
   */
  if (address == NULL)
  {
    return sma_alloc(region, size);
  }

  if (address < region->start_address)
  {
    /* address is out of region, fall back to conventional reallocation */
    header = (SMA_HEADER *)address;
    header--;
    if (header->size >= size)
    {
      return address;
    }
    
    new_index = region->block_shift + region->threshold_index;
    real_size = size >> new_index;
    while (real_size > 1)
    {
      real_size >>= 1;
      new_index++;
    }

    real_size = 1 << new_index;
    if (size > real_size)
    {
      real_size <<= 1;
    }

    header = (SMA_HEADER *)realloc(header, real_size + sizeof(SMA_HEADER));
    if (header != NULL)
    {
      header->size = real_size;
      header++;
    }
    return (void *)header;
  }

  offset = address - region->start_address;
  if (offset > region->region_size)
  {
    /* address is out of region, fall back to conventional reallocation */
    header = (SMA_HEADER *)address;
    header--;
    if (header->size >= size)
    {
      return address;
    }
    
    new_index = region->block_shift + region->threshold_index;
    real_size = size >> new_index;
    while (real_size > 1)
    {
      real_size >>= 1;
      new_index++;
    }

    real_size = 1 << new_index;
    if (size > real_size)
    {
      real_size <<= 1;
    }

    header = (SMA_HEADER *)realloc(header, real_size + sizeof(SMA_HEADER));
    if (header != NULL)
    {
      header->size = real_size;
      header++;
    }
    return (void *)header;
  }

  /* Calculate the index that will give us the actual
   * size of the blocks. The formula for the actual
   * block size is 1 << (region->block_shift + index)
   */

  new_index = region->block_shift + region->threshold_index;
  real_size = size >> new_index;
  while (real_size > 1)
  {
    real_size >>= 1;
    new_index++;
  }

  real_size = 1 << new_index;
  if (size > real_size)
  {
    real_size <<= 1;
    new_index++;
  }

  /* Case 3: the address is out of our region
   * - Let the OS take care of it and return the result
   */

  new_index -= region->block_shift;
  page = offset >> region->page_shift;

  /* Case 4: the requested size already fits in the currently
   *         allocated block
   * - return the same block unaltered
   */
  index = region->offset_table[page] & region->index_mask;
  if (new_index <= index)
  {
    /* allocated memory already fits requirements */
    return address;
  }

  /* Case 5: the requested size doesn't fit into the currently
   *         allocated block
   * - Obtain a new block from sma_alloc()
   * - Copy over old data to new block
   * - Free the old block using sma_free()
   * - return the new block
   */

  /* Case 0: the size is bigger than our page !!!
   * - Let the os handle it
   */
  if (new_index > region->page_index)
  {
    header = (SMA_HEADER *)malloc(real_size + sizeof(SMA_HEADER));
    if (header == NULL)
    {
      return NULL;
    }
    header->size = real_size;
    header++;
    new_address = (void *)header;
  }
  else
  {
    entry_block = region->free_blocks[new_index].entry_block_head;

    /* Case 1: there is no entry block in the slot for the given size
     * - Get a new empty page; if no page is available fall back to the OS
     * - Increase the number pages in use
     * - Remove the page from the free page list
     * - If the page is prepared for another blocksize, remove its
     *   entry block from its slot
     * - Calculate the start address of the page
     * - Devide the page into blocks of the requested size, or return an
         entire page (which concludes this case)
     * - Add the entry block to the free blocks list in the slot for
     *   the given size
     * - Return the last block on the page
     */
    if (entry_block->next_entry_block == NULL)
    {
      /* get a new page */
      entry_block = region->free_pages.page_head;
      if (entry_block->next_page == NULL)
      {
        /* TODO: we could check for a bigger free block :-) */
        header = (SMA_HEADER *)malloc(real_size + sizeof(SMA_HEADER));
        if (header == NULL)
        {
          return NULL;
        }
        header->size = real_size;
        header++;
        new_address = (void *)header;
      }
      else
      {
        region->used_pages++;

        /* remove the page from the page free list */
        entry_block->next_page->previous_page = entry_block->previous_page;
        entry_block->previous_page->next_page = entry_block->next_page;

        new_page = ((void *)entry_block - region->start_address) >> region->page_shift;

        /* If the page was devided in other block sizes, remove the entry block from the
         * free blocks list _and_ calculate the actual page offset 
         */
        if (entry_block->next_entry_block != NULL)
        {
          /* remove the entry block from its list */
          entry_block->next_entry_block->previous_entry_block = entry_block->previous_entry_block;
          entry_block->previous_entry_block->next_entry_block = entry_block->next_entry_block;
        }

        offset = (unsigned long)new_page << region->page_shift;
        block = entry_block = (SMA_BLOCK *)(region->start_address + offset);

        /* return a full page */
        if (new_index == region->page_index)
        {
          region->offset_table[new_page] = region->offset_mask | new_index; 
          new_address = (void *)entry_block;
        }
        else
        {
          num_blocks = (1 << (region->page_index - new_index)) - 1;
          while (--num_blocks > 0)
          {
            block->next_block = (SMA_BLOCK *)(((void *)block) + real_size);
            block = block->next_block;
          }
          block->next_block = NULL;
          block = (SMA_BLOCK *)(((void *)block) + real_size);

          entry_block->used_blocks = 1;

          entry_block->next_entry_block = region->free_blocks[index].entry_block_head;
          entry_block->previous_entry_block = entry_block->next_entry_block->previous_entry_block;
          region->free_blocks[index].entry_block_head = entry_block;
          entry_block->next_entry_block->previous_entry_block = entry_block;

          region->offset_table[new_page] = offset | new_index;

          new_address = (void *)block;
        }
      }
    }
    else
    {
      /* Case 2: There is an entry block, but that's also the last block of the given size.
       * - Remove the entry block from the offset table for this page
       * - Remove the entry block from the free blocks list in the slot for the given size
       * - Return the entry block
       */
      block = entry_block->next_block;
      if (block == NULL)
      {
        new_page = ((void *)entry_block - region->start_address) >> region->page_shift;
        region->offset_table[new_page] = region->offset_mask | new_index;

        /* remove the entry block from its list */
        entry_block->next_entry_block->previous_entry_block = entry_block->previous_entry_block;
        entry_block->previous_entry_block->next_entry_block = entry_block->next_entry_block;

        new_address = (void *)entry_block;
      }
      else
      {
       /* Case 3: There is an entry block, and it has more free blocks to give away :-)
        * - Remove the first block from the free list of the entry block
        * - Increase the number of used blocks for this page
        * - If the block is the first used block of this size, remove the page from
        *   the free page list
        * - Return the block
        */
        entry_block->next_block = block->next_block;
        if (entry_block->used_blocks++ == 0)
        {
          /* remove the page from the page free list */
          entry_block->next_page->previous_page = entry_block->previous_page;
          entry_block->previous_page->next_page = entry_block->next_page;
        }

        new_address = (void *)block;
      }
    }
  }

  /* since the old and new memory areas never overlap we can use memcpy */
  memcpy(new_address, address, 1 << (region->block_shift + index));

  /*
   * Find the index representing the block size of the given
   * address
   */
  entry_block = (SMA_BLOCK *)address;

  /* Calculate the offset of the entry block from the start address
   * of the region
   */
  offset = region->offset_table[page] & region->offset_mask;

  /* Case 3: there is no entry block present for this page
   * - Become the new entry block and exit
   */
  if (offset == region->offset_mask)
  {
    /* Case 2: the address is a full page (index has all bits set)
     * - Clear the offset table
     * - Return the page to the free page list and exit
     */
    if (index == region->page_index)
    {
      entry_block->next_entry_block = NULL;
      region->offset_table[page] = 0;
      entry_block->next_page = region->free_pages.page_head;
      entry_block->previous_page = entry_block->next_page->previous_page;
      region->free_pages.page_head = entry_block;
      entry_block->next_page->previous_page = entry_block;
      return new_address;
    }

    /* become new entry block */
    entry_block->next_entry_block = region->free_blocks[index].entry_block_head;
    entry_block->previous_entry_block = entry_block->next_entry_block->previous_entry_block;
    region->free_blocks[index].entry_block_head = entry_block;
    entry_block->next_entry_block->previous_entry_block = entry_block;

    entry_block->next_block = NULL;
    entry_block->used_blocks = (1 << (region->page_index - index)) - 1;
    region->offset_table[page] = (address - region->start_address) | index;

    return new_address;
  }

  /* Case 3: there is an entry block present for this page, but this block isn't the
   *         last block on the page to be returned
   * - Add our block to the free blocks list of the entry block
   */
  entry_block = (SMA_BLOCK *)(region->start_address + offset);
  ((SMA_BLOCK *)address)->next_block = entry_block->next_block;
  entry_block->next_block = (SMA_BLOCK *)address;
  entry_block->used_blocks--;

  if (entry_block->used_blocks > 0)
  {
    return new_address;
  }

  /* Case 4: there is an entry block present for this page and this block is the
   *         last block on the page to be returned
   * - Add our block to the free blocks list of the entry block (this was taken care
   *   of at case 3)
   * - Return the page to the free list (still maintaining a list of free blocks of
   *   the same size)
   * - Reduce the count of pages in use
   */
  entry_block->previous_page = region->free_pages.page_tail;
  entry_block->next_page = entry_block->previous_page->next_page;
  region->free_pages.page_tail = entry_block;
  entry_block->previous_page->next_page = entry_block;

  region->used_pages--;

  return new_address;
}

void
sma_init_page(SMA_REGION *region, size_t size)
{
  int index, page, num_blocks;
  unsigned long offset;
  size_t real_size;
  SMA_BLOCK *entry_block, *block;

  assert (region != NULL && size > 0);

  /* Calculate the index that will give us the actual
   * size of the blocks. The formula for the actual
   * block size is 1 << (region->block_shift + index)
   */
  index = region->block_shift + region->threshold_index;
  real_size = size >> index;
  while (real_size > 1)
  {
    real_size >>= 1;
    index++;
  }
  real_size = 1 << index; 

  if (size > real_size)
  {
    real_size <<= 1;
    index++;
  }
  index -= region->block_shift;

  if (index >= region->page_index)
  {
    return;
  }

  /* get a new page */
  entry_block = region->free_pages.page_head;
  if (entry_block->next_page == NULL)
  {
    return;
  }

  /* remove the page from the page free list */
  entry_block->next_page->previous_page = entry_block->previous_page;
  entry_block->previous_page->next_page = entry_block->next_page;

  page = ((void *)entry_block - region->start_address) >> region->page_shift;

  /* If the page was devided in other block sizes, remove the entry block from the
   * free blocks list _and_ calculate the actual page offset 
   */
  if (entry_block->next_entry_block != NULL)
  {
    /* remove the entry block from its list */
    entry_block->next_entry_block->previous_entry_block = entry_block->previous_entry_block;
    entry_block->previous_entry_block->next_entry_block = entry_block->next_entry_block;
  }

  offset = (unsigned long)page << region->page_shift;
  block = entry_block = (SMA_BLOCK *)(region->start_address + offset);

  num_blocks = 1 << (region->page_index - index);
  while (--num_blocks > 0)
  {
    block->next_block = (SMA_BLOCK *)(((void *)block) + real_size);
    block = block->next_block;
  }
  block->next_block = NULL;

  entry_block->used_blocks = 0;

  entry_block->next_entry_block = region->free_blocks[index].entry_block_head;
  entry_block->previous_entry_block = entry_block->next_entry_block->previous_entry_block;
  region->free_blocks[index].entry_block_head = entry_block;
  entry_block->next_entry_block->previous_entry_block = entry_block;

  region->offset_table[page] = offset | index;

  entry_block->previous_page = region->free_pages.page_tail;
  entry_block->next_page = entry_block->previous_page->next_page;
  region->free_pages.page_tail = entry_block;
  entry_block->previous_page->next_page = entry_block;
}