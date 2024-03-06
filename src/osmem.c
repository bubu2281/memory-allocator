// SPDX-License-Identifier: BSD-3-Clause
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"
#include "printf.h"



#define META_SIZE       ((sizeof(struct block_meta)/8 + (sizeof(struct block_meta) % 8 != 0)) * 8)
#define MMAP_THRESHOLD      (128 * 1024)
#define ALIGN(size)		(((size) + 7) & ~7)
#define PAGE_SIZE		getpagesize()

//global variables
int is_first_heap = 1;
int is_calloc;
int is_realloc;
struct block_meta *blocks;


struct block_meta *search_best_block(struct block_meta *block, size_t size)
{
	if (block == NULL)
		return NULL;
	size_t min_size = 9999999;
	struct block_meta *best_block = NULL;

	while (block) {
		if ((min_size > ALIGN(block->size)) && (block->size >= size) && (block->status == STATUS_FREE)) {
			min_size = block->size;
			best_block = block;
		}
		block = block->next;
	}
	return best_block;
}

void coalesce(struct block_meta *blocky)
{
	int repeat = 0;

	while (blocky) {
		repeat = 0;
		if (blocky->next) {
			if (blocky->status == STATUS_FREE && blocky->next->status == STATUS_FREE) {
				struct block_meta *coalesce_block = blocky->next;

				blocky->size = ALIGN(blocky->size) + META_SIZE + ALIGN(coalesce_block->size);
				blocky->next = coalesce_block->next;
				if (blocky->next)
					blocky->next->prev = blocky;
				repeat = 1;
			}
		}
		if (!repeat)
			blocky = blocky->next;
	}
}

struct block_meta *last_block(struct block_meta *block)
{
	struct block_meta *ant = NULL;

	while (block) {
		ant = block;
		block = block->next;
	}
	return ant;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	if (blocks && !is_realloc)
		coalesce(blocks);

	// preallocate heap
	size_t limit;

	if (!is_calloc)
		limit = MMAP_THRESHOLD;
	else
		limit = PAGE_SIZE - META_SIZE;
	if (size < limit) {
		if (is_first_heap) {
			//preallocate heap
			blocks = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			if (blocks != NULL) {
				blocks->size = MMAP_THRESHOLD - META_SIZE;
				blocks->status = STATUS_ALLOC;
				blocks->next = NULL;
				blocks->prev = NULL;
				is_first_heap = 0;
				return (char *)blocks + META_SIZE;
			}
		}
		struct block_meta *best_block = search_best_block(blocks, size);

		if (best_block != NULL) {
			int remaining_size = ALIGN(best_block->size) - META_SIZE - ALIGN(size);

			best_block->status = STATUS_ALLOC;
			//split it
			//there is a block in the list that has more bytes than needed
			if (remaining_size >= 1) {
				struct block_meta *split_block = (struct block_meta *)((char *)best_block + ALIGN(META_SIZE + size));

				split_block->size = remaining_size;
				split_block->next = best_block->next;
				split_block->prev = best_block;
				best_block->next = split_block;
				split_block->status = STATUS_FREE;
				best_block->size = ALIGN(size);
			}
			return (char *)best_block + META_SIZE;
		}
		//do not split it

		//the last block in the list is free and we can expand it
		if ((last_block(blocks) != NULL) && (last_block(blocks)->status == STATUS_FREE)) {
			if (last_block(blocks)->size < size) {
				struct block_meta *last = last_block(blocks);
				size_t needed_size = ALIGN(size) - ALIGN(last->size);

				sbrk(ALIGN(needed_size));
				last->status = STATUS_ALLOC;
				last->size = ALIGN(size);
				return (char *)last + META_SIZE;
			}
		}

		//there is no block in the list that is free and has the required size
		struct block_meta *new_block = sbrk(ALIGN(size + META_SIZE));

		new_block->size = ALIGN(size);
		new_block->status = STATUS_ALLOC;
		new_block->next = NULL;
		new_block->prev = last_block(blocks);
		if (last_block(blocks))
			last_block(blocks)->next = new_block;
		else
			blocks = new_block;
		return (char *)new_block + META_SIZE;
	}
	struct block_meta *best_block;

		best_block = (struct block_meta *)mmap(NULL, ALIGN(size + META_SIZE),
			PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
		best_block->size = ALIGN(size);
		best_block->status = STATUS_MAPPED;
		best_block->prev = NULL;
		best_block->next = NULL;
	return ((char *)best_block) + META_SIZE;
	return NULL;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	ptr = ((char *)ptr) - META_SIZE;
	struct block_meta *meta = (struct block_meta *)ptr;

	if (meta->status == STATUS_MAPPED) {
		munmap(ptr, ALIGN(((struct block_meta *)ptr)->size + META_SIZE));
		return;
	}
	if (meta->status == STATUS_ALLOC) {
		meta->status = STATUS_FREE;
		meta->size = ALIGN(meta->size);
		return;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	is_calloc = 1;
	void *block = os_malloc(nmemb*size);

	is_calloc = 0;
	if (!block)
		return NULL;
	memset(block, 0, nmemb * size);
	return block;
}

void printf_blocks(struct block_meta *block, void *new_ptr, void *ptr, size_t size)
{
	printf("realloc(%d)\n", size);
	while (block) {
		printf("(%d[%d])", block->size, block->status);
		if ((void *)(block + 1) == (void *)new_ptr)
			printf("<--new ");
		if ((void *)(block + 1) == (void *)ptr)
			printf("<--old ");
		block = block->next;
		printf("\n");
	}
	printf("\n\n");
}

int split_special_case(size_t size)
{
	struct block_meta *iter = blocks;
	int ret = 0;

	while (iter && iter->status == 1)
		iter = iter->next;
	if (iter == NULL)
		return 0;
	while (iter && iter->status == 0) {
		if (iter->size <= size)
			ret = 1;
		iter = iter->next;
	}
	if (iter == NULL)
		return 0;
	while (iter && iter->status == 1)
		iter = iter->next;
	if (iter == NULL)
		return 1;
	while (iter && iter->status == 0)
		iter = iter->next;
	if (iter == NULL)
		return 0;
	if (iter->status == 1) {
		if (iter->next && iter->next->status == 1)
			ret = 1;
		return ret;
	}
	return 0;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *meta = (struct block_meta *)((char *)ptr - META_SIZE);

	//measure to prevent undefined behavior
	if (meta->status == STATUS_FREE)
		return NULL;
	if (meta->status == STATUS_ALLOC) {
		meta->status = STATUS_FREE;
		coalesce(meta);
		meta->status = STATUS_ALLOC;
	}

	printf_blocks(blocks, NULL, ptr, size);
	if ((last_block(blocks) != NULL) && (last_block(blocks) == meta) && split_special_case(size)) {
		if (last_block(blocks)->size <= size + META_SIZE) {
			struct block_meta *last = last_block(blocks);
			int needed_size = ALIGN(size) - ALIGN(last->size);

			if (needed_size > 0)
				sbrk(ALIGN(needed_size));
			last->status = STATUS_ALLOC;
			last->size = ALIGN(size);
			printf_blocks(blocks, NULL, ptr, size);
			printf("expand");
			return (char *)last + META_SIZE;
		}
	}
	if ((meta->size > ALIGN(size) + META_SIZE) && meta->status == STATUS_ALLOC) {
		struct block_meta *split_block = (struct block_meta *)((char *)meta + ALIGN(META_SIZE + size));

		split_block->size = ALIGN(meta->size - ALIGN(size) - META_SIZE);
		split_block->next = meta->next;
		split_block->prev = meta;
		meta->next = split_block;
		split_block->status = STATUS_FREE;
		meta->size = ALIGN(size);
		printf("split");
		return (char *)meta + META_SIZE;
	}
	if (meta->status == STATUS_ALLOC)
		os_free(ptr);
	is_realloc = 1;
	void *new_ptr = os_malloc(size);

	is_realloc = 0;
	size_t size_copied;

	if (size > meta->size)
		size_copied = meta->size;
	else
		size_copied = size;
	memcpy(new_ptr, ptr, ALIGN(size_copied));
	if (meta->status == STATUS_MAPPED)
		os_free(ptr);
	printf("final");
	printf_blocks(blocks, new_ptr, ptr, size);
	return new_ptr;
}
