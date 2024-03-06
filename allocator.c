// SPDX-License-Identifier: BSD-3-Clause

#include "test-utils.h"
#include <sys/mman.h>
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

struct block_meta *global = NULL, *last = NULL;

struct block_meta *get_block_ptr(void *ptr) {
    return (struct block_meta *)ptr - 1;
}

struct block_meta *get_last(struct block_meta *global) {
    struct block_meta *aux = global;
    while (aux->next) {
        aux = aux->next;
    }
    return aux;
}

struct block_meta *get_global(struct block_meta *block) {
    struct block_meta *aux = block;
    while (aux->prev) {
        aux = aux->prev;
    }
    return aux;
}

void expand_block(struct block_meta *block, size_t size, size_t current_size) {
    struct block_meta *behind = NULL;
    size_t total_size = ALIGN(current_size);
    size_t total_size2 = ALIGN(size);

    current_size = total_size2 - total_size;
    behind = block->prev;
    void *request = sbrk(current_size);
    if (request == (void *)-1) {
        return;
    }
    block->size = size;
    block->status = STATUS_ALLOC;
    block->next = NULL;
    if (behind) {
        behind->next = block;
        block->prev = behind;
    }
}

void merge_blocks(struct block_meta *block) {
    if (!block || block->status != STATUS_FREE) {
        return;
    }
    if (block->next && block->next->status == STATUS_FREE) {
        block->size =
            ALIGN(block->size) + ALIGN(METADATA_SIZE + block->next->size);
        block->next = block->next->next;
        if (block->next) {
            block->next->prev = block;
        }
    }
    if (block->prev && block->prev->status == STATUS_FREE) {
        block->prev->size =
            ALIGN(block->prev->size) + ALIGN(METADATA_SIZE + block->size);
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block->prev;
        }
    }
}

void split_block(struct block_meta *block, size_t size) {
    size_t remaining_size = ALIGN(block->size) - ALIGN(size);

    if (remaining_size >= ALIGN(METADATA_SIZE + 1)) {
        struct block_meta *new_block =
            (struct block_meta *)((char *)block + ALIGN(size) + METADATA_SIZE);

        new_block->size = ALIGN(remaining_size) - METADATA_SIZE;
        new_block->status = STATUS_FREE;
        new_block->prev = block;
        new_block->next = block->next;
        block->size = size;
        block->next = new_block;
        if (new_block->next) {
            new_block->next->prev = new_block;
        }
        merge_blocks(new_block);
    }
}

void realloc_merge(struct block_meta *block, size_t size) {
    struct block_meta *aux = block->next, *old_block = NULL;
    size_t current_size = block->size;
    while (aux->next && current_size < ALIGN(size)) {
        current_size += ALIGN(aux->size + METADATA_SIZE);
        aux = aux->next;
    }
    if (current_size >= ALIGN(size)) {
        current_size -= block->size;
        block->size += current_size;
    }
    old_block = block;
    split_block(block, size);
    if (old_block->size == block->size) {
        block->size = size;
    }
}

struct block_meta *find_best(size_t size) {
    struct block_meta *current = global;
    size_t min_size = 128 * 1024;
    struct block_meta *min_current = NULL;

    while (current->next) {
        if (current->status == STATUS_FREE && current->size >= size &&
            current->size - size < min_size) {
            min_size = current->size - size;
            min_current = current;
        }
        current = current->next;
    }
    if (current->status == STATUS_FREE && current->size >= size &&
        current->size - size < min_size) {
        min_size = current->size - size;
        min_current = current;
    }
    if (current->status == STATUS_FREE && current->size < size &&
        !min_current) {
        min_current = current;
        expand_block(min_current, size, current->size);
    }

    return min_current;
}

struct block_meta *request_space(struct block_meta *last, size_t size,
                                 int status) {
    size_t total_size = ALIGN(size + METADATA_SIZE);

    struct block_meta *block;
    if (status == STATUS_ALLOC) {
        block = sbrk(0);
        void *request = sbrk(total_size);
        if (request == (void *)-1) {
            return NULL;
        }
    } else {
        block =
            (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            return NULL;
        }
    }
    if (last) {
        last->next = block;
        block->prev = last;
        last->next->prev = last;
    }
    block->size = size;
    block->next = NULL;
    block->status = status;

    return block;
}

void *os_malloc(size_t size) {
    struct block_meta *block;
    int status = STATUS_MAPPED;
    if (size <= 0) {
        return NULL;
    }
    if (size + METADATA_SIZE < MMAP_THRESHOLD) {
        status = STATUS_ALLOC;
    }
    if (!global && status == STATUS_ALLOC) {
        block = request_space(NULL, 128 * 1024 - METADATA_SIZE, status);
        if (!block) {
            return NULL;
        }
        global = block;
        last = global;
        last->prev = NULL;
        last->next = NULL;
    } else {
        block = NULL;
        if (global) {
            block = find_best(size);
        }
        if (!block) {
            if (global) {
                last = get_last(global);
            }
            block = request_space(last, size, status);
            if (!block) {
                return NULL;
            }
        } else {
            block->status = status;
            split_block(block, size);
        }
    }
    return block + 1;
}

void os_free(void *ptr) {
    if (!ptr) {
        return;
    }
    struct block_meta *block_ptr = get_block_ptr(ptr), *prev = NULL,
                      *next = NULL;
    size_t size = block_ptr->size;
    prev = block_ptr->prev;
    next = block_ptr->next;
    void *adjusted_ptr = (void *)((uintptr_t)ptr - METADATA_SIZE);
    if (block_ptr->status == STATUS_MAPPED) {
        if (prev && next) {
            prev->next = next;
            prev->next->prev = prev;
            prev->size += ALIGN(size + METADATA_SIZE);
        } else if (prev) {
            prev->next = NULL;
            prev->size += ALIGN(size + METADATA_SIZE);
        }
        munmap((char *)adjusted_ptr, ALIGN(size + METADATA_SIZE));
    } else {
        block_ptr->status = STATUS_FREE;
        merge_blocks(block_ptr);
    }
}

void *os_calloc(size_t nelem, size_t elsize) {
    size_t page_size = getpagesize();
    size_t size = nelem * elsize;
    struct block_meta *block;
    int status = STATUS_MAPPED;
    if (size <= 0) {
        return NULL;
    }
    if (size + METADATA_SIZE < page_size) {
        status = STATUS_ALLOC;
    }
    if (!global && status == STATUS_ALLOC) {
        block = request_space(NULL, 128 * 1024 - METADATA_SIZE, status);
        if (!block) {
            return NULL;
        }
        global = block;
        last = global;
        last->prev = NULL;
        last->next = NULL;
    } else {
        block = NULL;
        if (global) {
            block = find_best(size);
        }
        if (!block) {
            if (global) {
                last = get_last(global);
            }
            block = request_space(last, size, status);
            if (!block) {
                return NULL;
            }
        } else {
            block->status = status;
            split_block(block, size);
        }
    }
    memset(block + 1, 0, size);
    return block + 1;
}

void *os_realloc(void *ptr, size_t size) {
    size_t adjusted_size = 0, unmap_size = 0;
    struct block_meta *aux = NULL, *old_block = NULL, *block = NULL;
    void *ptr_aux = NULL;
    if (!ptr) {
        ptr = os_malloc(size);
        block = get_block_ptr(ptr);
        return block + 1;
    }
    if (!size) {
        os_free(ptr);
        block = get_block_ptr(ptr);
    }
    block = get_block_ptr(ptr);
    if (block->status == STATUS_FREE) {
        return NULL;
    }
    if (size < block->size) {
        if (block->status == STATUS_ALLOC) {
            old_block = block;
            split_block(block, size);
            if (old_block->size == block->size) {
                block->size = size;
            }
        } else {
            unmap_size = ALIGN(block->size + METADATA_SIZE);
            old_block = block;
            ptr_aux = os_malloc(size);
            block = get_block_ptr(ptr_aux);
            block->next = old_block->next;
            block->prev = old_block->prev;
            munmap((char *)ptr - METADATA_SIZE, unmap_size);
        }
    } else if (size > block->size) {
        if (block->status == STATUS_ALLOC) {
            if (block->next == NULL) {
                expand_block(block, size, block->size);
            } else if (block->next->status = STATUS_FREE) {
                old_block = block;
                realloc_merge(block, size);
                if (block->size == old_block->size) {
                    aux = NULL;
                    global = get_global(block);
                    if (global) {
                        aux = find_best(size);
                    }
                    if (!aux) {
                        ptr_aux = os_malloc(size);
                        aux = get_block_ptr(ptr_aux);
                        memcpy(aux + METADATA_SIZE, block + METADATA_SIZE,
                               ALIGN(size));
                        if (block->prev) {
                            block->prev->next = block->next;
                        }
                        if (block->next) {
                            block->next->prev = block->prev;
                        }
                    } else {
                        old_block = aux;
                        split_block(aux, size);
                        if (old_block->size == aux->size) {
                            block->size = size;
                        }
                    }
                }
            } else {
                aux = NULL;
                global = get_global(block);
                if (global) {
                    aux = find_best(size);
                }
                if (!aux) {
                    ptr_aux = os_malloc(size);
                    aux = get_block_ptr(ptr_aux);
                    memcpy(aux + METADATA_SIZE, block + METADATA_SIZE,
                           ALIGN(size));
                    if (block->prev) {
                        block->prev->next = block->next;
                    }
                    if (block->next) {
                        block->next->prev = block->prev;
                    }
                } else {
                    old_block = aux;
                    split_block(aux, size);
                    if (old_block->size == aux->size) {
                        block->size = size;
                    }
                }
            }
        } else {
            unmap_size = ALIGN(block->size + METADATA_SIZE);
            old_block = block;
            ptr_aux = os_malloc(size);
            block = get_block_ptr(ptr_aux);
            block->next = old_block->next;
            block->prev = old_block->prev;
            munmap((char *)ptr - METADATA_SIZE, unmap_size);
        }
    }
    return block + 1;
}
