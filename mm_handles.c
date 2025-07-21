// MIT License
//
// Copyright (c) 2025 Catmengi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//NOTE: there is some multithreading concerns, like you CAN NOT hold handle in 2 different threads, so you must keep this in mind



#include "mm_handles.h"
#include "mm_osspecif.h"

typedef struct _mm_handle_metablock{
    int huid; //handle unique ID
    uintptr_t metadata[MM_HANDLE_META_MAX]; //userdefined metadata;

    int alloc_size; //size of memory controlled by handle
    short alligned_size; //size of allocation in blocks
    uint8_t* ptr;     //pointer to chunk of memory

    struct{
        struct{
            void (*incref)(mm_handle handle, void* udata);
            void (*decref)(mm_handle handle, void* udata);
            int (*zero)(mm_handle handle); //return NON 0 if you need to stop further free
        }callbacks;

        void* ctx;
        atomic_int counter;
    }refcount;

    recursive_mutex_t lock;
    bool used;
}mm_handle_metablock;

static recursive_mutex_t g_heap_mutex;
static mm_handle_metablock g_handle_metablocks[HANDLE_HEAP_SIZE / HANDLE_HEAP_MINALLOC] = {0};
static uint8_t g_handle_heap[HANDLE_HEAP_SIZE] = {0};

static size_t g_blocks_availible = sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]);

__attribute__((constructor))
static void init_metablocks_lock(void){
    recursive_mutex_init(&g_heap_mutex);

    for(int i = 0; i < sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]); i++){
        recursive_mutex_init(&g_handle_metablocks[i].lock);
    }
}

static uintptr_t nextby (uintptr_t value, uintptr_t by) {
    if (value % by == 0) {
        return value; // Already divisible by
    }
    return (value / by + 1) * by; // Calculate the next multiple of by
}

static mm_handle_metablock* find_free_metablock(){
    recursive_mutex_lock(&g_heap_mutex);

    mm_handle_metablock* free_block = NULL;

    for(int i = 0; i < sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]); i++){
        if(recursive_mutex_trylock(&g_handle_metablocks[i].lock) == 0){
            if(g_handle_metablocks[i].used == false){
                free_block = &g_handle_metablocks[i];
                free_block->used = true; //set this to used before mm_alloc, to prevent possible race-conditions

                recursive_mutex_unlock(&g_handle_metablocks[i].lock);
                break;
            }
            recursive_mutex_unlock(&g_handle_metablocks[i].lock);
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
    return free_block;
}

static uint8_t* find_free_heap_start(int size){
    recursive_mutex_lock(&g_heap_mutex);

    uint8_t* free_start = &g_handle_heap[0];
    int alligned_size = nextby(size, HANDLE_HEAP_MINALLOC);


    for(int i = 0; i < sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]); i++){
        if(g_handle_metablocks[i].used == true){
            if(free_start <= g_handle_metablocks[i].ptr){
                free_start = g_handle_metablocks[i].ptr + g_handle_metablocks[i].alligned_size;

                if(free_start >= &g_handle_heap[HANDLE_HEAP_SIZE] || &g_handle_heap[HANDLE_HEAP_SIZE] - free_start < alligned_size) {
                    recursive_mutex_unlock(&g_heap_mutex);
                    return NULL;
                }
            }
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
    return free_start;
}

static int compactor_sort(const void* a, const void* b){
    mm_handle_metablock* metablock_a = &g_handle_metablocks[*(int*)a];
    mm_handle_metablock* metablock_b = &g_handle_metablocks[*(int*)b];

    if(metablock_a->ptr < metablock_b->ptr) return -1;
    if(metablock_a->ptr > metablock_b->ptr) return 1;

    return 0;
}

static void compact_heap(){
    recursive_mutex_lock(&g_heap_mutex);

    int sorted_indices[sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0])];
    for(int i = 0; i < sizeof(sorted_indices) / sizeof(sorted_indices[0]); i++){
        sorted_indices[i] = i; //initialise this array first
    }

    //then do qsort on it, but not based on index, instead being based on g_handle_metablocks[index].ptr
    qsort_impl(sorted_indices,sizeof(sorted_indices) / sizeof(sorted_indices[0]), sizeof(sorted_indices[0]),compactor_sort);

    //now loop on sorted_indices to compact heap
    uint8_t* move_to = &g_handle_heap[0]; //move block to that pointer, then increase it by alligned_size
    for(int i = 0; i < sizeof(sorted_indices) / sizeof(sorted_indices[0]); i++){

        //we can be sure that number of elements in sorted_indices == number of elements in g_handle_metablocks
        if(g_handle_metablocks[sorted_indices[i]].used && g_handle_metablocks[sorted_indices[i]].ptr && move_to != g_handle_metablocks[sorted_indices[i]].ptr){
            if(recursive_mutex_trylock(&g_handle_metablocks[sorted_indices[i]].lock) == 0){
                memmove(move_to,g_handle_metablocks[sorted_indices[i]].ptr,g_handle_metablocks[sorted_indices[i]].alligned_size);
                g_handle_metablocks[sorted_indices[i]].ptr = move_to;

                move_to += g_handle_metablocks[sorted_indices[i]].alligned_size;

                recursive_mutex_unlock(&g_handle_metablocks[sorted_indices[i]].lock);

            } else move_to += g_handle_metablocks[sorted_indices[i]].alligned_size; //it can be done different, but i decided that move_to offseting should be done while locked if lock succeded!
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
}

mm_handle mm_alloc(size_t size){
    mm_handle handle = {0};

    if(size > 0 && mm_availiblemem() >= size){
        recursive_mutex_lock(&g_heap_mutex);

        if(g_blocks_availible > 0){
            mm_handle_metablock* metablock = find_free_metablock(); mm_assert(metablock); //this should NEVER fail; find_free_metablock will mark metablock as used
            recursive_mutex_lock(&metablock->lock);


            while((metablock->ptr = find_free_heap_start(size)) == NULL){
                compact_heap();
            }

            if(metablock->ptr){
                memset(metablock->metadata, 0, sizeof(metablock->metadata));
                memset(&metablock->refcount, 0, sizeof(metablock->refcount));

                metablock->alloc_size = size;

                metablock->alligned_size = nextby(metablock->alloc_size,HANDLE_HEAP_MINALLOC);
                g_blocks_availible -= (metablock->alligned_size / HANDLE_HEAP_MINALLOC);

                random_buf(&metablock->huid,sizeof(metablock->huid));

                handle.huid = metablock->huid;
                handle.info = metablock;
            }else metablock->used = false;

            recursive_mutex_unlock(&metablock->lock);
        }

        recursive_mutex_unlock(&g_heap_mutex);
    }
    return handle;
}

size_t mm_size(mm_handle handle){
    size_t size = 0;
    if(mm_lock(handle)){
        size = handle.info->alloc_size;
        mm_unlock(handle);
    }

    return size;
}

mm_handle mm_realloc(mm_handle handle, size_t size){
    recursive_mutex_lock(&g_heap_mutex);

    if(mm_lock(handle) && size != 0){

        int new_alligned_size = nextby(size,HANDLE_HEAP_MINALLOC);

        mm_handle_metablock* mblock = handle.info;

        if(mblock->alligned_size == new_alligned_size){
            mblock->alloc_size = size;

            recursive_mutex_unlock(&g_heap_mutex);
            mm_unlock(handle);
            return handle;
        } else {
            if(mblock->alligned_size > new_alligned_size){
                mblock->alligned_size = new_alligned_size;
                mblock->alloc_size = size;

                recursive_mutex_unlock(&g_heap_mutex);
                mm_unlock(handle);
                return handle;
            }

            if(mblock->alligned_size < new_alligned_size){
                uint8_t* check_is_empty = mblock->ptr + new_alligned_size;
                bool unused = true;

                for(int i = 0; i < sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]); i++){
                    if(g_handle_metablocks[i].ptr == check_is_empty){
                        unused = false;
                        break;
                    }
                }

                if(unused){
                    mblock->alligned_size = new_alligned_size;
                    mblock->alloc_size = size;

                    recursive_mutex_unlock(&g_heap_mutex);
                    mm_unlock(handle);
                    return handle;
                } else {
                    mm_handle new_handle = mm_alloc(size);
                    mm_handle old_handle = handle; //copying this to properly unlock it in future

                    memcpy(mm_lock(new_handle),mm_lock(old_handle),mm_size(old_handle));

                    mm_unlock(new_handle);
                    mm_unlock(old_handle);

                    mm_free(old_handle);
                    recursive_mutex_unlock(&g_heap_mutex);
                    return new_handle;
                }

            }
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
    return (mm_handle){0};
}

void* mm_lock(mm_handle handle){
    if(handle.info && handle.info->huid == handle.huid){
        recursive_mutex_lock(&handle.info->lock);
        return handle.info->ptr;
    }

    return NULL;
}

void mm_unlock(mm_handle handle){
    if(handle.info && handle.info->huid == handle.huid){
        recursive_mutex_unlock(&handle.info->lock);
    }
}

void mm_set_incref_cb(mm_handle handle, void (*incref)(mm_handle handle, void* udata)){
    if(mm_lock(handle)){
        handle.info->refcount.callbacks.incref = incref;
        mm_unlock(handle);
    }
}
void mm_set_decref_cb(mm_handle handle, void (*decref)(mm_handle handle, void* udata)){
    if(mm_lock(handle)){
        handle.info->refcount.callbacks.decref = decref;
        mm_unlock(handle);
    }
}
void mm_set_zero_cb(mm_handle handle, int (*zero)(mm_handle handle)){
    if(mm_lock(handle)){
        handle.info->refcount.callbacks.zero = zero;
        mm_unlock(handle);
    }
}

void mm_set_refcount_ctx(mm_handle handle, void* ctx){
    if(mm_lock(handle)){
        handle.info->refcount.ctx = ctx;
        mm_unlock(handle);
    }
}

void* mm_get_refcount_ctx(mm_handle handle){
    void* ret = NULL;
    if(mm_lock(handle)){
        ret = handle.info->refcount.ctx;
        mm_unlock(handle);
    }
    return ret;
}

atomic_int mm_get_refcount(mm_handle handle){
    int ret = -1;
    if(mm_lock(handle)){
        ret =  handle.info->refcount.counter;
        mm_unlock(handle);
    }
    return ret;
}

int mm_set_metadata(mm_handle handle, enum mm_metadata_blocks block, uintptr_t data){
    mm_assert(block < MM_HANDLE_META_MAX && block >= 0);

    if(mm_lock(handle)){
        handle.info->metadata[block] = data;
        mm_unlock(handle);

        return 0;
    }
    return 1;
}

uintptr_t mm_get_metadata(mm_handle handle, enum mm_metadata_blocks block){
    mm_assert(block < MM_HANDLE_META_MAX && block >= 0);

    if(mm_lock(handle)){
        uintptr_t ret =  handle.info->metadata[block];

        mm_unlock(handle);
        return ret;
    }
    mm_assert(0 && "Invalid handle!");
}

mm_handle mm_incref(mm_handle handle, void* udata){
    if(mm_lock(handle)){
        if(handle.info->refcount.callbacks.incref){

            handle.info->refcount.counter++;
            handle.info->refcount.callbacks.incref(handle,udata);

            mm_unlock(handle);
            return handle;
        }
    }
    return (mm_handle){0};
}

void mm_decref(mm_handle handle, void* udata){
    if(mm_lock(handle)){
        mm_handle_metablock* metablock = handle.info;

        if(metablock->refcount.counter > 0){
            metablock->refcount.counter--;

            if(metablock->refcount.callbacks.decref){
                metablock->refcount.callbacks.decref(handle,udata);
            }
        }
        mm_unlock(handle); //unlock after main operations is done

        if(metablock->refcount.counter == 0){
            mm_free(handle); //this will call zero callback if it exists!
        }
    }
}

void mm_zeroout(mm_handle handle){
    if(mm_lock(handle)){
        if(handle.info->refcount.callbacks.zero){
            if(handle.info->refcount.callbacks.zero(handle) == 0){
                handle.info->refcount.counter = 0;
            }
        }
        mm_unlock(handle);
    }
}

void mm_free(mm_handle handle){
    if(mm_lock(handle)){
        recursive_mutex_lock(&g_heap_mutex);

        mm_handle_metablock* mblock = handle.info;

        int disallow_further_free = 0; //reversed logic beucase zero callback should return NON 0 value if error
        if(mblock->refcount.callbacks.zero){
            disallow_further_free = mblock->refcount.callbacks.zero(handle); //trying to call zero callback on free!
        }

        if(disallow_further_free == 0){
            random_buf(&mblock->huid,sizeof(mblock->huid)); //invalidate previos HUID

            size_t alligned_size = mblock->alligned_size;

            mblock->used = false; //we are still holding the lock, so we can do this
            g_blocks_availible += alligned_size / HANDLE_HEAP_MINALLOC; //return N blocks to heap as availible
        }

        recursive_mutex_unlock(&g_heap_mutex);
        recursive_mutex_unlock(&mblock->lock);
    }
}

size_t mm_availiblemem(){
    recursive_mutex_lock(&g_heap_mutex);
    size_t availib  = g_blocks_availible * HANDLE_HEAP_MINALLOC;
    recursive_mutex_unlock(&g_heap_mutex);

    return availib;
}

