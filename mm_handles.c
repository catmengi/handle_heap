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
    uint8_t* ptr;     //pointer to chunk of memory

    struct{
        struct{
            void (*incref)(mm_handle handle, void* udata);
            void (*decref)(mm_handle handle, void* udata);
            int (*zero)(mm_handle handle); //return NON 0 if you need to stop further free
        }callbacks;

        void* ctx;
        int counter;
    }refcount;

    int lock_count;
    recursive_mutex_t lock;
    bool used;
}mm_handle_metablock;

static recursive_mutex_t g_heap_mutex;
static size_t g_metablocblocks_availible = HANDLE_HEAP_METABLOCK_AMMOUNT;
static size_t g_heap_availible = HANDLE_HEAP_SIZE;

#ifndef PLACE_IN_HEAP
static mm_handle_metablock g_handle_metablocks[HANDLE_HEAP_METABLOCK_AMMOUNT] = {0};
static int g_sorted_indices[HANDLE_HEAP_METABLOCK_AMMOUNT] = {0};
static uint8_t g_handle_heap[HANDLE_HEAP_SIZE] = {0};
#else
static mm_handle_metablock* g_handle_metablocks;
static int* g_sorted_indices;
static uint8_t* g_handle_heap;
#endif

#ifndef ESP_PLATFORM
__attribute__((constructor(101)))
static
#endif
void mm_init(void){
    #ifdef PLACE_IN_HEAP
    void* heap_data = alloc_memory((HANDLE_HEAP_METABLOCK_AMMOUNT) * sizeof(*g_handle_metablocks) +
    (HANDLE_HEAP_METABLOCK_AMMOUNT) * sizeof(*g_sorted_indices) + (HANDLE_HEAP_SIZE) * sizeof(*g_handle_heap)); mm_assert(heap_data);

    g_handle_metablocks = heap_data; heap_data += (HANDLE_HEAP_METABLOCK_AMMOUNT) * sizeof(*g_handle_metablocks);
    memset(g_handle_metablocks,0,(HANDLE_HEAP_METABLOCK_AMMOUNT) * sizeof(*g_handle_metablocks));

    g_sorted_indices = heap_data; heap_data += (HANDLE_HEAP_METABLOCK_AMMOUNT) * sizeof(*g_sorted_indices);
    g_handle_heap = heap_data;
    #endif

    recursive_mutex_init(&g_heap_mutex);

    for(int i = 0; i < HANDLE_HEAP_METABLOCK_AMMOUNT; i++){
        recursive_mutex_init(&g_handle_metablocks[i].lock);
    }
}

static mm_handle_metablock* find_free_metablock(){
    recursive_mutex_lock(&g_heap_mutex);

    mm_handle_metablock* free_block = NULL;

    for(int i = 0; i < HANDLE_HEAP_METABLOCK_AMMOUNT; i++){
        if(recursive_mutex_trylock(&g_handle_metablocks[i].lock) == 0){
            if(g_handle_metablocks[i].used == false){
                free_block = &g_handle_metablocks[i];
                free_block->used = true; //set this to used before mm_alloc, to prevent possible race-conditions
                free_block->lock_count = 0;

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


    for(int i = 0; i < HANDLE_HEAP_METABLOCK_AMMOUNT; i++){
        if(g_handle_metablocks[i].used == true){
            if(free_start <= g_handle_metablocks[i].ptr){
                free_start = g_handle_metablocks[i].ptr + g_handle_metablocks[i].alloc_size;

                if(free_start >= &g_handle_heap[HANDLE_HEAP_SIZE] || &g_handle_heap[HANDLE_HEAP_SIZE] - free_start < size) {
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

    for(int i = 0; i < HANDLE_HEAP_METABLOCK_AMMOUNT; i++){
        g_sorted_indices[i] = i; //initialise this array first
    }

    //then do qsort on it, but not based on index, instead being based on g_handle_metablocks[index].ptr
    qsort_impl(g_sorted_indices,HANDLE_HEAP_METABLOCK_AMMOUNT, sizeof(*g_sorted_indices),compactor_sort);

    //now loop on g_sorted_indices to compact heap
    uint8_t* move_to = &g_handle_heap[0]; //move block to that pointer, then increase it by alligned_size
    for(int i = 0; i < HANDLE_HEAP_METABLOCK_AMMOUNT; i++){

        //we can be sure that number of elements in g_sorted_indices == number of elements in g_handle_metablocks
        if(g_handle_metablocks[g_sorted_indices[i]].used && g_handle_metablocks[g_sorted_indices[i]].ptr && move_to != g_handle_metablocks[g_sorted_indices[i]].ptr){
            if(recursive_mutex_trylock(&g_handle_metablocks[g_sorted_indices[i]].lock) == 0 && g_handle_metablocks[g_sorted_indices[i]].lock_count == 0){
                memmove(move_to,g_handle_metablocks[g_sorted_indices[i]].ptr,g_handle_metablocks[g_sorted_indices[i]].alloc_size);
                g_handle_metablocks[g_sorted_indices[i]].ptr = move_to;


                recursive_mutex_unlock(&g_handle_metablocks[g_sorted_indices[i]].lock);

            }
            move_to += g_handle_metablocks[g_sorted_indices[i]].alloc_size;
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
}

mm_handle mm_alloc(size_t size){
    mm_handle handle = {0};

    if(size > 0){
        recursive_mutex_lock(&g_heap_mutex);

        if(mm_availiblemem() >= size){
            mm_handle_metablock* metablock = find_free_metablock(); mm_assert(metablock); //this should NEVER fail; find_free_metablock will mark metablock as used
            recursive_mutex_lock(&metablock->lock);


            while((metablock->ptr = find_free_heap_start(size)) == NULL){
                compact_heap();
            }

            if(metablock->ptr){
                memset(metablock->metadata, 0, sizeof(metablock->metadata));
                memset(&metablock->refcount, 0, sizeof(metablock->refcount));

                metablock->alloc_size = size;

                g_heap_availible -= metablock->alloc_size;
                g_metablocblocks_availible--;

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
    mm_handle ret = {0};
    if(size == 0){ //size == 0 ===> free, libc semantic
        mm_free(handle);
        goto exit;
    }
    if(mm_size(handle) == size){
        ret = handle;
        goto exit;
    }
    ret = mm_alloc(size);
    void* new_cpy = mm_lock(ret);
    void* old_cpy = mm_lock(handle);
    if(new_cpy == NULL){
        mm_unlock(handle);
        goto exit;
    }
    if(old_cpy == NULL){
        mm_unlock(ret);
        mm_free(ret);
        ret = (mm_handle){0};
    }
    memcpy(new_cpy,old_cpy,mm_size(handle));
    mm_unlock(ret);
    mm_unlock(handle);

    exit:
    recursive_mutex_unlock(&g_heap_mutex);
    return ret;
}

static inline int is_handle_valid(mm_handle h){
    int ret = 0;
    if(h.info && h.info->huid == h.huid){
        ret = 1;
    }
    return ret;
}

void* mm_lock(mm_handle handle){
    if(is_handle_valid(handle)){
        recursive_mutex_lock(&handle.info->lock);
        ++handle.info->lock_count;

        return handle.info->ptr;
    }

    return NULL;
}

mm_handle mm_unlock(mm_handle handle){
    if(is_handle_valid(handle)){
        --handle.info->lock_count;
        recursive_mutex_unlock(&handle.info->lock);
    }
    return handle;
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

int mm_get_refcount(mm_handle handle){
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
    recursive_mutex_lock(&g_heap_mutex);
    if(mm_lock(handle)){
        mm_handle_metablock* mblock = handle.info;

        int disallow_further_free = 0; //reversed logic beucase zero callback should return NON 0 value if error
        if(mblock->refcount.callbacks.zero){
            disallow_further_free = mblock->refcount.callbacks.zero(handle); //trying to call zero callback on free!
        }

        if(disallow_further_free == 0){
            random_buf(&mblock->huid,sizeof(mblock->huid)); //invalidate previos HUID

            mblock->used = false; //we are still holding the lock, so we can do this
            g_metablocblocks_availible++; //add as metablock as free to counter;
            g_heap_availible += mblock->alloc_size; //add memory as free to counter;
        }
        recursive_mutex_unlock(&mblock->lock);
    }
    recursive_mutex_unlock(&g_heap_mutex);
}

size_t mm_availiblemem(){
    recursive_mutex_lock(&g_heap_mutex);
    size_t availib = 0;
    if(g_metablocblocks_availible > 0){
        availib = g_heap_availible;
    }
    recursive_mutex_unlock(&g_heap_mutex);

    return availib;
}

