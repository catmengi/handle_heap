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

static recursive_mutex_t g_heap_mutex = PTHREAD_MUTEX_INITIALIZER;
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

static mm_handle_metablock* find_free_metablock(){
    recursive_mutex_lock(&g_heap_mutex);

    mm_handle_metablock* free_block = NULL;

    for(int i = 0; i < sizeof(g_handle_metablocks) / sizeof(g_handle_metablocks[0]); i++){
        if(g_handle_metablocks[i].used == false){
            free_block = &g_handle_metablocks[i];
            break;
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
    return free_block;
}

static uintptr_t nextby (uintptr_t value, uintptr_t by) {
    if (value % by == 0) {
        return value; // Already divisible by
    }
    return (value / by + 1) * by; // Calculate the next multiple of by
}

static void* find_free_heap_start(int size){
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
        if(g_handle_metablocks[sorted_indices[i]].used && move_to != g_handle_metablocks[sorted_indices[i]].ptr){

            recursive_mutex_lock(&g_handle_metablocks[sorted_indices[i]].lock);

            memmove(move_to,g_handle_metablocks[sorted_indices[i]].ptr,g_handle_metablocks[sorted_indices[i]].alligned_size);
            g_handle_metablocks[sorted_indices[i]].ptr = move_to;

            move_to += g_handle_metablocks[sorted_indices[i]].alligned_size;

            recursive_mutex_unlock(&g_handle_metablocks[sorted_indices[i]].lock);
        }
    }

    recursive_mutex_unlock(&g_heap_mutex);
}

mm_handle mm_alloc(size_t size){
    mm_assert(size != 0);

    recursive_mutex_lock(&g_heap_mutex);

    mm_assert(g_blocks_availible > 0);
    g_blocks_availible -= (nextby(size,HANDLE_HEAP_MINALLOC) / HANDLE_HEAP_MINALLOC);

    mm_handle_metablock* metablock = find_free_metablock();

    int retry_count = 0;
    while((metablock->ptr = find_free_heap_start(size)) == NULL){
        compact_heap();
        mm_assert(retry_count++ == 0 && "Cannot allocate enough space, FIX API TO NOT CRASH WHOLE DEVICE!");
    }

    metablock->alloc_size = size;
    metablock->alligned_size = nextby(metablock->alloc_size,HANDLE_HEAP_MINALLOC);
    memset(metablock->metadata,0,sizeof(metablock->metadata));
    random_buf(&metablock->huid,sizeof(metablock->huid));


    metablock->used = true;

    mm_handle handle = {
        .huid = metablock->huid,
        .info = metablock,
    };

    recursive_mutex_unlock(&g_heap_mutex);

    return handle;
}

size_t mm_size(mm_handle handle){
    if(handle.info && handle.huid == handle.info->huid){

        auto_unlock mm_handle auto_handle = handle;
        mm_lock(auto_handle);

        return handle.info->alloc_size;
    }
    mm_assert(0 && "Usage of invalid handle! mm_size");
}

mm_handle mm_realloc(mm_handle handle, size_t size){
    recursive_mutex_lock(&g_heap_mutex);

    auto_unlock mm_handle auto_handle = handle;
    mm_lock(auto_handle);

    if(auto_handle.info && auto_handle.huid == auto_handle.info->huid && size != 0){

        int new_alligned_size = nextby(size,HANDLE_HEAP_MINALLOC);

        mm_handle_metablock* mblock = auto_handle.info;

        if(mblock->alligned_size == new_alligned_size){
            mblock->alloc_size = size;

            recursive_mutex_unlock(&g_heap_mutex);
            return auto_handle;
        } else {
            if(mblock->alligned_size > new_alligned_size){
                mblock->alligned_size = new_alligned_size;
                mblock->alloc_size = size;

                recursive_mutex_unlock(&g_heap_mutex);
                return auto_handle;
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
                    return auto_handle;
                } else {
                    auto_unlock mm_handle new_handle = mm_alloc(size);
                    auto_unlock mm_handle old_handle = auto_handle; //copying this to properly unlock it in future

                    memcpy(mm_lock(new_handle),mm_lock(old_handle),mm_size(old_handle));

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

void mm_auto_unlock(mm_handle* handle){
    mm_unlock(*handle);
}

void mm_set_incref_cb(mm_handle handle, void (*incref)(mm_handle handle, void* udata)){
    auto_unlock mm_handle auto_handle = handle; //auto_handle is equal to handle, but it will be automaticly unlocked at scope exit, mm_lock return NULL if handle is invalid, mm_unlock will ignore invalid handles!
    if(mm_lock(auto_handle)){
        auto_handle.info->refcount.callbacks.incref = incref;
    }
}
void mm_set_decref_cb(mm_handle handle, void (*decref)(mm_handle handle, void* udata)){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        auto_handle.info->refcount.callbacks.decref = decref;
    }
}
void mm_set_zero_cb(mm_handle handle, int (*zero)(mm_handle handle)){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        auto_handle.info->refcount.callbacks.zero = zero;
    }
}

void mm_set_refcount_ctx(mm_handle handle, void* ctx){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        auto_handle.info->refcount.ctx = ctx;
    }
}

void* mm_get_refcount_ctx(mm_handle handle){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        return auto_handle.info->refcount.ctx;
    }
    return NULL;
}

atomic_int mm_get_refcount(mm_handle handle){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        return auto_handle.info->refcount.counter;
    }
    return -1;
}

int mm_set_metadata(mm_handle handle, enum mm_metadata_blocks block, uintptr_t data){
    mm_assert(block < MM_HANDLE_META_MAX && block >= 0);

    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        auto_handle.info->metadata[block] = data;
        return 0;
    }
    return 1;
}

uintptr_t mm_get_metadata(mm_handle handle, enum mm_metadata_blocks block){
    mm_assert(block < MM_HANDLE_META_MAX && block >= 0);

    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        return auto_handle.info->metadata[block];
    }
    mm_assert(0 && "Invalid handle!");
}

mm_handle mm_incref(mm_handle handle, void* udata){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        if(auto_handle.info->refcount.callbacks.incref){

            auto_handle.info->refcount.counter++;
            auto_handle.info->refcount.callbacks.incref(auto_handle,udata);

            return handle;
        }
    }
    return (mm_handle){0};
}

void mm_decref(mm_handle handle, void* udata){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        mm_handle_metablock* metablock = handle.info;

        if(metablock->refcount.counter > 0){
            metablock->refcount.counter--;

            if(metablock->refcount.callbacks.decref){
                metablock->refcount.callbacks.decref(handle,udata);
            }
        }
        if(metablock->refcount.counter == 0){
            mm_free(handle); //this will call zero callback if it exists!
        }
    }
}

void mm_zeroout(mm_handle handle){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        if(auto_handle.info->refcount.callbacks.zero){
            if(auto_handle.info->refcount.callbacks.zero(auto_handle) == 0){
                auto_handle.info->refcount.counter = 0;
            }
        }
    }
}

void mm_free(mm_handle handle){
    auto_unlock mm_handle auto_handle = handle;
    if(mm_lock(auto_handle)){
        mm_handle_metablock* mblock = auto_handle.info;

        int disallow_further_free = 0; //reversed logic beucase zero callback should return NON 0 value if error
        if(mblock->refcount.callbacks.zero){
            disallow_further_free = mblock->refcount.callbacks.zero(auto_handle); //trying to call zero callback on free!
        }

        if(disallow_further_free == 0){
            random_buf(&mblock->huid,sizeof(mblock->huid)); //invalidate previos HUID

            size_t alligned_size = mblock->alligned_size;
            mblock->used = false;

            g_blocks_availible += alligned_size / HANDLE_HEAP_MINALLOC; //return N blocks to heap as availible
        }
    }
}

size_t mm_availiblemem(){
    return g_blocks_availible * HANDLE_HEAP_MINALLOC;
}
