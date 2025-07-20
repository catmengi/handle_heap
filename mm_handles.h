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



#pragma once

#include "mm_osspecif.h"

#define HANDLE_HEAP_SIZE (1 * 1024 * 1024)
#define HANDLE_HEAP_MINALLOC 128

typedef struct _mm_handle_metablock mm_handle_metablock;

enum mm_metadata_blocks{
    MM_HANDLE_SERIALIZE_FUNC,
    MM_HANDLE_DESERIALIZE_FUNC,
    MM_HANDLE_META_MAX,
};

typedef struct{
    int huid; //after mm_handle invalidation it would be changed in metablock and all handles with this HUID will be invalid
    mm_handle_metablock* info;
}mm_handle;

mm_handle mm_alloc(size_t size); //allocate memory sized by size, allocation is alligned based on internal define of HANDLE_HEAP_MINALLOC

mm_handle mm_realloc(mm_handle handle, size_t size); //realloc handle to size

void* mm_lock(mm_handle handle); //locks handle, prevents this block from accessed or being moved from another thread;

void mm_unlock(mm_handle handle);//unlocks handle

size_t mm_size(mm_handle handle); //returns allocation size of handle (not alligned_size)

size_t mm_availiblemem(); //return ammount of availible memory in bytes!

void mm_set_incref_cb(mm_handle handle, void (*incref)(mm_handle handle, void* udata)); //sets handle callback on incref

void mm_set_decref_cb(mm_handle handle, void (*decref)(mm_handle handle, void* udata)); //sets handle callback on decref

void mm_set_zero_cb(mm_handle handle, int (*zero)(mm_handle handle)); //sets handle callback that will be executed when handle's refcount reaches 0; zero callback should return 0 on success, otherwise any NON 0 value

void mm_set_refcount_ctx(mm_handle handle, void* ctx); //sets handle ctx that can be accessed from refcount callbacks

int mm_set_metadata(mm_handle handle, enum mm_metadata_blocks block, uintptr_t data); //set handle metadata block

void* mm_get_refcount_ctx(mm_handle handle); //get handle's context for callbacks set by mm_set_refcount_ctx

atomic_int mm_get_refcount(mm_handle handle); //get handle refcount

uintptr_t mm_get_metadata(mm_handle handle, enum mm_metadata_blocks block); //get handle metadata block

mm_handle mm_incref(mm_handle handle, void* udata); //increse refcount and call incref callback, return same handle, can be used like this void* ptr = mm_lock(mm_incref(handle,"some void* data that u can use"));

void mm_decref(mm_handle handle, void* udata); //decrese refcount and call decref callback, if refcount reaches 0 -> call mm_free!

void mm_free(mm_handle handle); //call zero callback and free memory that handle use. If zero callback return error (NON 0 value) handle will not be freed

void mm_zeroout(mm_handle handle); //calls zero callback, if zero callback returned success(0) drops refcount to 0
