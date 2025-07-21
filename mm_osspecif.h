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



#pragma once

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

#ifndef EXT_RAM_BSS_ATTR
#define EXT_RAM_BSS_ATTR
#endif

//OS SPECIFIC CODE!  ======================================================================================================

typedef struct{
    pthread_mutex_t impl;
}recursive_mutex_t;

static inline void recursive_mutex_init(recursive_mutex_t* mutex){
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mutex->impl,&attr);
    pthread_mutexattr_destroy(&attr);
}

static inline void recursive_mutex_lock(recursive_mutex_t* mutex){
    pthread_mutex_lock(&mutex->impl);
}

static inline void recursive_mutex_unlock(recursive_mutex_t* mutex){
    pthread_mutex_unlock(&mutex->impl);
}

static inline int recursive_mutex_trylock(recursive_mutex_t* mutex){
    return pthread_mutex_trylock(&mutex->impl);
}

static inline void qsort_impl(void* base, size_t num, size_t size, int (*compare) (const void *, const void *)){
    qsort(base,num,size,compare);
}

static inline void random_buf(void* buf, size_t nbytes){
    arc4random_buf(buf,nbytes);
}

#define mm_assert assert
//==========================================================================================================================
