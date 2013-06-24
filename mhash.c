/*
 *  Copyright (c) 1999 Sascha Schumann. All rights reserved.
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 
 *  3. All advertising materials mentioning features or use of this
 *     software must display the following acknowledgment:
 *     "This product includes software developed by
 *      Sascha Schumann <ss@2ns.de>."
 * 
 *  4. Redistributions of any form whatsoever must retain the following
 *     acknowledgment:
 *     "This product includes software developed by
 *      Sascha Schumann <ss@2ns.de>."
 * 
 *  THIS SOFTWARE IS PROVIDED BY SASCHA SCHUMANN ``AS IS'' AND ANY
 *  EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL SASCHA SCHUMANN OR
 *  ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: mhash.c,v 1.16 1999/10/21 12:11:44 nikos Exp $ */

#include <stdlib.h>

#include "libdefs.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
 
#include "mhash.h"
#include "mhash_crc32.h"
#include "mhash_haval.h"
#include "mhash_md5.h"
#include "mhash_sha1.h"
#include "mhash_tiger.h"
#include "rmd128.h"
#include "rmd160.h"
#include "gosthash.h"

#define MAX_THREADS 256		/* After that pointers are being reused */

/* I think now it is re-entrant */

static int check_pointer[MAX_THREADS];
static int used_all_threads;
static int cur_thread;

/* Hold hmac key and keysize */
static int *hmac_key_size;
static int *hmac_block;
static unsigned char **hmac_key;


#ifdef MHASH_PTHREADS

pthread_mutex_t counter_cur_thread = PTHREAD_MUTEX_INITIALIZER;

#define CURRENT_COUNTER_LOCK pthread_mutex_lock(&counter_cur_thread)
#define CURRENT_COUNTER_UNLOCK pthread_mutex_unlock(&counter_cur_thread)


#else

#define CURRENT_COUNTER_LOCK
#define CURRENT_COUNTER_UNLOCK

#endif

/* one state for all algorithms */
static word8 **state;

/* hold the key and the algorithm */
static hashid *algorithm_given;

#define MHASH_ENTRY(name, blksize, hash_pblock) \
	{ #name, name, blksize, hash_pblock }

struct mhash_hash_entry {
	char *name;
	hashid id;
	size_t blocksize;
	size_t hash_pblock;
};

static mhash_hash_entry algorithms[] = {
	MHASH_ENTRY(MHASH_CRC32, 4, 0),
	MHASH_ENTRY(MHASH_MD5, 16, 64),
	MHASH_ENTRY(MHASH_SHA1, 20, 64),
	MHASH_ENTRY(MHASH_HAVAL, HAVAL_FPTLEN >> 3, 128),
	MHASH_ENTRY(MHASH_RIPEMD160, 160 >> 3, 64),
	MHASH_ENTRY(MHASH_RIPEMD128, 128 >> 3, 64),
	MHASH_ENTRY(MHASH_TIGER, 192 >> 3, 64),
	MHASH_ENTRY(MHASH_GOST, 32, 0),
	MHASH_ENTRY(MHASH_CRC32B, 4, 0),
	{0}
};

#define MHASH_LOOP(b) \
	mhash_hash_entry *p; \
	for(p = algorithms; p->name != NULL; p++) { b ; }

#define MHASH_ALG_LOOP(a) \
	MHASH_LOOP( if(p->id == type) { a; break; } )

size_t mhash_count(void)
{
	size_t count = 0;

	MHASH_LOOP(count++);

	return count;
}

size_t mhash_get_block_size(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->blocksize);
	return ret;
}

char *mhash_get_hash_name(hashid type)
{
	char *ret = NULL;

	/* avoid prefix */
	MHASH_ALG_LOOP(ret = strdup(p->name + sizeof("MHASH_") - 1));

	return ret;
}

MHASH mhash_init_int(const hashid type, const MHASH thread)
{
	MHASH ret = thread;
	
	if (!used_all_threads) {
		state = realloc(state, (thread + 1) * sizeof(word8*));

		algorithm_given =
		    realloc(algorithm_given,
			    (thread + 1) * sizeof(hashid));

		hmac_key =
		    realloc(hmac_key, (thread + 1) * sizeof(char *));
		hmac_key_size =
		    realloc(hmac_key_size, (thread + 1) * sizeof(int));
		hmac_block =
		    realloc(hmac_block, (thread + 1) * sizeof(int));

	}

	algorithm_given[thread] = type;
	check_pointer[thread] = 1;

	switch (type) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		state[thread] = malloc(sizeof(word32));
		clear_crc32((void *) state[thread]);
		break;
	case MHASH_MD5:
		state[thread] = malloc(sizeof(MD5_CTX));
		MD5Init((void *) state[thread]);
		break;
	case MHASH_SHA1:
		state[thread] = malloc(sizeof(SHA1_CTX));
		SHA1Init((void *) state[thread]);
		break;
	case MHASH_HAVAL:
		state[thread] = malloc(sizeof(haval_state));
		haval_start((void *) state[thread]);
		break;
	case MHASH_RIPEMD128:
		state[thread] = malloc(4 * sizeof(word32));
		MDinit_128((void *) state[thread]);
		break;
	case MHASH_RIPEMD160:
		state[thread] = malloc(5 * sizeof(word32));
		MDinit_160((void *) state[thread]);
		break;
	case MHASH_TIGER:
		state[thread] = malloc(3 * sizeof(word64));
		break;
	case MHASH_GOST:
		state[thread] = malloc(sizeof(GostHashCtx));
		gosthash_reset((void *) state[thread]);
		break;
	default:
		ret = MHASH_FAILED;
		break;
	}
	return ret;
}

#define MIX32(a) \
	(((unsigned long)((unsigned char *)(a))[0]) | \
	(((unsigned long)((unsigned char *)(a))[1]) << 8)| \
	(((unsigned long)((unsigned char *)(a))[2]) << 16)| \
	(((unsigned long)((unsigned char *)(a))[3]) << 24))


#ifdef WORDS_BIGENDIAN
void mhash_32bit_conversion(word32 *ptr, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		ptr[i] = MIX32(&ptr[i]);
	}
}
#else
#define mhash_32bit_conversion(a,b)
#endif

/* plaintext should be a multiply of the algorithm's block size */

int mhash(MHASH thread, const void *plaintext, size_t size)
{
	switch (algorithm_given[thread]) {
	case MHASH_CRC32:
		crc32((void *) state[thread], plaintext, size);
		break;
	case MHASH_CRC32B:
		crc32b((void *) state[thread], plaintext, size);
		break;
	case MHASH_MD5:
		MD5Update((void *) state[thread], plaintext, size);
		break;
	case MHASH_SHA1:
		SHA1Update((void *) state[thread], plaintext, size);
		break;
	case MHASH_HAVAL:
		haval_hash((void *) state[thread], plaintext, size);
		break;
	case MHASH_RIPEMD128:
		MDfinish_128((void *) state[thread], plaintext, size, 0);
		break;
	case MHASH_RIPEMD160:
		MDfinish_160((void *) state[thread], plaintext, size, 0);
		break;
	case MHASH_TIGER:
		tiger(plaintext, size, (void *) state[thread]);
		break;
	case MHASH_GOST:
		gosthash_update((void *) state[thread], plaintext, size);
		break;
	}
	return 0;
}


void *mhash_end(MHASH thread)
{
	void *digest;
	void *rtmp=NULL;

	check_pointer[thread] = 0;

	switch (algorithm_given[thread]) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		rtmp = get_crc32((void *) state[thread]);
		break;
	case MHASH_MD5:
		rtmp = MD5Final((void *) state[thread]);
		break;
	case MHASH_SHA1:
		rtmp = SHA1Final((void *) state[thread]);
		break;
	case MHASH_HAVAL:
		digest =
		    malloc(mhash_get_block_size(algorithm_given[thread]));
		haval_end((void *) state[thread], digest);
		rtmp = digest;
		break;
	case MHASH_RIPEMD160:
		digest = malloc(160 >> 3);
		memcpy(digest, (void *) state[thread], 160 >> 3);
		mhash_32bit_conversion(digest, 160 >> 5);
		rtmp = digest;
		break;
	case MHASH_RIPEMD128:
		digest = malloc(128 >> 3);
		memcpy(digest, (void *) state[thread], 128 >> 3);
		mhash_32bit_conversion(digest, 128 >> 5);
		rtmp = digest;
		break;
	case MHASH_TIGER:
		digest = malloc(192 >> 3);
		memcpy(digest, (void *) state[thread], 192 >> 3);
		mhash_32bit_conversion(digest, 192 >> 5);
		rtmp = digest;
		break;
	case MHASH_GOST:
		digest = malloc(32);
		gosthash_final((void *) state[thread], digest);
		rtmp = digest;
		break;
	}


	free(state[thread]);
	
	return rtmp;
}

MHASH mhash_init(const hashid type)
{
	static int gost_init, crc32b_init;
	MHASH ret = MHASH_FAILED;

	CURRENT_COUNTER_LOCK;

	if (type == MHASH_GOST && !gost_init) {
		gosthash_init();
		gost_init++;
	}

	if (type == MHASH_CRC32B && !crc32b_init) {
		crc32b_init++;
		crc32bgen();
	}

	if (cur_thread == MAX_THREADS) {
		/* FIXME: fixed size solutions can be improved */
		cur_thread = 0;
		used_all_threads = 1;
	}

	while (check_pointer[cur_thread] == 1 && cur_thread < MAX_THREADS) {
		cur_thread++;
	}

	if (cur_thread < MAX_THREADS) {
		ret = mhash_init_int(type, cur_thread);

		if (ret < 0) {
			mhash_end(cur_thread);
			ret = MHASH_FAILED;
		}
	}

	CURRENT_COUNTER_UNLOCK;

	return ret;
}

/* HMAC functions */

size_t mhash_get_hash_pblock(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->hash_pblock);
	return ret;
}

void *hmac_mhash_end(MHASH thread)
{
	void *digest;
	unsigned char *opad;
	MHASH tmptd;
	void *return_val;
	int i;

	opad = malloc(hmac_block[thread]);

	for (i = 0; i < hmac_block[thread]; i++) {
		opad[i] = (0x5C) ^ hmac_key[thread][i];
	}

	tmptd = mhash_init(algorithm_given[thread]);
	mhash(tmptd, opad, hmac_block[thread]);


	check_pointer[thread] = 0;

	switch (algorithm_given[thread]) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		return_val = get_crc32((void *) state[thread]);
		break;
	case MHASH_MD5:
		return_val = MD5Final((void *) state[thread]);
		break;
	case MHASH_SHA1:
		return_val = SHA1Final((void *) state[thread]);
		break;
	case MHASH_HAVAL:
		digest =
		    malloc(mhash_get_block_size(algorithm_given[thread]));
		haval_end((void *) state[thread], digest);
		return_val = digest;
		break;
	case MHASH_RIPEMD160:
		digest = malloc(160 >> 3);
		memcpy(digest, (void *) state[thread], 160 >> 3);
		return_val = digest;
		break;
	case MHASH_RIPEMD128:
		digest = malloc(128 >> 3);
		memcpy(digest, (void *) state[thread], 128 >> 3);
		return_val = digest;
		break;
	case MHASH_TIGER:
		digest = malloc(192 >> 3);
		memcpy(digest, (void *) state[thread], 192 >> 3);
		return_val = digest;
		break;
	case MHASH_GOST:
		digest = malloc(32);
		gosthash_final((void *) state[thread], digest);
		return_val = digest;
		break;
	}

	mhash(tmptd, return_val,
	      mhash_get_block_size(algorithm_given[thread]));

	free(state[thread]);

	return mhash_end(tmptd);
}

MHASH hmac_mhash_init(const hashid type, void *key, int keysize, int block)
{
	static int gost_init, crc32b_init;
	MHASH ret = MHASH_FAILED;
	MHASH tmptd;
	unsigned char *tmp;
	unsigned char *ipad;
	int i;

	CURRENT_COUNTER_LOCK;

	if (block == 0) {
		block = 64;	/* the default for ripemd,md5,sha-1 */
	}

	if (type == MHASH_GOST && !gost_init) {
		gost_init++;
		gosthash_init();
	}

	if (type == MHASH_CRC32B && !crc32b_init) {
		crc32b_init++;
		crc32bgen();
	}

	if (cur_thread == MAX_THREADS) {
		/* FIXME: fixed size solutions can be improved */
		cur_thread = 0;
		used_all_threads = 1;
	}

	while (check_pointer[cur_thread] == 1 && cur_thread < MAX_THREADS) {
		cur_thread++;
	}


	if (cur_thread < MAX_THREADS) {
		ret = mhash_init_int(type, cur_thread);

		if (ret < 0) {
			mhash_end(cur_thread);
			ret = MHASH_FAILED;
		} else {
			/* Initial hmac calculations */
			hmac_block[ret] = block;

			ipad = malloc(hmac_block[ret]);

			if (keysize > hmac_block[ret]) {
				tmptd = mhash_init(type);
				mhash(tmptd, key, keysize);
				hmac_key_size[ret] =
					mhash_get_block_size(type);
				hmac_key[ret] = mhash_end(tmptd);
			} else {
				hmac_key_size[ret] = keysize;
				hmac_key[ret] = malloc(keysize);
				memmove(hmac_key[ret], key, keysize);
			}

			if (hmac_key_size[ret] != hmac_block[ret]) {
				tmp = calloc(hmac_block[ret], 1);
				memmove(tmp, hmac_key[ret],
						hmac_key_size[ret]);
				free(hmac_key[ret]);
				hmac_key[ret] = tmp;
				hmac_key_size[ret] = hmac_block[ret];
			}

			/* IPAD */

			for (i = 0; i < hmac_block[ret]; i++) {
				ipad[i] = (0x36) ^ hmac_key[ret][i];
			}

			mhash(ret, ipad, hmac_block[ret]);
		}

	}

	CURRENT_COUNTER_UNLOCK;

	return ret;
}
