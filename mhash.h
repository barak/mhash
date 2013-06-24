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

#ifndef MHASH_H
#define MHASH_H

/* $Id: mhash.h,v 1.3 1999/10/04 12:13:10 sascha Exp $ */

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#define MHASH_API_VERSION 19991004

/* these are for backwards compatibility and will 
   be removed at some time */

#ifdef MHASH_BACKWARDS_COMPATIBLE
#define CRC32 MHASH_CRC32
#define MD5 MHASH_MD5
#define SHA1 MHASH_SHA1
#define HAVAL MHASH_HAVAL
#define RIPEMD160 MHASH_RIPEMD160
#define RIPEMD128 MHASH_RIPEMD128
#define SNEFRU MHASH_SNEFRU
#define TIGER MHASH_TIGER
#define GOST MHASH_GOST
#define CRC32B MHASH_CRC32B
#endif

/* typedefs */

	typedef int MHASH;

	enum hashid {
		MHASH_CRC32,
		MHASH_MD5,
		MHASH_SHA1,
		MHASH_HAVAL,
		MHASH_RIPEMD160,
		MHASH_RIPEMD128,
		MHASH_SNEFRU,
		MHASH_TIGER,
		MHASH_GOST,
		MHASH_CRC32B
	};

	typedef enum hashid hashid;

	typedef struct mhash_hash_entry mhash_hash_entry;

#define MHASH_FAILED ((MHASH) -1)

/* information prototypes */

	size_t mhash_count(void);
	size_t mhash_get_block_size(hashid type);
	char *mhash_get_hash_name(hashid type);

/* initializing prototypes */

	MHASH mhash_init(hashid type);
	MHASH mhash_init_int(hashid type, MHASH thread);

/* update prototype */

	int mhash(MHASH thread, const void *plaintext, size_t size);

/* finalizing prototype */

	void *mhash_end(MHASH thread);

	size_t mhash_get_hash_pblock(hashid type);
	MHASH hmac_mhash_init(const hashid type, void *key, int keysize, int block);
	void *hmac_mhash_end(MHASH thread);

#ifdef __cplusplus
}
#endif

#endif							/* !MHASH_H */
