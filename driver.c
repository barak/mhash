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
 *  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL Sascha Schumann OR
 *  ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/*
 * This is a simple test driver for use in combination with test_hash.sh
 *
 * It's ugly, limited and you should hit :q! now
 *
 * $Id: driver.c,v 1.1 1999/07/14 12:27:35 sascha Exp $
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
 
#include "mhash.h"

static char hexconvtab[] = "0123456789ABCDEF";

/*
   Also used in PHP3 
 */

static char *
bin2hex(const unsigned char *old, const size_t oldlen, size_t * newlen)
{
	unsigned char *new = NULL;
	int i, j;

	new = (char *) malloc(oldlen * 2 * sizeof(char) + 1);
	if (!new) {
		return new;
	}

	for (i = j = 0; i < oldlen; i++) {
		new[j++] = hexconvtab[old[i] >> 4];
		new[j++] = hexconvtab[old[i] & 15];
	}
	new[j] = '\0';

	if (newlen)
		*newlen = oldlen * 2 * sizeof(char);

	return new;
}

int 
main(int argc, char **argv)
{
	size_t bsize;
	unsigned char *data;
	size_t data_len;
	char *str;
	size_t str_len;
	hashid hashid;
	MHASH td;

	if (argc < 3) {
		exit(1);
	}

	hashid = atoi(argv[1]);
	data_len = atoi(argv[2]);

	bsize = mhash_get_block_size(hashid);
	if (!bsize)
		exit(1);

	data = malloc(data_len + 1);
	memset(data, 0, data_len + 1);

	if(data_len) read(0, data, data_len);

	td = mhash_init(hashid);
	mhash(td, data, data_len);
	free(data);
	data = mhash_end(td);
	str = bin2hex(data, bsize, &str_len);
	printf("%s\n", str);
	free(str);
	exit(0);
}
