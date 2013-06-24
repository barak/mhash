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


#include "libdefs.h"

/*
   Byte swap a 32bit integer 
 */
word32
byteswap(word32 x)
{
	register char *cp, tmp;

	cp = (char *) &x;
	tmp = cp[3];
	cp[3] = cp[0];
	cp[0] = tmp;

	tmp = cp[2];
	cp[2] = cp[1];
	cp[1] = tmp;

	return x;
}

/*
   expands the one keyword to three (for tripleDES)
 */
int
BreakToThree(void *key, unsigned int keylen, void *keyword1, void *keyword2, void *keyword3)
{
	unsigned int i;
	unsigned char *key_buf;
	char *tmpkey = key;
	key_buf = calloc(1, 24);

/*
   Copy the key into keybuf (the rest is padded) 
 */

	for (i = 0; i < keylen; i++) {
		memmove(&key_buf[i], &tmpkey[i], 1);
	}

	memmove(keyword1, &key_buf[0], 8);
	memmove(keyword2, &key_buf[8], 8);
	memmove(keyword3, &key_buf[16], 8);

	free(key_buf);

	return 0;

}
