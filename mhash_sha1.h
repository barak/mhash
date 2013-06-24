#ifndef MHASH_SHA1_H
#define MHASH_SHA1_H

#include <libdefs.h>

typedef struct {
	word32 state[5];
	word32 count[2];
	word8 buffer[64];
} SHA1_CTX;

void SHA1Transform(word32 state[5], word8 buffer[64]);
void SHA1Init(SHA1_CTX * context);
void SHA1Update(SHA1_CTX * context, const word8 * data, unsigned int len);
void *SHA1Final(SHA1_CTX * context);

#endif
