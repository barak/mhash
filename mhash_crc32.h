#ifndef MHASH_CRC32_H
#define MHASH_CRC32_H

#include "libdefs.h"

void clear_crc32(word32 * crc);
void *get_crc32(const word32 * crc);
void crc32(word32 * crc, const void *, int);
void crc32b(word32 * crc, const void *, int);
void crc32bgen(void);

#endif
