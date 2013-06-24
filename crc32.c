/*
   This is a modified version of the crc32 described in comp.compression faq
   * (the tables were taken from bzip2)
   * I think it works fine on big and little endian machines.
 */

#include "mhash_crc32.h"
#define CRC32_POLY 0x04c11db7	/*
								   AUTODIN II, Ethernet, & FDDI 
								 */

static word32 crc32_table[256] =
{

	0x00000000UL, 0x04c11db7UL, 0x09823b6eUL, 0x0d4326d9UL,
	0x130476dcUL, 0x17c56b6bUL, 0x1a864db2UL, 0x1e475005UL,
	0x2608edb8UL, 0x22c9f00fUL, 0x2f8ad6d6UL, 0x2b4bcb61UL,
	0x350c9b64UL, 0x31cd86d3UL, 0x3c8ea00aUL, 0x384fbdbdUL,
	0x4c11db70UL, 0x48d0c6c7UL, 0x4593e01eUL, 0x4152fda9UL,
	0x5f15adacUL, 0x5bd4b01bUL, 0x569796c2UL, 0x52568b75UL,
	0x6a1936c8UL, 0x6ed82b7fUL, 0x639b0da6UL, 0x675a1011UL,
	0x791d4014UL, 0x7ddc5da3UL, 0x709f7b7aUL, 0x745e66cdUL,
	0x9823b6e0UL, 0x9ce2ab57UL, 0x91a18d8eUL, 0x95609039UL,
	0x8b27c03cUL, 0x8fe6dd8bUL, 0x82a5fb52UL, 0x8664e6e5UL,
	0xbe2b5b58UL, 0xbaea46efUL, 0xb7a96036UL, 0xb3687d81UL,
	0xad2f2d84UL, 0xa9ee3033UL, 0xa4ad16eaUL, 0xa06c0b5dUL,
	0xd4326d90UL, 0xd0f37027UL, 0xddb056feUL, 0xd9714b49UL,
	0xc7361b4cUL, 0xc3f706fbUL, 0xceb42022UL, 0xca753d95UL,
	0xf23a8028UL, 0xf6fb9d9fUL, 0xfbb8bb46UL, 0xff79a6f1UL,
	0xe13ef6f4UL, 0xe5ffeb43UL, 0xe8bccd9aUL, 0xec7dd02dUL,
	0x34867077UL, 0x30476dc0UL, 0x3d044b19UL, 0x39c556aeUL,
	0x278206abUL, 0x23431b1cUL, 0x2e003dc5UL, 0x2ac12072UL,
	0x128e9dcfUL, 0x164f8078UL, 0x1b0ca6a1UL, 0x1fcdbb16UL,
	0x018aeb13UL, 0x054bf6a4UL, 0x0808d07dUL, 0x0cc9cdcaUL,
	0x7897ab07UL, 0x7c56b6b0UL, 0x71159069UL, 0x75d48ddeUL,
	0x6b93dddbUL, 0x6f52c06cUL, 0x6211e6b5UL, 0x66d0fb02UL,
	0x5e9f46bfUL, 0x5a5e5b08UL, 0x571d7dd1UL, 0x53dc6066UL,
	0x4d9b3063UL, 0x495a2dd4UL, 0x44190b0dUL, 0x40d816baUL,
	0xaca5c697UL, 0xa864db20UL, 0xa527fdf9UL, 0xa1e6e04eUL,
	0xbfa1b04bUL, 0xbb60adfcUL, 0xb6238b25UL, 0xb2e29692UL,
	0x8aad2b2fUL, 0x8e6c3698UL, 0x832f1041UL, 0x87ee0df6UL,
	0x99a95df3UL, 0x9d684044UL, 0x902b669dUL, 0x94ea7b2aUL,
	0xe0b41de7UL, 0xe4750050UL, 0xe9362689UL, 0xedf73b3eUL,
	0xf3b06b3bUL, 0xf771768cUL, 0xfa325055UL, 0xfef34de2UL,
	0xc6bcf05fUL, 0xc27dede8UL, 0xcf3ecb31UL, 0xcbffd686UL,
	0xd5b88683UL, 0xd1799b34UL, 0xdc3abdedUL, 0xd8fba05aUL,
	0x690ce0eeUL, 0x6dcdfd59UL, 0x608edb80UL, 0x644fc637UL,
	0x7a089632UL, 0x7ec98b85UL, 0x738aad5cUL, 0x774bb0ebUL,
	0x4f040d56UL, 0x4bc510e1UL, 0x46863638UL, 0x42472b8fUL,
	0x5c007b8aUL, 0x58c1663dUL, 0x558240e4UL, 0x51435d53UL,
	0x251d3b9eUL, 0x21dc2629UL, 0x2c9f00f0UL, 0x285e1d47UL,
	0x36194d42UL, 0x32d850f5UL, 0x3f9b762cUL, 0x3b5a6b9bUL,
	0x0315d626UL, 0x07d4cb91UL, 0x0a97ed48UL, 0x0e56f0ffUL,
	0x1011a0faUL, 0x14d0bd4dUL, 0x19939b94UL, 0x1d528623UL,
	0xf12f560eUL, 0xf5ee4bb9UL, 0xf8ad6d60UL, 0xfc6c70d7UL,
	0xe22b20d2UL, 0xe6ea3d65UL, 0xeba91bbcUL, 0xef68060bUL,
	0xd727bbb6UL, 0xd3e6a601UL, 0xdea580d8UL, 0xda649d6fUL,
	0xc423cd6aUL, 0xc0e2d0ddUL, 0xcda1f604UL, 0xc960ebb3UL,
	0xbd3e8d7eUL, 0xb9ff90c9UL, 0xb4bcb610UL, 0xb07daba7UL,
	0xae3afba2UL, 0xaafbe615UL, 0xa7b8c0ccUL, 0xa379dd7bUL,
	0x9b3660c6UL, 0x9ff77d71UL, 0x92b45ba8UL, 0x9675461fUL,
	0x8832161aUL, 0x8cf30badUL, 0x81b02d74UL, 0x857130c3UL,
	0x5d8a9099UL, 0x594b8d2eUL, 0x5408abf7UL, 0x50c9b640UL,
	0x4e8ee645UL, 0x4a4ffbf2UL, 0x470cdd2bUL, 0x43cdc09cUL,
	0x7b827d21UL, 0x7f436096UL, 0x7200464fUL, 0x76c15bf8UL,
	0x68860bfdUL, 0x6c47164aUL, 0x61043093UL, 0x65c52d24UL,
	0x119b4be9UL, 0x155a565eUL, 0x18197087UL, 0x1cd86d30UL,
	0x029f3d35UL, 0x065e2082UL, 0x0b1d065bUL, 0x0fdc1becUL,
	0x3793a651UL, 0x3352bbe6UL, 0x3e119d3fUL, 0x3ad08088UL,
	0x2497d08dUL, 0x2056cd3aUL, 0x2d15ebe3UL, 0x29d4f654UL,
	0xc5a92679UL, 0xc1683bceUL, 0xcc2b1d17UL, 0xc8ea00a0UL,
	0xd6ad50a5UL, 0xd26c4d12UL, 0xdf2f6bcbUL, 0xdbee767cUL,
	0xe3a1cbc1UL, 0xe760d676UL, 0xea23f0afUL, 0xeee2ed18UL,
	0xf0a5bd1dUL, 0xf464a0aaUL, 0xf9278673UL, 0xfde69bc4UL,
	0x89b8fd09UL, 0x8d79e0beUL, 0x803ac667UL, 0x84fbdbd0UL,
	0x9abc8bd5UL, 0x9e7d9662UL, 0x933eb0bbUL, 0x97ffad0cUL,
	0xafb010b1UL, 0xab710d06UL, 0xa6322bdfUL, 0xa2f33668UL,
	0xbcb4666dUL, 0xb8757bdaUL, 0xb5365d03UL, 0xb1f740b4UL
};



void
clear_crc32(word32 * crc)
{
	*crc = 0xffffffff;			/*
								   preload shift register, per CRC-32 spec 
								 */
}

void *
get_crc32(const word32 * crc)
{
	word32 *tmp = malloc(sizeof(word32));
	*tmp = ~(*crc);				/*
								   transmit complement, per CRC-32 spec 
								 */
	return tmp;
}

void
crc32(word32 * crc, const void *given_buf, int len)
{
	const unsigned char *p;

	for (p = given_buf; len > 0; ++p, --len) {
		(*crc) = ((*crc) << 8) ^ crc32_table[((*crc) >> 24) ^ *p];
	}
}