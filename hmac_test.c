#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>

#define KEY1 "Jefe"
#define DATA1 "what do ya want for nothing?"
#define DIGEST1 "750c783e6ab0b503eaa86e310a5db738"

#define KEY2 ""
#define DATA2 "Hi There"
#define DIGEST2 "9294727a3638bb1c13f48ef8158bfc9d"

int main()
{

	char *tmp;
	char tmp2[3];
	char *password;
	int passlen;
	char *data;
	int datalen;
	MHASH td;
	unsigned char *mac;
	int j;

	tmp=calloc(1, 2*16);

	passlen=sizeof(KEY1);
	password = malloc(passlen+1);
	memcpy(password, KEY1, passlen);
	
	datalen=strlen(DATA1);
	data=malloc(datalen+1);
	strcpy(data, DATA1);

	td =
	    hmac_mhash_init(MHASH_MD5, password, passlen,
			    mhash_get_hash_pblock(MHASH_MD5));

	mhash(td, data, datalen);
	mac = hmac_mhash_end(td);

	tmp2[2]='\0';
	
	for (j = 0; j < mhash_get_block_size(MHASH_MD5); j++) {
		sprintf(tmp2, "%.2x", mac[j]);
		strcat(tmp, tmp2);
	}

	if (strcmp(DIGEST1, tmp)!=0) {
		fprintf(stderr, "HMAC-Test: Failed\n");
		fprintf(stderr, "Expecting: 0x%s\nGot: 0x%s\n", DIGEST1, tmp);
		free(password);
		free(data);
		free(tmp);
		return 1;
	}

		free(password);
		free(data);
		free(tmp);
	
	/* Test No 2 */	

	tmp=calloc(1, 2*16);
	
	passlen=sizeof(KEY2);
	password = malloc(passlen+1);
	memcpy(password, KEY2, passlen);
	
	datalen=strlen(DATA2);
	data=malloc(datalen+1);
	strcpy(data, DATA2);

	td =
	    hmac_mhash_init(MHASH_MD5, password, passlen,
			    mhash_get_hash_pblock(MHASH_MD5));

	mhash(td, data, datalen);
	mac = hmac_mhash_end(td);

	tmp2[2]='\0';
	
	for (j = 0; j < mhash_get_block_size(MHASH_MD5); j++) {
		sprintf(tmp2, "%.2x", mac[j]);
		strcat(tmp, tmp2);
	}

	if (strcmp(DIGEST2, tmp)!=0) {
		fprintf(stderr, "HMAC-Test: Failed\n");
		fprintf(stderr, "Expecting: 0x%s\nGot: 0x%s\n", DIGEST2, tmp);
		free(password);
		free(data);
		free(tmp);
		return 1;
	}


	free(password);
	free(data);
	free(tmp);

	fprintf(stderr, "HMAC-Test: Succeed\n");

	return 0;
}
