#include <mhash.h>
#include <strings.h>
#include <stdio.h>

int main (int argc, char **argv) {

int td,i, j;
unsigned char * rval;
int size;
FILE *fs;
unsigned char text[2];


if (argc<=1) {
  fprintf( stderr, "Usage: digest FILE1 FILE2 ...\n");
  exit(1);
}

text[1]='\0';

for (j=1; j<argc; j++) {

  fs=fopen(argv[j], "rb");
  if (fs==NULL) {
      perror("fopen"); 
      exit(1);
  }

  printf("File:\t%s\n", argv[j]);
  size=get_block_size(CRC32);
  td=init_mhash(CRC32);

  if (td<0) {perror("td"); exit(1); }
  
  while (fread(text, 1, 1, fs)!=0) {
    mhash(td, text, 1);
  }

  rval=end_mhash(td);



  printf("CRC32:\t");
  for (i=0;i<size; i++) {
   printf("%.2x", rval[i]);
  
  }
  printf("\n");


  /* MD5 */
  size=get_block_size(MD5);
  td=init_mhash(MD5);

  fseek(fs, 0, SEEK_SET);

  while (fread(text, 1, 1, fs)!=0) {
    mhash(td, text, 1);
  }

  rval=end_mhash(td);

  printf("MD5:\t");
  for (i=0;i<size; i++) {
   printf("%.2x", rval[i]);
  }
  printf("\n");



  /* SHA1 */
  size=get_block_size(SHA1);
  td=init_mhash(SHA1);

  fseek(fs, 0, SEEK_SET);

  while (fread(text, 1, 1, fs)!=0) {
    mhash(td, text, 1);
  }

  rval=end_mhash(td);

  printf("SHA1:\t");
  for (i=0;i<size; i++) {
   printf("%.2x", rval[i]);
  }
  printf("\n\n");

  fclose(fs);
} /* for */

 return 0;


}
