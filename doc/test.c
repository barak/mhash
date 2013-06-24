#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>

main() {

  int td, i;
  unsigned char buffer;
  unsigned char *hash;
      
  td=init_mhash(MD5);
          
  while ( fread(&buffer, 1, 1, stdin)==1 ) {
      mhash (td, &buffer, 1);
  }

  hash=end_mhash(td);

  printf ("Hash:");
  for (i=0; i<get_block_size(MD5); i++) {
   printf ("%.2x", hash[i]);
  }
  printf ("\n");
  
  return 0;

}
