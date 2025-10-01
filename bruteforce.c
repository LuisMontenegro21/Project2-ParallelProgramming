//bruteforce.c
//nota: el key usado es bastante pequenio, cuando sea random speedup variara

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h> // deprecated for OpenSSl 3.0, but still usable. May show warnings
#include <time.h>

/*
Reads file and returns a pointer to the content
*/
char* read_file(const char* file){
  FILE *f = fopen(file, "rb");
  if (f == NULL){
    printf("Error opening file\n");
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *string = malloc(fsize + 1);
  if (string == NULL){
    perror("Error allocating memory\n");
    fclose(f);
    exit(1);
  }
  if (fread(string, 1, fsize, f) != 1) {
    perror("Error reading file\n");
    fclose(f);
    exit(1);
  }
  
  string[fsize] = '\0';
  fclose(f);  
  return string;
} 

/*
long key : key to use to decrypt
char *ciph: message to be decrypted
int len: length of message
*/
void decrypt(long key, char *ciph, int len){
  //set parity of key and do decrypt
  DES_cblock keyblock;
  memcpy(keyblock, &key, 8);
  DES_set_odd_parity(&keyblock);
  DES_key_schedule schedule;
  DES_set_key_checked(&keyblock, &schedule);
  for (int i = 0; i< len; i+=8)
    DES_ecb_encrypt((DES_cblock *)(ciph+i), (DES_cblock *) (ciph + i), &schedule, DES_DECRYPT);

}

/*
long key : key to sue
char *ciph: message to be encrypted
int len: length of message
*/
void encrypt(long key, char *ciph, int len){
  DES_cblock keyblock;
  memcpy(keyblock, &key, 8);
  DES_set_odd_parity(&keyblock);
  DES_key_schedule schedule;
  DES_set_key_checked(&keyblock, &schedule);
  for (int i = 0; i < len; i+= 8)
    DES_ecb_encrypt((DES_cblock *)(ciph+i), (DES_cblock *)(ciph+i), &schedule, DES_ENCRYPT);
}

char search[] = " the "; // search word , hard coded, needs fixing

/*
Tries different key combinations and returns a substring containing the match word
*/
int tryKey(long key, char *ciph, int len){
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0}; // hardcoded cypher, temporary to experiment
int main(int argc, char **argv){ 
  int size, rank;
  long upper = (1L <<56); //upper bound DES keys 2^56
  long mylower, myupper;
  MPI_Status status;
  MPI_Request req;
  int flag;
  int ciphlen = strlen(cipher);
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &size);
  MPI_Comm_rank(comm, &rank);

  // divide ranges among processes
  int range_per_node = upper / size; 
  mylower = range_per_node * rank;
  myupper = range_per_node * (rank+1) -1;
  if(rank == size-1){
    //compensar residuo
    myupper = upper;
  }

  long found = 0;

  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  for(int i = mylower; i<myupper && (found==0); ++i){
    if(tryKey(i, (char *)cipher, ciphlen)){
      found = i;
      for(int node=0; node<size; node++){
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }  
  }

  if(rank==0){
    MPI_Wait(&req, &status);
    decrypt(found, (char *)cipher, ciphlen);
    printf("%li %s\n", found, cipher);
  }

  MPI_Finalize();
}

