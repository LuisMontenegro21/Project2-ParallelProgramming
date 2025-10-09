// Compilar:
//   mpicc -w bruteforce.c -o bruteforce -lcrypto

// Comandos para usar:
//   mpirun -np 1 ./bruteforce encrypt <key> <infile> <outfile>
//   mpirun -np N ./bruteforce brute <cipherfile> <keyword>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>
#include <unistd.h>

#define TAG_FOUND 1234


char* read_file_bin(const char* path, int *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror("fopen"); return NULL; }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc(sz + 1);
  if (!buf) { perror("malloc"); fclose(f); return NULL; }
  if (fread(buf, 1, sz, f) != (size_t)sz) { perror("fread"); free(buf); fclose(f); return NULL; }
  buf[sz] = '\0';
  fclose(f);
  *out_len = (int)sz;
  return buf;
}

int write_file_bin(const char* path, const char* data, int len) {
  FILE *f = fopen(path, "wb");
  if (!f) { perror("fopen write"); return -1; }
  if (fwrite(data, 1, len, f) != (size_t)len) { perror("fwrite"); fclose(f); return -1; }
  fclose(f);
  return 0;
}

int pad8_up(int n) { return ((n + 7) / 8) * 8; }

// Crea el Des y ajusta paridad
void set_key_from_long(long key, DES_cblock *out) {
  unsigned char tmp[8] = {0};
  size_t copy_len = sizeof(long) < 8 ? sizeof(long) : 8;
  memcpy(tmp, &key, copy_len);
  memcpy(out, tmp, 8);
  DES_set_odd_parity(out);
}

// Convierte la clave a una normalizada
long des_cblock_to_long(const DES_cblock *kb) {
  long val = 0;
  unsigned char tmp[8];
  memcpy(tmp, kb, 8);
  memcpy(&val, tmp, 8);
  return val;
}

void des_decrypt_blockwise(long key, char *buf, int len) {
  DES_cblock keyblock;
  DES_key_schedule ks;
  set_key_from_long(key, &keyblock);
  DES_set_key_checked(&keyblock, &ks);
  for (int i = 0; i < len; i += 8) {
    DES_ecb_encrypt((DES_cblock *)(buf + i), (DES_cblock *)(buf + i), &ks, DES_DECRYPT);
  }
}

void des_encrypt_blockwise(long key, char *buf, int len) {
  DES_cblock keyblock;
  DES_key_schedule ks;
  set_key_from_long(key, &keyblock);
  DES_set_key_checked(&keyblock, &ks);
  for (int i = 0; i < len; i += 8) {
    DES_ecb_encrypt((DES_cblock *)(buf + i), (DES_cblock *)(buf + i), &ks, DES_ENCRYPT);
  }
}

// Se hace un intento de encontrar la key: devuelve 1 si encuentra keyword en texto descifrado
int tryKey(long key, const char *cipher, int clen, const char *keyword) {
  char *tmp = malloc(clen + 1);
  if (!tmp) return 0;
  memcpy(tmp, cipher, clen);
  tmp[clen] = '\0';
  des_decrypt_blockwise(key, tmp, clen);
  int found = (strstr(tmp, keyword) != NULL);
  free(tmp);
  return found;
}

int main(int argc, char **argv) {
  MPI_Init(&argc, &argv);

  int rank = 0, nprocs = 1;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

  if (argc < 2) {
    if (rank == 0) {
      fprintf(stderr, "Uso:\n  encrypt: %s encrypt <key> <infile> <outfile>\n  brute:   %s brute <cipherfile> <keyword>\n", argv[0], argv[0]);
    }
    MPI_Finalize();
    return 1;
  }

  // MODO ENCRYPT
  if (strcmp(argv[1], "encrypt") == 0) {
    if (argc < 5) {
      if (rank == 0) fprintf(stderr, "encrypt usage: %s encrypt <key> <infile> <outfile>\n", argv[0]);
      MPI_Finalize();
      return 1;
    }
    if (rank != 0) { MPI_Finalize(); return 0; }

    long key = atol(argv[2]);
    int inlen;
    char *plaintext = read_file_bin(argv[3], &inlen);
    if (!plaintext) { MPI_Finalize(); return 1; }

    int padded = pad8_up(inlen);
    char *buf = calloc(1, padded);
    memcpy(buf, plaintext, inlen);

    // Se muestra la clave normalizada (con paridad ajustada)
    DES_cblock kb;
    set_key_from_long(key, &kb);
    long normalized = des_cblock_to_long(&kb);
    printf("Encrypt: input key = %ld ; normalized key used by DES = %ld\n", key, normalized);

    des_encrypt_blockwise(key, buf, padded);
    if (write_file_bin(argv[4], buf, padded) != 0) {
      free(plaintext); free(buf);
      MPI_Finalize(); return 1;
    }
    printf("Encrypt done. Output: %s (len %d, padded %d)\n", argv[4], inlen, padded);

    free(plaintext);
    free(buf);
    MPI_Finalize();
    return 0;
  }

  // MODO BRUTE
  if (strcmp(argv[1], "brute") != 0) {
    if (rank == 0) fprintf(stderr, "Unknown command. Use 'encrypt' or 'brute'.\n");
    MPI_Finalize();
    return 1;
  }
  if (argc < 4) {
    if (rank == 0) fprintf(stderr, "brute usage: %s brute <cipherfile> <keyword>\n", argv[0]);
    MPI_Finalize();
    return 1;
  }

  const char *cipherfile = argv[2];
  const char *keyword = argv[3];

  int clen = 0;
  char *cipher = NULL;
  if (rank == 0) {
    cipher = read_file_bin(cipherfile, &clen);
    if (!cipher) { fprintf(stderr, "Rank 0: cannot read %s\n", cipherfile); MPI_Abort(MPI_COMM_WORLD, 1); }
    
    if (clen >= 4) {
      unsigned char *uc = (unsigned char*)cipher;
      int is_null4 = (uc[0] == 0 && uc[1] == 0 && uc[2] == 0 && uc[3] == 0);
      int is_ascii_0000 = (uc[0] == '0' && uc[1] == '0' && uc[2] == '0' && uc[3] == '0');
      char *env_strip = getenv("STRIP_HEADER");
      int force_strip = env_strip ? atoi(env_strip) : 0;
      if (is_null4 || is_ascii_0000 || force_strip) {
        int newlen = clen - 4;
        if (newlen > 0) {
          char *buf = malloc(newlen + 1);
          if (buf) {
            memcpy(buf, cipher + 4, newlen);
            buf[newlen] = '\0';
            fprintf(stdout, "Rank 0: stripped 4-byte header from %s (bytes: %02X %02X %02X %02X), new length=%d\n",
                    cipherfile, uc[0], uc[1], uc[2], uc[3], newlen);
            free(cipher);
            cipher = buf;
            clen = newlen;
          }
        }
      }
    }
    int padded = pad8_up(clen);
    if (padded != clen) {
      char *buf = calloc(1, padded + 1);
      memcpy(buf, cipher, clen);
      free(cipher);
      cipher = buf;
      clen = padded;
    }
  }

  // compartir tamaño y contenido con todos
  MPI_Bcast(&clen, 1, MPI_INT, 0, MPI_COMM_WORLD);
  if (clen <= 0) { if (rank==0) fprintf(stderr,"Error: clen <= 0\n"); MPI_Finalize(); return 1; }
  if (rank != 0) {
    cipher = malloc(clen + 1);
    if (!cipher) { perror("malloc cipher worker"); MPI_Abort(MPI_COMM_WORLD, 1); }
  }
  MPI_Bcast(cipher, clen + 1, MPI_CHAR, 0, MPI_COMM_WORLD);

  long upper = (1L << 56);
  char *env_upper = getenv("UPPER_LIMIT");
  if (env_upper) {
    long v = atol(env_upper);
    if (v > 0) {
      upper = v;
      if (rank == 0) fprintf(stdout, "Using UPPER_LIMIT from env: %ld\n", upper);
    }
  }

  MPI_Barrier(MPI_COMM_WORLD);
  double t0 = MPI_Wtime();

  long found = 0;
  long local_found = 0;
  MPI_Status status;
  int flag = 0;

  long log_interval = 1000000;
  char *env = getenv("CHECK_LOG_INTERVAL");
  if (env) {
    long v = atol(env);
    if (v > 0) log_interval = v;
  }

  long aggregate_interval = log_interval * 10;
  char *envagg = getenv("AGGREGATE_LOG_INTERVAL");
  if (envagg) {
    long v = atol(envagg);
    if (v > 0) aggregate_interval = v;
  }

  long local_trials = 0;
  double last_log_time = MPI_Wtime();
  long local_at_last_agg = 0;
  double last_agg_time = MPI_Wtime();

  for (long k = rank; k < upper; k += nprocs) {
    if (tryKey(k, cipher, clen, keyword)) {
      local_found = k;
      DES_cblock kb_local;
      set_key_from_long(local_found, &kb_local);
      long normalized_local = des_cblock_to_long(&kb_local);
      char *tmp_local = malloc(clen + 1);
      if (tmp_local) {
        memcpy(tmp_local, cipher, clen);
        tmp_local[clen] = '\0';
        des_decrypt_blockwise(local_found, tmp_local, clen);
      }
      fprintf(stdout, "[rank %d] Found LOCAL key raw=%ld normalized=%ld (k=%ld)\nDecrypted prefix: %.256s\n", rank, local_found, normalized_local, k, tmp_local ? tmp_local : "(no tmp)");
      fflush(stdout);
      fflush(stdout);
      for (int dest = 0; dest < nprocs; ++dest) {
        if (dest == rank) continue;
        MPI_Request req;
        MPI_Isend(&local_found, 1, MPI_LONG, dest, TAG_FOUND, MPI_COMM_WORLD, &req);
      }
      found = local_found;
      if (tmp_local) free(tmp_local);
      break;
    }

    local_trials++;
    if ((local_trials % log_interval) == 0) {
      double now = MPI_Wtime();
      double dt = now - last_log_time;
      double rate = (dt > 0) ? (double)log_interval / dt : 0.0;
      long approx_done = k - rank + nprocs;
      double percent = (upper > 0) ? ((double)approx_done / (double)upper) * 100.0 : 0.0;
      fprintf(stdout, "[rank %d] tried ~%ld keys, rate=%.0f keys/s, approx=%.6f%% (k=%ld)\n", rank, local_trials, rate, percent, k);
      fflush(stdout);
      last_log_time = now;
    }

    // Ver si otro proceso ya encontró la key
    MPI_Iprobe(MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &flag, &status);
    if (flag) {
      MPI_Recv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &status);
      DES_cblock kb_recv;
      set_key_from_long(found, &kb_recv);
      long normalized_recv = des_cblock_to_long(&kb_recv);
      if (rank == 0) {
        fprintf(stdout, "[rank %d] Received announced key raw=%ld normalized=%ld from rank %d\n", rank, found, normalized_recv, status.MPI_SOURCE);
      } else {
        fprintf(stdout, "[rank %d] Notified of found key raw=%ld normalized=%ld from rank %d\n", rank, found, normalized_recv, status.MPI_SOURCE);
      }
      fflush(stdout);
      break;
    }
    flag = 0;
  }

  long global_found = 0;
  MPI_Allreduce(&found, &global_found, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);

  double t1 = MPI_Wtime();
  double elapsed = t1 - t0;

  if (rank == 0) {
    if (global_found) {
      // mostrar raw y normalized para evitar confusión
      DES_cblock kb;
      set_key_from_long(global_found, &kb);
      long normalized = des_cblock_to_long(&kb);
      char *tmp = malloc(clen + 1);
      memcpy(tmp, cipher, clen);
      tmp[clen] = '\0';
      des_decrypt_blockwise(global_found, tmp, clen);
      printf("[rank 0] Found key (raw) = %ld ; normalized (DES parity) = %ld\n", global_found, normalized);
      printf("Decrypted text (prefix):\n%.512s\n", tmp);
      free(tmp);
    } else {
      printf("[rank 0] Key not found in search space (upper=%ld) after distributed search\n", upper);
    }
    printf("[rank 0] elapsed time = %.6f s (nprocs=%d)\n", elapsed, nprocs);
  }

  printf("[rank %d] elapsed time = %.6f s\n", rank, elapsed);

  free(cipher);
  MPI_Finalize();
  return 0;
}
