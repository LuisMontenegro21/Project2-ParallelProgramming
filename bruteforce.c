// bruteforce.c
// Versión corregida para Project2 - MPI
// Soporta:
//   mpirun -np 1 ./bruteforce encrypt <key> <infile> <outfile>
//   mpirun -np N ./bruteforce brute <cipherfile> <keyword>
//
// Compilar:
//   mpicc -w bruteforce.c -o bruteforce -lssl -lcrypto
//
// Nota: para pruebas use un 'upper' pequeño (ver comentario más abajo).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>
#include <unistd.h>

#define TAG_FOUND 1234

// lee archivo binario/texto, devuelve buffer terminado en '\0' y *out_len
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

// Crea el bloque DES a partir de long y ajusta paridad
void set_key_from_long(long key, DES_cblock *out) {
  unsigned char tmp[8] = {0};
  // copiamos la representación de key en tmp (little-endian típico en x86/WSL)
  size_t copy_len = sizeof(long) < 8 ? sizeof(long) : 8;
  memcpy(tmp, &key, copy_len);
  memcpy(out, tmp, 8);
  DES_set_odd_parity(out); // asegurar paridad impar por byte
}

// convierte DES_cblock a long (para comparar/mostrar la "clave normalizada")
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
  // DES_set_key_checked puede fallar si la clave es débil; aun así intentamos usarla.
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

// intenta la key: devuelve 1 si encuentra keyword en texto descifrado
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
    if (rank != 0) { MPI_Finalize(); return 0; } // sólo rank 0 hace encrypt

    long key = atol(argv[2]);
    int inlen;
    char *plaintext = read_file_bin(argv[3], &inlen);
    if (!plaintext) { MPI_Finalize(); return 1; }

    int padded = pad8_up(inlen);
    char *buf = calloc(1, padded);
    memcpy(buf, plaintext, inlen);

    // mostrar la clave normalizada que DES usará
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
    int padded = pad8_up(clen);
    if (padded != clen) {
      char *buf = calloc(1, padded + 1);
      memcpy(buf, cipher, clen);
      free(cipher);
      cipher = buf;
      clen = padded;
    }
  }

  // compartir tamaño y contenido con todos (Bcast)
  MPI_Bcast(&clen, 1, MPI_INT, 0, MPI_COMM_WORLD);
  if (clen <= 0) { if (rank==0) fprintf(stderr,"Error: clen <= 0\n"); MPI_Finalize(); return 1; }
  if (rank != 0) {
    cipher = malloc(clen + 1);
    if (!cipher) { perror("malloc cipher worker"); MPI_Abort(MPI_COMM_WORLD, 1); }
  }
  MPI_Bcast(cipher, clen + 1, MPI_CHAR, 0, MPI_COMM_WORLD); // incluyo terminador

  // Espacio de búsqueda DES: default 2^56
  long upper = (1L << 56);
  // ---------------------------------------------------------
  // Para pruebas rápidas en tu máquina local: cambia temporalmente a:
  // long upper = (1L << 24); // ~16M keys -> rápida para debug
  // ---------------------------------------------------------

  // Para debug: si quieres reducir desde aquí sin editar el archivo fuente,
  // puedes setear una variable de entorno UPPER_LIMIT (no implementado aquí,
  // es preferible editar el código para pruebas rápidas).

  MPI_Barrier(MPI_COMM_WORLD);
  double t0 = MPI_Wtime();

  long found = 0;      // 0 => no encontrado aún
  long local_found = 0; // si este proceso encuentra -> guarda la key
  MPI_Status status;
  int flag = 0;

  // Estrategia: búsqueda intercalada (stride = nprocs)
  for (long k = rank; k < upper; k += nprocs) {
    // check si otro proceso anunció llave (no bloqueante)
    MPI_Iprobe(MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &flag, &status);
    if (flag) {
      MPI_Recv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &status);
      // otro proceso encontró; salir
      break;
    }
    // probar esta llave
    if (tryKey(k, cipher, clen, keyword)) {
      local_found = k;
      // notificar a todos (non-blocking sends para evitar potencial bloqueo)
      for (int dest = 0; dest < nprocs; ++dest) {
        if (dest == rank) continue;
        MPI_Request req;
        MPI_Isend(&local_found, 1, MPI_LONG, dest, TAG_FOUND, MPI_COMM_WORLD, &req);
        // no guardamos req (pequeña posibilidad de buffering) — para cluster pequeño está OK
      }
      // además, setear found localmente
      found = local_found;
      break;
    }
    // reset flag para la siguiente iteración
    flag = 0;
  }

  // Todos los procesos realizan un Allreduce (MAX) para obtener la key global encontrada (si existe)
  long global_found = 0;
  MPI_Allreduce(&found, &global_found, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);

  double t1 = MPI_Wtime();
  double elapsed = t1 - t0;

  if (rank == 0) {
    if (global_found) {
      // mostrar raw y normalized (parity) para evitar confusión
      DES_cblock kb;
      set_key_from_long(global_found, &kb);
      long normalized = des_cblock_to_long(&kb);
      // descifrar una copia y mostrar prefijo
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

  // Optional: cada proceso puede imprimir su tiempo
  // printf("[rank %d] elapsed time = %.6f s\n", rank, elapsed);

  free(cipher);
  MPI_Finalize();
  return 0;
}
