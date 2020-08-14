/*******************************************************************************************
 * Copyright 2020 sisyphus                                                                 *
 * The gmp library (https://gmplib.org) is required.                                       *
 *                                                                                         *
 * I build decrypt.exe with: gcc -o decrypt.exe decrypt.c -lgmp                            *
 * Usage: decrypt.exe                                                                      *
 *                                                                                         *
 * Upon execution, the contents of "msg.enc" are decrypted in a way that's based on the    *
 * contents of "primes.in", and the decrypted material is then written to "msg.dec".       *
 * For this to work correctly, the file named "primes.in" needs to be found, and also      *
 * needs to be identical to the "primes.in" that was used to create "msg.enc".             *
 *                                                                                         *
 * Additional "DEBUG" output can be obtained by running "decrypt.exe DEBUG" instead of     *
 * simply "decrypt.exe".                                                                   *
 *******************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <malloc.h>
#include <gmp.h>

int main(int argc, char *argv[]) {
 FILE *fp;
 int i_seed, i_count, i_bitsize, base, i, fail = 0;
 struct stat stbuf;
 struct stat p_stbuf;
 char seed_buf[11];
 char tmp[12];
 char *msg_buf, *tmp_buf, *chk_buf, *dec_buf, *prime_buf;
 mpz_t z_enc, z_dec, z_pad, z_mod, z_keep;
 size_t bitsize, r_shift, its, count, bytesize, ret;
 mpz_t z_phi, pless1, qless1;
 mpz_t z_seed, p, q;
 unsigned int N, k, e, check, r;
 double kdoub;

 stat("primes.in", &p_stbuf);
 printf("sizeof primes.in: %d\n", (int)p_stbuf.st_size);

 prime_buf = malloc(1 + p_stbuf.st_size);

 if(prime_buf == NULL) {
   printf("Failed to allocate memory to prime_buf.\n");
   exit(1);
 }

/**** START SETTING PRIMES ****/

 fp = fopen("primes.in", "r");

 if(fp == NULL) {
   printf("Error while opening primes.in for reading.\n");
   exit(1);
 }

 fgets(prime_buf, p_stbuf.st_size, fp);
 base = atoi(prime_buf);
 if(base < 2 || base > 32) {
   printf("value specified for base (%d) is outside of allowable range of 2 to 32.\n", base);
   exit(1);
 }

 fgets(prime_buf, p_stbuf.st_size, fp);
 mpz_init_set_str(p, prime_buf, base);

 if(!mpz_probab_prime_p(p, 50)) {
   printf("First prime is NOT prime.\n");
   mpz_out_str(stdout, base, p);
   printf("\n");
   exit(1);
 }

 fgets(prime_buf, p_stbuf.st_size, fp);
 mpz_init_set_str(q, prime_buf, base);

 if(!mpz_probab_prime_p(q, 50)) {
   printf("Second prime is NOT prime.\n");
   exit(1);
 }

 fclose(fp);
 free(prime_buf);

 if(mpz_sizeinbase(p, 2) <= 500) {
   printf("Bitsize of first prime(%d) needs to be geater than 500.\n", (int)mpz_sizeinbase(p, 2));
   exit(1);
 }

 if(mpz_sizeinbase(q, 2) <= 500) {
   printf("Bitsize of second prime(%d) needs to be geater than 500.\n", (int)mpz_sizeinbase(q, 2));
   exit(1);
 }

 if(mpz_sizeinbase(p, 2) == mpz_sizeinbase(q, 2)) {
   printf("Must select primes that differ in bitsize.\n");
   exit(1);
 }

/****  END SETTING OF PRIMES  ****/

 fp = fopen("msg.enc", "rb");

 if(fp == NULL) {
   printf("Error while opening msg.enc for reading.\n");
   exit(1);
 }

 stat("msg.enc", &stbuf);
 msg_buf = malloc(1 + stbuf.st_size);
 tmp_buf = malloc(1 + stbuf.st_size);
 chk_buf = malloc(1 + stbuf.st_size);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("file size  : %d\n", (int)stbuf.st_size);
   printf("buffer size: %d\n", (int)(1 + stbuf.st_size));
 }

 msg_buf[0] = 0;
 tmp[11] = 0;

 ret = fread(msg_buf, 1, stbuf.st_size, fp);

 if(ret < stbuf.st_size) {
   printf("ret: %d < %d\n", (int)ret, (int)stbuf.st_size);
   exit(1);
 }

 fclose(fp);

 if(msg_buf[0] != '1' || msg_buf[10] != '?') {
   strncpy(tmp, msg_buf, 11);
   printf("Error at beginning of msg.enc:\n<%s>\n", tmp);
   exit(1);
 }

 for(i = 0; msg_buf[i] != '?'; i++)
   tmp[i] = msg_buf[i];

 tmp[i] = 0;
 i_seed = atoi(tmp);
 printf("seed: %d\n", i_seed);

 msg_buf += i + 1;

 for(i = 0; msg_buf[i] != '#'; i++)
   tmp[i] = msg_buf[i];

 tmp[i] = 0;
 i_count = atoi(tmp);
 printf("count: %d\n", i_count);

 msg_buf += i + 1;

 for(i = 0; msg_buf[i] != '*'; i++)
   tmp[i] = msg_buf[i];

 tmp[i] = 0;
 i_bitsize = (i_count * 8) - atoi(tmp);
 printf("bitsize: %d\n", i_bitsize);
 printf("sizeof 'msg.enc': %d\n", (int)stbuf.st_size);

 msg_buf += i + 1;

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("file size: %d\n", (int)stbuf.st_size);
   printf("message size: %d\n", (int)strlen(msg_buf));
 }

 mpz_init(z_enc);

 msg_buf[i_count] = 0;

 mpz_import(z_enc, i_count, 1, 1, 0, 0, msg_buf);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("MSG:\n");
   mpz_out_str(stdout, 16, z_enc);
   printf("\n\n");
 }

 bitsize = i_bitsize;

 mpz_export(chk_buf, &count, 1, 1, 0, 0, z_enc);
 chk_buf[count] = 0;

 if(strcmp(msg_buf, chk_buf)) {
   printf("<%s>\nIS NOT:\n<%s>\n", msg_buf, chk_buf);
   fail = 1;
   /* exit(1); */
 }

/**** START SEED GEN ****/

 mpz_init_set_si(z_seed, i_seed);

 if(mpz_cmp_si(z_seed, 0) < 0) {
   printf("Negative seed in seed gen.\n");
   exit(1);
 }

 if(argc > 1 && !strcmp(argv[1], "DEBUG"))
   printf("\nbitsizes of primes: %d %d\n", (int)mpz_sizeinbase(p, 2), (int)mpz_sizeinbase(q, 2));

 mpz_init(z_phi);
 mpz_init(pless1);
 mpz_init(qless1);

 mpz_sub_ui(qless1, q, 1);
 mpz_sub_ui(pless1, p, 1);

 mpz_mul(z_phi, p, q);

 N = mpz_sizeinbase(z_phi, 2);
 e = N / 80;
 if(!(e & 1)) --e;

 if(e < 3) {
   printf("You need to choose different primes P and Q. The product of P and Q needs to be at least a 240-bit number");
   exit(1);
 }

 mpz_mul(z_phi, pless1, qless1);
 mpz_clear(pless1);
 mpz_clear(qless1);

 while(1) {
   if(mpz_gcd_ui(NULL, z_phi, e) == 1) break;
   e -= 2;
   if(e < 3) {
     printf("The chosen primes are unsuitable in seed gen function. Select other primes P ad Q\n");
     exit(1);
   }
 }

 kdoub = (double) 2 / (double)e;
 kdoub = (double) 1 - kdoub;
 kdoub *= (double) N;
 k = (int)kdoub;
 r = N - k;

 while(mpz_sizeinbase(z_seed, 2) < r) {
   mpz_mul_2exp(z_seed, z_seed, 1);
   if(mpz_sizeinbase(z_seed, 2) & 3)
     mpz_add_ui(z_seed, z_seed, 1);
 }

 if(mpz_sizeinbase(z_seed, 2) != r) {
   printf("The size of the seed (%d) being used should be %d.\n", (int)mpz_sizeinbase(z_seed, 2), r);
   exit(1);
 }


/****  END SEED GEN  ****/
/****  START PAD GEN ****/

 r_shift = bitsize % k;

 if(r_shift) its = (bitsize / k) + 1;
 else its = bitsize / k;

 if(its < 1) {
   printf("At least one iteration must be done.\n");
   exit(1);
 }

  if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("Z_SEED:\n");
   mpz_out_str(stdout, 16, z_seed);
   printf("\n");
   printf("seed: %d\n", i_seed);
   printf("e: %d\n", e);
   printf("k: %d\n", k);
   printf("N: %d\n", N);
   printf("r: %d\n", r);
   printf("r_shift: %d\n", (int)r_shift);
   printf("iterations: %d\n\n", (int)its);
 }

 mpz_init(z_mod);
 mpz_init(z_keep);
 mpz_init_set_ui(z_pad, 0);
 mpz_ui_pow_ui(z_mod, 2, k);

 for(i = 0; i < its; ++i) {
   mpz_powm_ui(z_seed, z_seed, e, z_phi);
   mpz_mod(z_keep, z_seed, z_mod);
   mpz_mul_2exp(z_pad, z_pad, k);
   mpz_add(z_pad, z_pad, z_keep);
   mpz_fdiv_q_2exp(z_seed, z_seed, k);
   if(!i) check = k - mpz_sizeinbase(z_keep, 2);
 }

 mpz_clear(z_phi);
 mpz_clear(z_keep);
 mpz_clear(z_mod);

 if(r_shift) mpz_fdiv_q_2exp(z_pad, z_pad, k - r_shift);

 if(check + mpz_sizeinbase(z_pad, 2) != bitsize) {
   printf("Bug in pad gen.\n");
   exit(1);
 }

 bitsize = mpz_sizeinbase(z_pad, 2);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("PAD:\n");
   mpz_out_str(stdout, 16, z_pad);
   printf("\n\n");
 }

/****  END PAD GEN   ****/

 mpz_init(z_dec);
 mpz_xor(z_dec, z_enc, z_pad);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("bitsize of encrypted message: %d\n", (int)mpz_sizeinbase(z_enc, 2));
   printf("bitsize of pad: %d\n", (int)mpz_sizeinbase(z_pad, 2));
   printf("bitsize of decrypted message: %d\n", (int)mpz_sizeinbase(z_dec, 2));
 }

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("DEC:\n");
   mpz_out_str(stdout, 16, z_dec);
   printf("\n\n");
 }

 bitsize = mpz_sizeinbase(z_dec, 2);

 bytesize = bitsize / 8;
 if(bitsize % 8) bytesize++;

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("bitsize of z_dec: %d\n", (int)bitsize);
   printf("bytesize of decrypted message: %d\n", (int)bytesize);
 }

 dec_buf = malloc(1 + bytesize);

 mpz_export(dec_buf, &count, 1, 1, 0, 0, z_dec);
 dec_buf[count] = 0;

 printf("mpz_export count: %d\n", (int)count);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("%02x\n", dec_buf[bytesize - 1]); /* Should be the last byte */
   printf("%02x\n", dec_buf[bytesize]);     /* Should be 00 */
 }

 dec_buf[bytesize] = 0; /* Should NOT be needed and is probably not needed. *
                         * But I'm tempted to leave it in ... just in case  */

/* printf("<%s>\n", dec_buf); */

 fp = fopen("msg.dec", "wb");

 ret = fwrite(dec_buf, 1, bytesize, fp);

 if(ret < bytesize) {
   printf("ret: %d < %d\n", (int)ret, (int)bytesize);
   exit(1);
 }

 fclose(fp);

 if(fail) printf("Fail: %d\n", fail);

 return 0;

}

