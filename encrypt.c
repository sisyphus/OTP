/*******************************************************************************************
 * Copyright 2020 sisyphus                                                                 *
 * The gmp library (https://gmplib.org) is required.                                       *
 *                                                                                         *
 * I build encrypt.exe with: gcc -o encrypt.exe encrypt.c -lgmp                            *
 * Usage: encrypt.exe                                                                      *
 *                                                                                         *
 * Upon execution, the contents of "msg.in" are encrypted in a way that's based on the     *
 * contents of "primes.in", and written to "msg.enc"  .                                    *
 * In turn. the contents of "msg.enc" can be decrypted back to the original contents of    *
 * of "msg.in" by running decrypt.exe (whch needs to locate an identical "primes.in").     *
 *                                                                                         *
 * Additional "DEBUG" output can be obtained by running "encrypt.exe DEBUG" instead of     *
 * simply "encrypt.exe".                                                                   *
 *                                                                                         *
 * USERID must be a unique value for each user. This value must consist of 11 decimal      *
 * digits. The leading (most siginificant) digit must be one, and the last (least          *
 * siginificant) 6 digits must all be "0".                                                 *
 * This leaves the 2nd, 3rd, and 4th digits to form the unique identifier - thus           *
 * allowing for 1000 users (0 to 999, inclusive).                                          *
 * This value is incremented each time a message is encrypted, thus allowing for each user *
 * to send 1,000,000 encrypted messages - after which, new input primes need to be         *
 * generated - and next_seed.txt needs to be manually altered to contain "0".              *
 *******************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <gmp.h>

#ifndef USERID
#define USERID 1000000000 /* Edit this value (as per documented    *
                           * procedure) to be unique for all users */
#endif

int main(int argc, char *argv[]) {
 FILE* fp;
 int i_seed, base, i, i_count, i_bitsize;
 struct stat stbuf;
 struct stat stbuf_enc;
 struct stat p_stbuf;
 char seed_buf[11];
 char tmp[12];
 char *msg_buf, *tmp_buf, *chk_buf, *enc_buf, *prime_buf;
 mpz_t z_in, z_pad, z_mod, z_keep, z_check;
 size_t bitsize, r_shift, its, count, ret, pad_shift, bitdiff;
 mpz_t z_phi, pless1, qless1;
 mpz_t z_seed, p, q;
 unsigned int N, k, e, check, r;
 double kdoub;
 mpz_t z_enc;

 stat("msg.in", &stbuf);

 if(stbuf.st_size > 536870900) {
   printf("This program cannot reliably deal with an 'msg.in' whose size is greater than 536,870,900 bytes.\n");
   exit(1);
 }

 stat("primes.in", &p_stbuf);

 printf("sizeof 'primes.in': %d bytes\n", (int)p_stbuf.st_size);

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
/** START PARSING NEXT_SEED.TXT **/

 fp = fopen("next_seed.txt", "r");

 if(fp == NULL) {
   printf("Error while opening next_seed.txt for reading.\n");
   exit(1);
 }

 if(fgets (seed_buf, 11, fp)==NULL) {
   printf("Error while reading next_seed.txt.\n");
   exit(1);
 }

 i_seed = atoi(seed_buf);

 if(i_seed < 0 || i_seed > 999999) {
   printf("i_seed (%d) needs to initially be in range 0 to 999999 (inclusive).\n", i_seed);
   exit(1);
 }

 i_seed += USERID;

 printf("seed: %d\n", i_seed);

 fclose(fp);

 if(i_seed < 1000000000 || i_seed >= 2000000000) {
   printf("i_seed (%d) should now be in the range 1,000,000,000 to 1,999,999,999 (inclusive).\n", i_seed);
   exit(1);
 }

 fp = fopen("next_seed.txt", "w");

 if(fp == NULL) {
   printf("Error while opening next_seed.txt for writing.\n");
   exit(1);
 }

 sprintf(seed_buf, "%d", i_seed - USERID + 1);
 fputs(seed_buf, fp);
 fclose(fp);

/** END PARSING NEXT_SEED.TXT **/

 fp = fopen("msg.in", "rb");

 if(fp == NULL) {
   printf("Error while opening msg.in for reading.\n");
   exit(1);
 }

 msg_buf = malloc(1 + stbuf.st_size);
 if(msg_buf == NULL) {
   printf("Failed to allocate memory to msg_buf.\n");
   exit(1);
 }

 tmp_buf = malloc(1 + stbuf.st_size);
 if(tmp_buf == NULL) {
   printf("Failed to allocate memory to tmp_buf.\n");
   exit(1);
 }

 chk_buf = malloc(1 + stbuf.st_size);
 if(chk_buf == NULL) {
   printf("Failed to allocate memory to chk_buf.\n");
   exit(1);
 }

 printf("sizeof 'msg.in': %d\n", (int)stbuf.st_size);

 msg_buf[0] = 0;
 tmp[11] = 0;

 ret = fread(msg_buf, 1, 1 + stbuf.st_size, fp);

 if(ret != stbuf.st_size) {
   printf("'msg.in' contains %d bytes but %d were read to msg_buf.\n", (int)stbuf.st_size, (int)ret);
   exit(1);
 }

 msg_buf[stbuf.st_size] = 0; /* I thought fread() would do this ? */

 fclose(fp);

 mpz_init(z_in);
 mpz_import(z_in, stbuf.st_size, 1, 1, 0, 0, msg_buf);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("MSG_IN:\n");
   mpz_out_str(stdout, 16, z_in);
   printf("\n");
 }

 bitsize = mpz_sizeinbase(z_in, 2);
 i_bitsize = (int)bitsize;

 printf("bitsize: %d\n", i_bitsize);

 mpz_export(chk_buf, &count, 1, 1, 0, 0, z_in);
 chk_buf[count] = 0;

 /* i_count = (int)count; */ /* No !! We need to set i_count to the 'count' from the next mpz_export */

 if(strcmp(msg_buf, chk_buf)) {
   printf("<%s>\nIS NOT\n<%s>\n", msg_buf, chk_buf);
   exit(1);
 }

 for(i = 0; i < count; i++ ) {
   if(msg_buf[i] != chk_buf[i]) {
     printf("byte[%d] differs between msg_buf and chk_buf.\n", i);
     exit(1);
   }
 }

 if(msg_buf[count] != chk_buf[count]) {
   printf("msg_buf[%d] != chk_buf[%d]\n", (int)count, (int)count);
   exit(1);
 }

 if(msg_buf[count] != 0) {
   printf("msg_buf[%d] and chk_buf[%d] are not NULL>\n", (int)count, (int)count);
   exit(1);
 }

 if(ret != count) {
   printf("Number of imported bytes (%d) differs from number of exported bytes (%d).\n",
          (int)ret, (int)count);
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
 if(!(e & 1)) --e; /* gcd(phi,e) must be 1 - which implies that e must be odd */

 if(e < 3) {
   printf("You need to choose different (larger) primes P and Q.\n");
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

 /* Given seed (i_seed) needs to be expanded  *
  * to r bits. Pad with '0111' sequences.     */
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

 /***************************************************************
  * enc_buf is the encrypted message. It is written to msg.enc. *
  * That buffer is prefixed with the information needed for the *
  * recipient to decrypt the message. Hence we provide it with  *
  * an additional 28 bytes (though 25 should be sufficient).    *
  ***************************************************************/
 enc_buf = malloc(28 + stbuf.st_size);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("PAD:\n");
   mpz_out_str(stdout, 16, z_pad);
   printf("\n");
 }

/****  END PAD GEN   ****/

 mpz_init(z_enc);
 mpz_xor(z_enc, z_in, z_pad);
 bitdiff = mpz_sizeinbase(z_in, 2) - mpz_sizeinbase(z_enc, 2);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("bitsize of input message: %d\n", (int)mpz_sizeinbase(z_in, 2));
   printf("bitsize of pad: %d\n", (int)mpz_sizeinbase(z_pad, 2));
   printf("bitsize of encrypted message: %d\n", (int)mpz_sizeinbase(z_enc, 2));
 }

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("MSG:\n");
   mpz_out_str(stdout, 16, z_enc);
   printf("\n");
 }

 mpz_export(chk_buf, &count, 1, 1, 0, 0, z_enc);
 chk_buf[count] = 0;

 i_count = count;

 mpz_init(z_check);
 mpz_import(z_check, count, 1, 1, 0, 0, chk_buf);

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("%d bytes written to chk_buf\n", (int)count);
 }

 if(mpz_cmp(z_check, z_enc)) {
   printf("mpz_export-mpz_import round trip failed.\n");
   printf("strlen(chk_buf): %d\n", (int)strlen(chk_buf));
   exit(1);
 }

 sprintf(enc_buf, "%d", i_seed);

 strcat(enc_buf, "?");
 sprintf(tmp, "%d", i_count);
 strcat(enc_buf, tmp);

 strcat(enc_buf, "#");
 sprintf(tmp, "%d", (i_count * 8) - i_bitsize);
 strcat(enc_buf, tmp);

 strcat(enc_buf, "*");

 pad_shift = strlen(enc_buf);
 enc_buf += pad_shift;
 for(i = 0; i < count; i++)
   enc_buf[i] = chk_buf[i];
 enc_buf[count] = 0;
 enc_buf -= pad_shift;

 if(strlen(enc_buf) != pad_shift + strlen(chk_buf)) {
   printf("string being written to msg.enc might be incorrect.\n");
   exit(1);
 }

 fp = fopen("msg.enc", "wb");

 if(fp == NULL) {
   printf("Error while opening msg.enc for writing.\n");
   exit(1);
 }

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("MSG_IN_BUFFER:\n");
   for(i = 0; i < count + pad_shift; i++)
     printf("%02x", ((const unsigned char*)enc_buf)[i]);
   printf("\n");
 }

 ret = fwrite(enc_buf, 1, count + pad_shift, fp);

 if(ret < count + pad_shift) {
   printf("ret: %d < %d\n", (int)ret, (int)count + (int)pad_shift);
   exit(1);
 }

 if(argc > 1 && !strcmp(argv[1], "DEBUG")) {
   printf("%d bytes written to enc_buf\n", (int)count + (int)pad_shift);
 }

 fclose(fp);

 stat("msg.enc", &stbuf_enc);
 printf("sizeof 'msg.enc': %d\n", (int)stbuf_enc.st_size);

 return 0;
}



