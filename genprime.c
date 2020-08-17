/*******************************************************************************************
 * Copyright 2020 sisyphus                                                                 *
 * The gmp library (https://gmplib.org) is required.                                       *
 *                                                                                         *
 * I build genprime.exe with: gcc -o genprime.exe genprime.c -lgmp                         *
 * Usage: genprime.exe base integer_string1 integer_string2                                *
 *                                                                                         *
 * Arguments:                                                                              *
 *  base: a number between 2 and 32 (inclusive) that specifies the numeric base, b, of the *
 *        the next 2 arguments.                                                            *
 *  integer_string1: a string of base b integers. The integer_string1 argument must        *
 *                   represent an integer that contains more than 500 bits.                *
 *  integer_string2: another string of base b integers. The integer_string2 argument       *
 *                   must represent an integer that contains more than 500 bits.           *
 *                                                                                         *
 * Upon execution of the program the following is written to a file named "primes.in",     *
 *  clobbering any existing file of the same name:                                         *
 *                                                                                         *
 *  Line 1: the base b. (Must be in the range 2 to 32, inclusive).                                                                   *
 *  Line 2: the smallest prime (written as a base b integer) that is larger than the       *
 *           base b integer_string1 argument.                                              *
 *                                                                                         *
 *  Line 3: the smallest prime (written as a base b integer) that is larger than the       *
 *           base b integer_string2 argument.                                              *
 *                                                                                         *
 * The values held in "primes.in" will be used by encrypt.exe and decrypt.exe to           *
 * generate (resp. decrypt) an encrypted message.                                          *
 *                                                                                         *
 * The same base and primes must be used for both encryption and decryption. The           *
 * security depends upon the values of the two primes being available only to the sender   *
 * and the intended recipient(s) of the encrypted message.                                 *
 *******************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <gmp.h>

int main(int argc, char *argv[]) {
 FILE *fp;
 mpz_t a, b, p, q;
 int base;
 size_t bitsize1, bitsize2;
 int iterations = 50000;

 if(argc != 4) {
   printf("Usage: genprime base integer_string1 integer_string2\n");
   exit(1);
 }

 mpz_init(p);
 mpz_init(q);
 base = atoi(argv[1]);

 if(base < 2 || base > 32) {
   printf("value specified for base (%d) is outside of allowable range of 2 to 32.\n", base);
   exit(1);
 }

 if(mpz_init_set_str(a, argv[2], base)) {
   printf("Second command line argument is not a valid base %d integer.\n", base);
   exit(1);
 }

 bitsize1 = mpz_sizeinbase(a, 2);
 if(bitsize1 <= 500) {
   printf("2nd command line argument needs to be at least 501 bits, but is only %d bits.\n",
          (int)bitsize1);
   exit(1);
 }

 if(mpz_init_set_str(b, argv[3], base)) {
   printf("Third command line argument is not a valid base %d integer.\n", base);
   exit(1);
 }

 bitsize2 = mpz_sizeinbase(b, 2);
 if(bitsize2 <= 500) {
   printf("3rd command line argument needs to be at least 501 bits, but is only %d bits.\n",
          (int)bitsize2);
   exit(1);
 }

 while(1) {
   mpz_nextprime(p, a);
   if(mpz_probab_prime_p(p, 2 + (iterations / bitsize1))) break;
   mpz_add_ui(a, p, 1);
 }

 printf("1st prime found - checked by running %d Miller-Rabin tests.\n",
        2 + (iterations / bitsize1));

 while(1) {
   mpz_nextprime(q, b);
   if(mpz_probab_prime_p(q, 2 + (iterations / bitsize2))) break;
   mpz_add_ui(b, q, 1);
 }

 printf("2nd prime found - checked by running %d Miller-Rabin tests.\n",
        2 + (iterations / bitsize2));

 fp = fopen("primes.in", "w");

 if(fp == NULL) {
   printf("Couldn't create primes.txt for writing.\n");
   exit(1);
 }

 fputs(argv[1], fp);
 fputs("\n", fp);
 mpz_out_str(fp, base, p);
 fputs("\n", fp);
 mpz_out_str(fp, base, q);
 fputs("\n", fp);

 fclose(fp);

 printf("Successfully Done\n");

 return 0;
}
