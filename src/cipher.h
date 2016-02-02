#ifndef _CIPHER_H_
#define _CIPHER_H_

#include <stdint.h>

#define NONCE_SZ    8

uint8_t * get_nonce(void);

void bin2hex(uint8_t * b, size_t sz, char * hex);
void hex2bin(char * hex, uint8_t * b, size_t sz);


/*
 * Encrypt a buffer using salsa20 using passwd as a basis to derive a
 * 256-bit key.
 * The input buffer is modified in place.
 * Returns -1 if errors occur, 0 otherwise
 */
int stream_cipher(
    uint8_t * buf,
    size_t sz,
    size_t offset,
    char * passwd,
    uint8_t * nonce);

#endif

