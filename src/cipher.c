#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha2.h"
#include "salsa20.h"
#include "hmac.h"


#define NONCE_SZ    8

/*
 * Generate a nonce and return a pointer to it.
 * The pointer is statically allocated inside this function, do not free or
 * modify it! This is not thread-safe.
 */
uint8_t * get_nonce(void)
{
    static uint8_t  nonce[NONCE_SZ];
    FILE * ran ;
    int i ;

    if ((ran=fopen("/dev/urandom", "r"))==NULL) {
        return NULL ;
    }
    fread(nonce, sizeof(uint8_t), NONCE_SZ, ran);
    fclose(ran);
    return nonce ;
}

/* Convert a nonce from binary to hex for printing */
void bin2hex(uint8_t * b, size_t sz, char * hex)
{
    int i ;
    for (i=0 ; i<sz ; i++) {
        sprintf(hex+2*i, "%02x", b[i]);
    }
    return ;
}

/* Convert a nonce back from hex to binary */
void hex2bin(char * hex, uint8_t * b, size_t sz)
{
    int i;
    for (i=0 ; i<sz ; i++) {
        switch(hex[2*i]) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            b[i] = (hex[2*i]-'0') * 0x10 ;
            break ;
            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            b[i] = (hex[2*i]-'a'+0x0a) * 0x10 ;
            break ;
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            b[i] = (hex[2*i]-'A'+0x0a) * 0x10 ;
            break ;
            default: b[i]=0 ; break;
        }
        switch(hex[2*i+1]) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            b[i] += hex[2*i+1]-'0';
            break ;
            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            b[i] += 0x0a + hex[2*i+1]-'a';
            break ;
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            b[i] += 0x0a + hex[2*i+1]-'A';
            break ;
            default: break;
        }
    }
    return ;
}


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
    uint8_t * key,
    uint8_t * nonce)
{
    sha256_ctx  sctx ;

    if (!buf || !key || (sz<1) || !nonce) {
        return -1 ;
    }
    return s20_crypt(key, S20_KEYLEN_256, nonce, offset, buf, sz);
}

