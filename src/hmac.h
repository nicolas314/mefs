#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>

void hmac_sha2(
    uint8_t * key,
    int klen,
    uint8_t * message,
    int mlen,
    uint8_t * dkey);

/*
 * Derive a key from a password using PKCS#5/SHA2
 * @password    User-provided password, not necessarily NULL-terminated
 * @plen        Number of bytes in password
 * @salt        Nonce
 * @slen        Salt length in bytes
 * @key         Output key, must be pre-allocated prior to calling
 * @klen        Desired key length in bytes
 * @iter        Number of iterations, keep it high for more security
 */
int derive_key(
    char * password,
    int    plen,
    uint8_t * salt,
    int    slen,
    uint8_t * key,
    int    klen,
    uint32_t iter);

#endif
