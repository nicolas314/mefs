#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "sha2.h"
#include "salsa20.h"
#include "hmac.h"


int main(int argc, char * argv[])
{
    char * buf ;
    size_t sz ;
    uint8_t * nonce ;
    uint8_t   key[32];
    char   hex[65] ;
    int    i ;

    buf = strdup("12345678901234567890");
    sz  = strlen(buf);
	if (argc<2) {
		printf("use: %s passwd\n", argv[0]);
		return 1 ;
	}
    /* Get a nonce */
    nonce = get_nonce();
    bin2hex(nonce, NONCE_SZ, hex);
    printf("nonce[%s]\n", hex);
    /* Derive key from password */
    printf("deriving key...\n");
    derive_key(argv[1],
               strlen(argv[1]),
               nonce,
               NONCE_SZ,
               key,
               32,
               20000);

    printf("stream cipher\n");
    stream_cipher(buf, sz, 0, key, nonce);
    printf("[");
    for (i=0 ; i<sz ; i++) {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("]\n");
    fflush(stdout);
    printf("stream cipher\n");
    stream_cipher(buf, sz, 0, key, nonce);
    printf("[%s]\n", buf);

    printf("by halves\n");
    stream_cipher(buf, sz/2, 0, key, nonce);
    stream_cipher(buf+sz/2, sz/2, sz/2, key, nonce);
    printf("[");
    for (i=0 ; i<sz ; i++) {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("]\n");

    printf("by 10 and sz-10\n");
    stream_cipher(buf, 10, 0, key, nonce);
    stream_cipher(buf+10, sz-10, 10, key, nonce);
    printf("[%s]\n", buf);
    free(buf);
	return 0 ;
}
