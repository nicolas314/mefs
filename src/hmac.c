#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha2.h"

#define SHA2_BYTESZ     32
#define SHA2_BLOCKSZ    64

void hmac_sha2(
    uint8_t * key,
    int klen,
    uint8_t * message,
    int mlen,
    uint8_t * dkey)
{
    sha256_ctx  sctx ;
    uint8_t wkey[SHA2_BLOCKSZ];
    uint8_t o_key_pad[SHA2_BLOCKSZ];
    uint8_t i_key_pad[SHA2_BLOCKSZ];
    int i ;

    if (!key || klen<1 || !message || mlen<1 || !dkey)
        return ;

    if (klen > SHA2_BLOCKSZ) {
        /* Keys longer than blocksize are shortened */
        sha256_init(&sctx);
        sha256_update(&sctx, key, klen);
        sha256_final(&sctx, wkey);
        klen = SHA2_BYTESZ;
    } else {
        /* Keys shorter than blocksize are right-padded with zeros */
        memset(wkey, 0, SHA2_BLOCKSZ);
        memcpy(wkey, key, klen);
        klen = SHA2_BLOCKSZ;
    }
    /* Prepare key pads */
    for (i=0 ; i<SHA2_BLOCKSZ ; i++) {
        o_key_pad[i] = 0x5c ^ wkey[i];
        i_key_pad[i] = 0x36 ^ wkey[i];
    }
    /* Compute h1 = hash(i_key_pad || message) */
    sha256_init(&sctx);
    sha256_update(&sctx, i_key_pad, SHA2_BLOCKSZ);
    sha256_update(&sctx, message, mlen);
    sha256_final(&sctx, wkey);
    /* Compute h2 = hash(o_key_pad || h1) */
    sha256_init(&sctx);
    sha256_update(&sctx, o_key_pad, SHA2_BLOCKSZ);
    sha256_update(&sctx, wkey, SHA2_BYTESZ);
    sha256_final(&sctx, dkey);

    return ;
}

/*
 * Derive a key from a password using PKCS#5/SHA2
 */
int derive_key(
    char * password,
    int    plen,
    uint8_t * salt,
    int    slen,
    uint8_t * key,
    int    klen,
    uint32_t iter)
{
    uint8_t * asalt ;
    uint8_t   obuf[SHA2_BYTESZ];
    uint8_t   d1[SHA2_BYTESZ], d2[SHA2_BYTESZ];
    int       i, j ;
    int       count ;
    size_t    r ;

    if (!password || plen<1 || !salt || slen<1 || !key || klen<1 || iter<1)
        return -1 ;

    asalt = malloc(slen+4);
    memcpy(asalt, salt, slen);
    for (count=1 ; klen>0 ; count++) {
        asalt[slen + 0] = (count >> 24) & 0xff ;
        asalt[slen + 1] = (count >> 16) & 0xff ;
        asalt[slen + 2] = (count >>  8) & 0xff ;
        asalt[slen + 3] =  count        & 0xff ;
        /* hmac_sha2(asalt, slen+4, password, plen, d1); */
        hmac_sha2(password, plen, asalt, slen+4, d1);
        memcpy(obuf, d1, sizeof(obuf));

        for (i=1 ; i<iter ; i++) {
            /* hmac_sha2(d1, sizeof(d1), password, plen, d2); */
            hmac_sha2(password, plen, d1, sizeof(d1), d2);
            memcpy(d1, d2, sizeof(d1));
            for (j=0 ; j<sizeof(obuf) ; j++) {
                obuf[j] ^= d1[j];
            }
        }
        r = (klen<SHA2_BYTESZ) ? klen : SHA2_BYTESZ ;
        memcpy(key, obuf, r);
        key += r ;
        klen -= r ;
    }
    memset(asalt, 0, slen+4);
    free(asalt);
    memset(d1, 0, SHA2_BYTESZ);
    memset(d2, 0, SHA2_BYTESZ);
    memset(obuf, 0, SHA2_BYTESZ);
    return 0 ;

}


#ifdef TEST_HMAC
#include <stdio.h>
int main(int argc, char *argv[])
{
    struct {
        uint8_t * key ;
        int             klen ;
        uint8_t * msg ;
        int             mlen ;
        uint8_t * res ;
    } test_vectors[] = {
        { .key = (char []){
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b
          },
          .klen = 20,
          .msg = (char[]){
            0x48, 0x69, 0x20, 0x54, 0x68,
            0x65, 0x72, 0x65
          },
          .mlen = 8,
          .res = (char[]){
            0xb0, 0x34, 0x4c, 0x61, 0xd8,
            0xdb, 0x38, 0x53, 0x5c, 0xa8,
            0xaf, 0xce, 0xaf, 0x0b, 0xf1,
            0x2b, 0x88, 0x1d, 0xc2, 0x00,
            0xc9, 0x83, 0x3d, 0xa7, 0x26,
            0xe9, 0x37, 0x6c, 0x2e, 0x32,
            0xcf, 0xf7
          }
        },
        { .key = (char[]) {
            0x4a,0x65,0x66,0x65
          },
          .klen = 4,
          .msg = (char[]) {
            0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,0x79,0x61,0x20,
            0x77,0x61,0x6e,0x74,0x20,0x66,0x6f,0x72,0x20,0x6e,0x6f,
            0x74,0x68,0x69,0x6e,0x67,0x3f
          },
          .mlen = 28,
          .res = (char[]) {
              0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,
              0x24,0x26,0x08,0x95,0x75,0xc7,0x5a,0x00,0x3f,0x08,
              0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,
              0x38,0x43
          }
        },
        { .key = (char[]) {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
          },
          .klen = 20,
          .msg = (char[]) {
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd
          },
          .mlen = 50,
          .res = (char[]) {
            0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,
            0xd0,0x91,0x81,0xa7,0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,
            0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
          }
        },
        { .key = (char[]) {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,
            0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
            0x17,0x18,0x19
          },
          .klen = 25,
          .msg = (char[]) {
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd
          },
          .mlen = 50,
          .res = (char[]) {
            0x82,0x55,0x8a,0x38,0x9a,0x44,0x3c,0x0e,0xa4,0xcc,0x81,
            0x98,0x99,0xf2,0x08,0x3a,0x85,0xf0,0xfa,0xa3,0xe5,0x78,
            0xf8,0x07,0x7a,0x2e,0x3f,0xf4,0x67,0x29,0x66,0x5b
          }
        },
        { .key=NULL }
        /*
        { .key = (char[]) {
          },
          .klen =,
          .msg = (char[]) {
          },
          .mlen =,
          .res = (char[]) {
          }
        },
        */
    };

    struct {
        char *  pass ;
        int     plen ;
        char *  salt ;
        int     slen ;
        int     iter ;
        int     dklen ;
        uint8_t *  res ;
    } test_dk[] = {
        {
            .pass = "password",
            .plen = 8,
            .salt = "salt",
            .slen = 4,
            .iter = 1,
            .dklen = 32,
            .res = (char[]){
                0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c,
                0x43,0xe7,0x22,0x52,0x56,0xc4,0xf8,0x37,
                0xa8,0x65,0x48,0xc9,0x2c,0xcc,0x35,0x48,
                0x08,0x05,0x98,0x7c,0xb7,0x0b,0xe1,0x7b
            }
        },
        {
            .pass = "password",
            .plen = 8,
            .salt = "salt",
            .slen = 4,
            .iter = 2,
            .dklen = 32,
            .res = (char[]) {
                0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a,
                0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e,
                0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47,
                0x4c, 0x43
            }
        },
        {
            .pass = "password",
            .plen = 8,
            .salt = "salt",
            .slen = 4,
            .iter = 4096,
            .dklen = 20,
            .res = (char[]) {
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53,
                0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0
            }
        },
        {
            .pass = "password",
            .plen = 8,
            .salt = "salt",
            .slen = 4,
            .iter = 20000,
            .dklen = 20,
            .res = (char[]) {
                0x2a,0x6a,0x4f,0x08,0x32,0xd0,0x46,0x83,0x8f,0x4a,
                0x22,0xcb,0xad,0xc9,0x4d,0xff,0x08,0xa5,0xbc,0xc3
            }
        },
        {
            .pass = NULL
        }
    };
    uint8_t hmac[SHA2_BYTESZ];
    uint8_t * dk ;
    int i=0 ;

    printf("HMAC-SHA256 test vectors\n");
    while (test_vectors[i].key) {
        hmac_sha2(test_vectors[i].key,
                  test_vectors[i].klen,
                  test_vectors[i].msg,
                  test_vectors[i].mlen,
                  hmac);
        hd("computed", hmac, SHA2_BYTESZ);
        hd("expected", test_vectors[i].res, SHA2_BYTESZ);
        i++;
    }

    printf("PKBDF2-HMAC-SHA256 test vectors\n");
    i=0 ;
    while (test_dk[i].pass) {
        dk = calloc(test_dk[i].dklen, 1);
        derive_key(test_dk[i].pass,
                   test_dk[i].plen,
                   test_dk[i].salt,
                   test_dk[i].slen,
                   dk,
                   test_dk[i].dklen,
                   test_dk[i].iter);
        hd("computed", dk, test_dk[i].dklen);
        hd("expected", test_dk[i].res, test_dk[i].dklen);
        free(dk);
        i++;
    }


}
#endif
