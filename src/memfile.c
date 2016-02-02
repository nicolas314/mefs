#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "logger.h"
#include "memfile.h"
#include "inode.h"
#include "fslimits.h"
#include "hmac.h"
#include "cipher.h"

#define MAGIC_SZ    4
#define CANARI_SZ   8

/* Magic number for memfs serialization files */
static char memfs_magic[] = {0xca, 0xfe, 0xfa, 0xce};

/* This is version 1.0 */
static char memfs_version[] = { 0x01, 0x00 };

/*
 * Initialize a memfile struct with blank fields
 */
void memfile_init(memfile * mf, const char * name, mode_t mode)
{
    if (!mf) {
        return ;
    }

    memset(mf, 0, sizeof(memfile));
    mf->name = name ? strdup(name) : NULL ;
    mf->sta.st_mode = S_IFREG | mode | 0600 ;
    mf->sta.st_uid  = getuid() ;
    mf->sta.st_gid  = getgid() ;
    mf->sta.st_nlink = 1 ;
    return ;
}

/*
 * Read a container with the provided key
 * Read all files and place them into the provided list
 * Returns:
 * >0   Number of read files
 * -1   File error during reading
 * -2   Wrong password in input
 */
int memfile_readfiles(char * filename, char * password, memfile * root)
{
    char *  buf ;
    char *  cur ;
    int     fd ;
    int     i ;
    struct stat fileinfo ;

    uint8_t nonce[NONCE_SZ];
    uint8_t key[KEY_SZ];

    uint64_t    u1, u2, u3 ;
    size_t      header_sz ;
    size_t      payload_sz ;
    char        fname[MAXNAMESZ];

    header_sz = MAGIC_SZ + 2 + NONCE_SZ + CANARI_SZ ;
    /* Find out file size in bytes */
    if (stat(filename, &fileinfo)!=0) {
        logger("no such file: %s", filename);
        return 1 ;
    }
    if (fileinfo.st_size < header_sz) {
        logger("not a container: ", filename);
        return -1 ;
    }
    /* Map input file */
    if ((fd=open(filename, O_RDONLY))==-1) {
        logger("cannot open: %s", filename);
        return -1 ;
    }
    buf = (char*)mmap(0,
                      fileinfo.st_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE,
                      fd,
                      0);
    close(fd);
    if (buf==(char*)-1) {
        logger("cannot map: %s", filename);
        return -1;
    }
    cur = buf ;
    payload_sz = fileinfo.st_size - header_sz ;
    /*
     * A container header is composed of:
     * A magic number of MAGIC_SZ bytes
     * A version number on 2 bytes: major.minor
     * A nonce of size NONCE_SZ bytes
     * A canari of size CANARI_SZ bytes
     */
    /* Check magic number */
    for (i=0 ; i<MAGIC_SZ ; i++) {
        if (cur[i]!=memfs_magic[i]) {
            logger("not a container: ", filename);
            munmap(buf, fileinfo.st_size);
            return -1 ;
        }
    }
    cur += MAGIC_SZ ;
    /* Read version number */
    if (cur[0]!=memfs_version[0] ||
        cur[1]!=memfs_version[1]) {
        logger("unsupported version for: ", filename);
        munmap(buf, fileinfo.st_size);
        return -1 ;
    }
    cur+=2 ;

    /* Copy nonce for later use */
    memcpy(nonce, cur, NONCE_SZ);
    cur += NONCE_SZ ;
    /* Derive key from password */
    derive_key(password,
               strlen(password),
               nonce,
               NONCE_SZ,
               key,
               KEY_SZ,
               20000);
    /* Decrypt everything starting from CANARI, using nonce and key */
    stream_cipher(cur,
                  fileinfo.st_size-(MAGIC_SZ+2+NONCE_SZ),
                  0,
                  key,
                  nonce);
    /* Test canari has expected pattern: 0xaaaa...aa */
    for (i=0 ; i<CANARI_SZ ; i++) {
        if ((unsigned char)cur[i]!=0xaa) {
            logger("wrong password for container: %s", filename);
            munmap(buf, fileinfo.st_size);
            return -2 ;
        }
    }
    cur+=CANARI_SZ ;

    /* Read files one by one */
    /*
     * filename is a zero-padded string of size MAXNAMESZ
     * filesize on a 64 big-endian unsigned int
     * ctime    on a 64-big-endian unsigned int
     * mtime    on a 64-big-endian unsigned int
     */
    i=0 ;
    while (1) {
        memcpy(fname, cur, MAXNAMESZ);
        cur+=MAXNAMESZ;
        memcpy(&u1, cur, sizeof(uint64_t));
        cur+=sizeof(uint64_t);
        memcpy(&u2, cur, sizeof(uint64_t));
        cur+=sizeof(uint64_t);
        memcpy(&u3, cur, sizeof(uint64_t));
        cur+=sizeof(uint64_t);

        root[i].name = strdup(fname);
        root[i].sta.st_ino = inode_next();
        root[i].sta.st_size     = u1 ;
        root[i].sta.st_ctime    = u2 ;
        root[i].sta.st_mtime    = u3 ;

        root[i].data = malloc(u1);
        memcpy(root[i].data, cur, u1);
        cur+=u1 ;
        if ((cur-buf) >= fileinfo.st_size)
            break ;
        i++ ;
    }
    munmap(buf, fileinfo.st_size);
    return 0 ;
}

/*
 * Save all files in rootdir to a container
 */
int memfile_savefiles(char * filename, char * password, memfile * root)
{
    FILE *  f ;
    int     i ;

    uint8_t nonce[NONCE_SZ];
    uint8_t key[KEY_SZ];
    uint8_t canari[CANARI_SZ];
    char    enc_name[MAXNAMESZ];
    uint64_t    u1, u2, u3 ;

    size_t  offset=0 ;

    /* Generate nonce */
    memcpy(nonce, get_nonce(), NONCE_SZ);
    /* Derive key from password */
    derive_key(password,
               strlen(password),
               nonce,
               NONCE_SZ,
               key,
               KEY_SZ,
               20000);
    /*
     * A container header is composed of:
     * A magic number of MAGIC_SZ bytes
     * A version number on 2 bytes: major.minor
     * A nonce of size NONCE_SZ bytes
     * A canari of size CANARI_SZ bytes
     */
    if ((f=fopen(filename, "w"))==NULL) {
        return 0 ;
    }
    /* Write magic number */
    fwrite(memfs_magic, 1, MAGIC_SZ, f);
    /* Write version */
    fwrite(memfs_version, 1, 2, f);
    /* Write nonce */
    fwrite(nonce, 1, NONCE_SZ, f);
    /* Generate and encrypt canari */
    for (i=0 ; i<CANARI_SZ ; i++) {
        canari[i] = 0xaa ;
    }
    stream_cipher(canari, CANARI_SZ, 0, key, nonce);
    fwrite(canari, 1, CANARI_SZ, f);
    offset += CANARI_SZ ;

    /* Write files one by one */
    /*
     * filename is a zero-padded string of size MAXNAMESZ
     * filesize on a 64 big-endian unsigned int
     * ctime    on a 64-big-endian unsigned int
     * mtime    on a 64-big-endian unsigned int
     */
    for (i=0 ; i<MAXFILES ; i++) {
        if (root[i].name==NULL) {
            continue ;
        }
        memset(enc_name, 0, MAXNAMESZ);
        strncpy(enc_name, root[i].name, MAXNAMESZ);
        stream_cipher(enc_name, MAXNAMESZ, offset, key, nonce);
        offset += MAXNAMESZ ;
        fwrite(enc_name, 1, MAXNAMESZ,  f);

        u1 = root[i].sta.st_size ;
        u2 = root[i].sta.st_ctime ;
        u3 = root[i].sta.st_mtime ;

        stream_cipher((uint8_t*)&u1, sizeof(uint64_t), offset, key, nonce);
        offset += sizeof(uint64_t);
        fwrite(&u1, sizeof(uint64_t), 1, f);

        stream_cipher((uint8_t*)&u2, sizeof(uint64_t), offset, key, nonce);
        offset += sizeof(uint64_t);
        fwrite(&u2, sizeof(uint64_t), 1, f);

        stream_cipher((uint8_t*)&u3, sizeof(uint64_t), offset, key, nonce);
        offset += sizeof(uint64_t);
        fwrite(&u3, sizeof(uint64_t), 1, f);

        stream_cipher(root[i].data,
                      root[i].sta.st_size, 
                      offset,
                      key,
                      nonce);
        offset += root[i].sta.st_size ;
        fwrite(root[i].data, 1, root[i].sta.st_size, f);
    }
    fclose(f);
    return 0 ;
}

/* vim: set ts=4 et sw=4 tw=75 */
