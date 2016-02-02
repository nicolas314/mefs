#ifndef __MEMFILE_H__
#define __MEMFILE_H__

#include <stdint.h>
#include <sys/stat.h>
#include "cipher.h"

typedef struct __memfile__ {
    struct stat     sta ;
    char    *       name ;
    uint8_t *       data ;
} memfile ;

void memfile_init(memfile * mf, const char * name, mode_t mode);
int memfile_dump(memfile * mf, FILE * f);
int memfile_read(memfile * mf, FILE * f);
int memfile_dump_s20(memfile * mf, FILE * f, uint8_t * key);
int memfile_read_s20(memfile * mf, FILE * f, uint8_t * key);

int memfile_readfiles(char * filename, char * password, memfile * root);
int memfile_savefiles(char * filename, char * password, memfile * root);





#endif
/* vim: set ts=4 et sw=4 tw=75 */
