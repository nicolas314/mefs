/*
 * Implementing a simple filesystem in memory
 * Based on these fuse tutorials:
 * http://www.cs.hmc.edu/~geoff/classes/hmc.cs135.201001/homework/fuse/fuse_doc.html
 * http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/
 */

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <zlib.h>

#include "logger.h"
#include "memfile.h"
#include "inode.h"
#include "fslimits.h"

#define DEBUG   1
#if DEBUG<1
#define logger(...)
#endif

#define KEYSZ   32

static struct {
    char backup_filename[MAXNAMESZ] ;
    char * password ;
    int    err ;
} config ;

/*
 * For this version, all files are kept in the root directory
 * with a limited amount of files (MAXFILES).
 */
static memfile rootdir[MAXFILES] ;
/* The root node */
static struct stat rootfs ;

/* Find file called 'path' in rootdir */
static int rootdir_find(const char * path)
{
    int i ;

    if (!path) {
        return -1 ;
    }
    for (i=0 ; i<MAXFILES ; i++) {
        if (rootdir[i].name && (!strcmp(path, rootdir[i].name))) {
            return i ;
        }
    }
    return -1 ;
}

/* Find first available slot in rootdir */
static int rootdir_first(void)
{
    int i ;
    for (i=0 ; i<MAXFILES ; i++) {
        if (rootdir[i].name == NULL) {
            return i ;
        }
    }
    return -1 ;
}

/*
 * Run only once at start
 */
static void * mefs_init(struct fuse_conn_info * conn)
{
    time_t  now ;
    int i, ret ;
    memfile mf ;

    logger("mefs_init");
    /* Setup root directory */
    rootfs.st_mode      = S_IFDIR | 0755 ;
    rootfs.st_ino       = 1 ;
    rootfs.st_nlink     = 2;
    rootfs.st_uid       = getuid();
    rootfs.st_gid       = getgid();
    rootfs.st_size      = 0 ;
    rootfs.st_blksize   = BLOCKSZ;
    rootfs.st_blocks    = 0 ;
    time(&now);
    rootfs.st_mtime     = now ;
    rootfs.st_ctime     = now ;

    /* Initialize list of files */
    for (i=0 ; i<MAXFILES ; i++) {
        memfile_init(rootdir+i, NULL, 0);
    }

    ret =
    memfile_readfiles(config.backup_filename,
                      config.password,
                      rootdir);
    if (ret<0) {
        config.err++ ;
        fuse_exit(fuse_get_context()->fuse);
    }
    return NULL ;
}

/*
 * Free everything!
 */
static void mefs_destroy(void * p)
{
    logger("mefs_destroy");
    if (config.err<1) {
        memfile_savefiles(config.backup_filename,
                          config.password,
                          rootdir);
    }
    return ;
}

/*
 * Return file attributes. See stat(2)
 */
static int mefs_getattr(const char *path, struct stat *stbuf)
{
    int i ;

    if (!path || ! stbuf) {
        return -ENOENT ;
    }
    logger("mefs_getattr: %s", path);
    if (!strcmp(path, "/")) {
        memcpy(stbuf, &rootfs, sizeof(struct stat));
        return 0 ;
    }
    /* Find name in rootdir */
    if ((i=rootdir_find(path))<0) {
        return -ENOENT ;
    }
    memcpy(stbuf, &(rootdir[i].sta), sizeof(struct stat));
	return 0 ;
}

/*
 * Since there is only one directory to take care of, everything
 * is hardcoded here for rootdir.
 */
static int mefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
    int i ;

    if (!path || !buf) {
        return -ENOENT ;
    }
    logger("mefs_readdir");
    if (strcmp(path, "/")) {
        return -ENOENT ;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    for (i=0 ; i<MAXFILES ; i++) {
        if (rootdir[i].name) {
            filler(buf, rootdir[i].name+1, &(rootdir[i].sta), 0);
        }
    }
	return 0;
}


/*
 * Delete a file
 */
static int mefs_unlink(const char *path)
{
    int i ;

    if (!path) {
        return -ENOENT ;
    }
    logger("mefs_unlink %s", path);
    if ((i = rootdir_find(path))<0) {
        return -ENOENT ;
    }
    /* Clean up all data */
    if (rootdir[i].sta.st_size>0 && rootdir[i].data!=NULL) {
        free(rootdir[i].data);
    }
    if (rootdir[i].name != NULL) {
        free(rootdir[i].name);
    }
    memset(&(rootdir[i]), 0, sizeof(memfile));
	return 0;
}

/*
 * Rename from to to. Source and target do not have to be in the same
 * directory, you may have to move the source. See rename(2)
 */
static int mefs_rename(const char *from, const char *to)
{
    int i;
    time_t now ;

    if (!from || !to) {
        return -ENOENT ;
    }

    logger("mefs_rename %s %s", from, to);
    i = rootdir_find(from);
    if (i<0) {
        return -ENOENT ;
    }
    if (rootdir[i].name != NULL) {
        free(rootdir[i].name);
    }
    rootdir[i].name = strdup(to);
    time(&now);
    rootdir[i].sta.st_mtime = now ;

	return 0;
}

/*
 * Truncate or extend the given file to specified size.
*/
static int mefs_truncate(const char *path, off_t size)
{
    time_t now ;
    int i ;
    uint8_t * newbuf ;

    logger("mefs_truncate: %s sz %d", path, (int)size);

    i = rootdir_find(path);
    if (i<0) {
        return -ENOENT ;
    }
    newbuf = calloc(size, sizeof(uint8_t));
    memcpy(newbuf, rootdir[i].data, size);
    if (rootdir[i].data) {
        free(rootdir[i].data);
    }
    rootdir[i].data = newbuf ;
    rootdir[i].sta.st_size = size ;
    rootdir[i].sta.st_blocks = 1 + size / BLOCKSZ ;
    time(&now);
    rootdir[i].sta.st_mtime = now ;

	return 0;
}

/*
 * Modify file time access. Useful for 'touch'
 */
static int mefs_utimens(const char * path, const struct timespec ts[2])
{
    int i ;
    time_t now ;

    if ((i=rootdir_find(path))<0) {
        return -ENOENT ;
    }

    time(&now);
    rootdir[i].sta.st_mtime = now ;
    return 0 ;

}

/*
 * Create a new file
 */
static int mefs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int i ;
    time_t now ;

    if (!path) {
        return -1 ;
    }
    logger("mefs_create %s", path);
    i = rootdir_find(path);
    if (i<0) {
        i = rootdir_first();
        if (i<0) {
            return -ENOSPC ;
        }
    }

    memfile_init(rootdir+i, path, mode);
    time(&now);
    rootdir[i].sta.st_ctime = now ;
    rootdir[i].sta.st_ino = inode_next() ;

    return 0;
}

/*
 * Open a file: check for existence, permissions, and return success or
 * error. If you use file handles, set fi->fh. See fuse_common.h for more
 * information about fi fields.
 */
static int mefs_open(const char *path, struct fuse_file_info *fi)
{
    int i ;

    logger("mefs_open");
    if ((i=rootdir_find(path))<0) {
        return -ENOENT ;
    }
    return 0 ;
}

/*
 * Read size bytes from offset. Return number of read bytes, or 0 if offset
 * was at or beyond the end of the file.
 */
static int mefs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
    int i ;
    logger("mefs_read: %s off %d sz %d", path, (int)offset, (int)size);

    if ((i=rootdir_find(path))<0) {
        return -ENOENT;
    }
    if ((offset+size)>rootdir[i].sta.st_size) {
        size = rootdir[i].sta.st_size - offset ;
        /* logger("read reduced to %d", (int)size); */
    }
    memcpy(buf, rootdir[i].data+offset, size);
    return size ;
}

/*
 * Same as read, but cannot return 0
 */
static int mefs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    int i ;
    time_t now ;
    uint8_t * newbuf ;
    size_t newsz ;

    logger("mefs_write: %s off %d sz %d", path, (int)offset, (int)size);
    i = rootdir_find(path);
    if (i<0) {
        /* Create new file */
        i = rootdir_first();
        if (i<0) {
            /* No more file slots available */
            return -ENOSPC ;
        }
        rootdir[i].name = strdup(path);
        rootdir[0].sta.st_mode = S_IFREG | 0600 ;
        rootdir[0].sta.st_ino = inode_next() ;
        rootdir[0].sta.st_uid  = getuid() ;
        rootdir[0].sta.st_gid  = getgid() ;
        rootdir[0].sta.st_nlink = 1 ;
        time(&now);
        rootdir[0].sta.st_mtime = now ;
        rootdir[0].sta.st_ctime = now ;

        newsz = offset + size ;
        rootdir[0].sta.st_size = newsz ;
        rootdir[0].sta.st_blocks = 1 + newsz / BLOCKSZ ;
        rootdir[0].data = calloc(newsz, sizeof(uint8_t));
        memcpy(rootdir[0].data + offset, buf, size);
    } else {
        newsz = offset + size ;
        /* Modify existing file */
        if (newsz > rootdir[i].sta.st_size) {
            /* Grow existing file */
            newbuf = calloc(newsz, sizeof(uint8_t));
            /* Copy previous contents */
            if (rootdir[i].sta.st_size > 0 ) {
                memcpy(newbuf, rootdir[i].data, offset);
                free(rootdir[i].data);
            }
            memcpy(newbuf+offset, buf, size);
            rootdir[i].data = newbuf ;
        } else {
            /* Write into existing file */
            memcpy(rootdir[i].data+offset, buf, size);
        }
        rootdir[i].sta.st_size = newsz ;
        rootdir[i].sta.st_blocks = 1 + newsz / BLOCKSZ ;
        time(&now);
        rootdir[0].sta.st_mtime = now ;
    }
	return size;
}
/*
 * Returns statistics about the filesystem. See statvfs(2)
 * You can ignore path
 */
static int mefs_statfs(const char *path, struct statvfs *sfs)
{
    int i ;
    int n=0 ;
    size_t  total_sz=0 ;

    for (i=0 ; i<MAXFILES ; i++) {
        if (rootdir[i].name!=NULL) {
            n++ ;
            total_sz += rootdir[i].sta.st_size ;
        }
    }
    
    logger("mefs_statfs");
    sfs->f_bsize  = 4096 ;
    sfs->f_blocks = total_sz / sfs->f_bsize ;
    sfs->f_bfree  = 0 ;
    sfs->f_bavail = 0 ;
    sfs->f_files  = n ;
    sfs->f_ffree  = MAXFILES-n ;

	return 0;
}

/*
 * Link to the FUSE API
 */
static struct fuse_operations mefs_oper = {
    .init       = mefs_init,
    .destroy    = mefs_destroy,
	.getattr	= mefs_getattr,
	.readdir	= mefs_readdir,
	.unlink		= mefs_unlink,
    .utimens    = mefs_utimens,
	.rename		= mefs_rename,
	.truncate	= mefs_truncate,
    .create     = mefs_create,
	.open		= mefs_open,
	.read		= mefs_read,
	.write		= mefs_write,
	.statfs		= mefs_statfs,
};

/*
 * Free all remaining memory pointers
 */
void cleanup(void)
{
    int i ;

    for (i=0 ; i<MAXFILES ; i++) {
        if (rootdir[i].name!=NULL)
            free(rootdir[i].name);
        if (rootdir[i].data!=NULL)
            free(rootdir[i].data);
    }
}

/*
 * ----- main()
 */
int main(int argc, char *argv[])
{
    char * wd ;
    char * password ;
    int    i ;
    struct fuse_args args = FUSE_ARGS_INIT(0, 0);

    if (argc<3) {
        printf("use: %s [fuseoptions] mountpoint container\n", argv[0]);
        return 1 ;
    }
    config.err=0 ;
    /* Grab container name */
    wd = getcwd(NULL, 0);
    sprintf(config.backup_filename, "%s/%s", wd, argv[argc-1]);
    free(wd);
    argc-- ;

    /* Force -s (single-threaded) and -f (foreground) for FUSE */
    fuse_opt_add_arg(&args, "-s");
    fuse_opt_add_arg(&args, "-f");
    /* Register arguments for fuse_main */
    for (i=1 ; i<argc ; i++) {
        fuse_opt_add_arg(&args, argv[i]);
    }
    fuse_opt_parse(&args, NULL, NULL, NULL);

    /* Register cleanup function upon exit */
    atexit(cleanup);

    /* Read password */
    config.password = getpass("Password: ");

    /* Start FUSE */
	return fuse_main(args.argc, args.argv, &mefs_oper, NULL);
}
/* vim: set ts=4 et sw=4 tw=75 */
