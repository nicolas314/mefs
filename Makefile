#
# Makefile
#

# Compiler settings
CC      = gcc
CFLAGS  = -D_FILE_OFFSET_BITS=64 -g -Isrc
LFLAGS  = -lfuse

default:	mefs

testing:    test_cipher test_hmac test_sha2

SRCS =  src/cipher.c src/hmac.c src/inode.c src/logger.c src/memfile.c \
        src/mefs.c src/sha2.c src/salsa20.c

mefs: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LFLAGS)

test_cipher: src/cipher.c src/salsa20.c src/sha2.c src/hmac.c \
             testing/test_cipher.c
	$(CC) $(CFLAGS) -o $@ $^

test_hmac: src/hmac.c src/sha2.c testing/test_hmac.c
	$(CC) $(CFLAGS) -o $@ $^

test_sha2: src/sha2.c testing/test_sha2.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f mefs test_cipher test_hmac test_sha2
