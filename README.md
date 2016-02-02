mefs
====

Memory-based Encrypted FileSystem

This program implements a minimal in-memory filesystem with encrypted
serialization. Data are decrypted in memory and encrypted when written back
to disk.

# Usage

This is a FUSE-based utility. All default FUSE options apply.
mefs expects the name of a directory to mount the virtual filesystem, and
the name of a file used to serialize the filesystem. If the serialization
file does not exist, it is created upon first start. Example:

    # Start this in a terminal
    mkdir mnt
    ./mefs mnt dump
    Password: 
    2016-02-02 10:06:35 memfs_init
    2016-02-02 10:06:35 no such file: /home/nico/dev/fuse/mefs/dump

    # Copy a file into mnt, e.g. from another terminal
    2016-02-02 10:07:44 memfs_getattr: /
    2016-02-02 10:07:51 memfs_getattr: /test
    2016-02-02 10:07:51 memfs_create /test
    2016-02-02 10:07:51 memfs_getattr: /test
    2016-02-02 10:07:54 memfs_write: /test off 0 sz 16

    # Stop mefs
    ^C2016-02-02 10:08:18 memfs_destroy

Your data are now encrypted in 'dump'.

mefs only support a single directory level (/) and no sub-directories.
It is useful to store a bunch of text files and other credentials.


# Scratch that itch

## Aim

The itch I needed to scratch is: find a way to store all the secrets I am
supposed to remember into a single place. There are already countless
solutions to this issue. My requirements are:

- Open-source
- Based on sound cryptographic primitives, i.e. not openssl
- Secrets must be stored in a single-file container: easily replicated
- Container must be mountable on POSIX systems. Once mounted, the container
  is seen as a regular filesystem containing directories and files.
- Container must be password-protected, with correct password hashing to
  thwart offline attacks.
- Must work at least on Linux and OSX


## Existing solutions

Truecrypt solves all above requirements and more.
This is my attempt at solving just my needs.


# Implementation

## Mounting a filesystem

The only viable option today for a portable way to mount filesystems in
userspace is FUSE. Unfortunately, this leaves Windows out of the equation,
but it would certainly have been a nice-to-have.

This implementation is terribly restricted in this version, as it does not
support directories and has a limit on the number of files you can store,
but should be more than enough to store a few password files in raw text.

## Implementing crypto

Very few cryptographic primitives are needed in order to implement
data-at-rest encryption. Choices made:

- *PBKDF2* with *HMAC-SHA256* to derive a key from a password.
  I picked SHA256 from a public domain implementation and rewrote the HMAC
  and PBKDF2 based on RFC indications. There are test vectors available for
  each part, compilable with 'make testing'.
- *salsa20* for stream encryption. This encryption algorithm was written by
  Dan Bernstein as an alternative to other stream ciphers like RC4.
  salsa20 is insanely fast and offers the interesting property that you can
  generate the pseudo-random stream at any offset without having to compute
  the fist N-1 bytes.

## Growing or fixed-size container

One way to achieve these requirements is to create a single-file container
on disk, and provide the layers to handle it as a virtual hard drive. This
would have forced me into writing a block-level handler like a true hard
drive and I did not feel this was needed.

My take is that any file is just one block, a pointer to contiguous raw
data, and an indication of size. The fact that salsa20 can encrypt directly
starting from an arbitrary offset certainly helps a lot in realizing this
abstraction.

Net effect: the container is read upon start, the in-memory filesystem is
re-created from its contents, and then data live their life in memory until
the filesystem is shut down, at which point the contents are dumped back,
overwriting the initial container. The filesystem grows in memory as files
are written into it. Fake data are returned in terms of block size and
number of free blocks to keep df happy.


# Improvements

There are many points worth improving:
- The whole container is decrypted upon startup. mefs should only
  decrypt contents when they are needed.
- Contents are never saved before the filesystem is shutdown. There should
  be intermediate checkpoints.


Nicolas314
