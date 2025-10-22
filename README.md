To launch the project you need to 
- run this command !
``` bash
gcc -Wall -D_FILE_OFFSET_BITS=64 tostfs.c `pkg-config fuse --cflags --libs` -o tostfs_fuse
```
- create     the temporary repository
``` bash
mkdir -p /tmp/tosfs
```

- Mount the filesystem
``` bash
./tostfs_fuse /tmp/tosfs -d
```

- To unmount the filesystem use this command
``` bash
fusermount -u /tmp/tosfs
```