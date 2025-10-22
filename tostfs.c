#define FUSE_USE_VERSION 26
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include "tosfs.h"
#define FS_FILENAME "test_tosfs_files"
#define FS_SIZE (32 * TOSFS_BLOCK_SIZE)

static struct tosfs_superblock *sb;
static struct tosfs_inode *inodes;
static struct tosfs_dentry *root;

static void tosfs_load_fs(void) {
    int fd;
    void *fs_addr;

    fd = open(FS_FILENAME, O_RDONLY);
    if (fd < 0) {
        perror("Erreur d’ouverture du fichier système");
        exit(EXIT_FAILURE);
    }

    fs_addr = mmap(NULL, FS_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fs_addr == MAP_FAILED) {
        perror("Erreur mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }

    sb = (struct tosfs_superblock *) fs_addr;
    inodes = (struct tosfs_inode *) ((char *) fs_addr + TOSFS_BLOCK_SIZE);
    root = (struct tosfs_dentry *) ((char *) fs_addr + 2 * TOSFS_BLOCK_SIZE);


    printf("===== SUPERBLOCK =====\n");
    printf("Magic number     : 0x%x\n", sb->magic);
    printf("Bitmap blocs     : "PRINTF_BINARY_PATTERN_INT32"\n", PRINTF_BYTE_TO_BINARY_INT32(sb->block_bitmap));
    printf("Bitmap inodes    : "PRINTF_BINARY_PATTERN_INT32"\n", PRINTF_BYTE_TO_BINARY_INT32(sb->inode_bitmap));
    printf("Taille des blocs : %u\n", sb->block_size);
    printf("Nombre de blocs  : %u\n", sb->blocks);
    printf("Nombre d’inodes  : %u\n", sb->inodes);
    printf("Inode racine     : %u\n\n", sb->root_inode);

    printf("===== TABLE DES INODES =====\n");
    for (int i = 0; i < sb->inodes; i++) {
        struct tosfs_inode *ino = &inodes[i];
        if (ino->inode == 0) continue;
        printf("Inode %d :\n", ino->inode);
        printf(" - Bloc de données : %d\n", ino->block_no);
        printf(" - UID/GID : %d/%d\n", ino->uid, ino->gid);
        printf(" - Mode     : %d\n", ino->mode);
        printf(" - Permissions : %o\n", ino->perm);
        printf(" - Taille   : %d octets\n", ino->size);
        printf(" - Liens    : %d\n\n", ino->nlink);
    }

    printf("===== RÉPERTOIRE RACINE =====\n");
    struct tosfs_dentry *entry = root;
    for (int i = 0; i < 32; i++) {
        if (entry->inode == 0) break;
        printf(" - %s (inode %u)\n", entry->name, entry->inode);
        entry++;
    }
}

static int tosfs_stat(fuse_ino_t ino, struct stat *stbuf) {
    if (ino == FUSE_ROOT_ID) {
        stbuf->st_ino = ino;
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_size = TOSFS_BLOCK_SIZE;
        return 0;
    }
    size_t idx = ino - 2;
    if (sb == NULL) {
        return -1;
    }
    if (idx < sb->inodes) {
        struct tosfs_inode *inode = &inodes[idx];
        if (inode->inode != 0) {
            stbuf->st_ino = ino;
            stbuf->st_mode = S_IFREG | inode->perm;
            stbuf->st_nlink = inode->nlink;
            stbuf->st_size = inode->size;
            stbuf->st_uid = inode->uid;
            stbuf->st_gid = inode->gid;
            return 0;
        }
    }

    return -1;
}

static void tosfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    if (tosfs_stat(ino, &stbuf) == -1)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, 1.0);
}

static void tosfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) req;
    (void) ino;
    (void) size;
    (void) off;
    (void) fi;
}

static void tosfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    (void) req;
    (void) parent;
    (void) name;
}

static void tosfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) req;
    (void) ino;
    (void) size;
    (void) off;
    (void) fi;
}

static void tosfs_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    (void) req;
    (void) parent;
    (void) name;
    (void) mode;
    (void) fi;
}

static void tosfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                        struct fuse_file_info *fi) {
    (void) req;
    (void) ino;
    (void) buf;
    (void) size;
    (void) off;
    (void) fi;
}

static const struct fuse_lowlevel_ops tosfs_ops = {
    .getattr = tosfs_getattr,
    .readdir = tosfs_readdir,
    .lookup = tosfs_lookup,
    .read = tosfs_read,
    .create = tosfs_create,
    .write = tosfs_write
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_chan *ch;
    char *mountpoint;
    int err = -1;

    tosfs_load_fs();

    if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
        (ch = fuse_mount(mountpoint, &args)) != NULL) {
        struct fuse_session *se;

        se = fuse_lowlevel_new(&args, &tosfs_ops, sizeof(tosfs_ops), NULL);
        if (se != NULL) {
            if (fuse_set_signal_handlers(se) != -1) {
                fuse_session_add_chan(se, ch);
                err = fuse_session_loop(se);
                fuse_remove_signal_handlers(se);
                fuse_session_remove_chan(ch);
            }
            fuse_session_destroy(se);
        }
        fuse_unmount(mountpoint, ch);
    }

    fuse_opt_free_args(&args);
    return err ? 1 : 0;
}
