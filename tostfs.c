#define FUSE_USE_VERSION 26
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "tosfs.h"
#define FS_FILENAME "test_tosfs_files"
#define FS_SIZE (32 * TOSFS_BLOCK_SIZE)
#define min(x, y) ((x) < (y) ? (x) : (y))

struct dirbuf {
    char *p;
    size_t size;
};

static struct tosfs_superblock *sb;
static struct tosfs_inode *inodes;
static struct tosfs_dentry *root;

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
                       fuse_ino_t ino) {
    struct stat stbuf;
    size_t oldsize = b->size;
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;

    size_t entry_len = fuse_add_direntry(req, NULL, 0, name, &stbuf, 0);

    char *newp = realloc(b->p, b->size + entry_len);
    if (newp == NULL) {
        return;
    }
    b->p = newp;

    fuse_add_direntry(req, b->p + oldsize, entry_len, name, &stbuf,
                      (off_t) (oldsize + entry_len));

    b->size += entry_len;
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize) {
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}


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

static void tosfs_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    (void) mask;
    struct stat st;
    if (tosfs_stat(ino, &st) == -1)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_err(req, 0);
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
    (void) fi;

    if (ino != FUSE_ROOT_ID) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    struct dirbuf b;
    b.p = NULL;
    b.size = 0;

    dirbuf_add(req, &b, ".", FUSE_ROOT_ID);
    dirbuf_add(req, &b, "..", FUSE_ROOT_ID);

    if (sb != NULL && root != NULL) {
        size_t max_dentries = TOSFS_BLOCK_SIZE / sizeof(struct tosfs_dentry);
        for (size_t i = 0; i < max_dentries; i++) {
            if (root[i].inode == 0)
                continue;
            if (strcmp(root[i].name, ".") == 0 || strcmp(root[i].name, "..") == 0)
                continue;
            fuse_ino_t entry_ino = root[i].inode + 1;
            dirbuf_add(req, &b, root[i].name, entry_ino);
        }
    }

    reply_buf_limited(req, b.p, b.size, off, size);
    free(b.p);
}

static void tosfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    if (parent != FUSE_ROOT_ID) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (sb == NULL || root == NULL) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    size_t max_dentries = TOSFS_BLOCK_SIZE / sizeof(struct tosfs_dentry);
    for (size_t i = 0; i < max_dentries; i++) {
        if (root[i].inode == 0)
            continue;

        if (strcmp(root[i].name, name) == 0) {
            struct fuse_entry_param e;
            memset(&e, 0, sizeof(e));

            e.ino = (fuse_ino_t) (root[i].inode + 1);
            e.entry_timeout = 1.0;
            e.attr_timeout = 1.0;

            if (tosfs_stat(e.ino, &e.attr) == -1) {
                fuse_reply_err(req, ENOENT);
                return;
            }

            printf("lookup: found %s (inode %d → fuse ino %lu)\n",
                   root[i].name, root[i].inode, (unsigned long) e.ino);

            fuse_reply_entry(req, &e);
            return;
        }
    }
    printf("lookup: %s not found\n", name);
    fuse_reply_err(req, ENOENT);
}

static void tosfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    if (ino == FUSE_ROOT_ID) {
        fuse_reply_err(req, EISDIR);
        return;
    }
    struct tosfs_inode *inode = &inodes[ino - 2];
    if (inode->inode == 0) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    char *data_block = (char *) sb + (inode->block_no * TOSFS_BLOCK_SIZE);

    if (off >= inode->size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    if (off + size > inode->size)
        size = inode->size - off;

    fuse_reply_buf(req, data_block + off, size);
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
    .write = tosfs_write,
    .access = tosfs_access
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
