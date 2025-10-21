#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tosfs.h"

#define FS_FILENAME "../test_tosfs_files"
#define FS_SIZE (32 * TOSFS_BLOCK_SIZE)

void tosfs_load_fs(void) {
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

    struct tosfs_superblock *sb = (struct tosfs_superblock *) fs_addr;
    struct tosfs_inode *inodes = (struct tosfs_inode *) ((char *) fs_addr + TOSFS_BLOCK_SIZE);
    struct tosfs_dentry *root = (struct tosfs_dentry *) ((char *) fs_addr + 2 * TOSFS_BLOCK_SIZE);

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

    munmap(fs_addr, FS_SIZE);
    close(fd);

}

int main() {
    tosfs_load_fs();

    return 0;
}
