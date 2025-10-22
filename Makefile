SRC = $(wildcard *.c)
BIN = $(patsubst %.c,%,$(SRC))

CFLAGS += -Wall -Wextra -g
#CFLAGS += --std=c99

all: $(BIN)

clean:
	rm -f $(BIN)
	rm -f *.o
	rm -f *~

indent:
	indent -linux -i4 -nut -ts2 *.c

.PHONY: all clean indent

run:
	gcc -Wall -D_FILE_OFFSET_BITS=64 tostfs.c `pkg-config fuse --cflags --libs` -o tostfs_fuse
	mkdir -p /tmp/tosfs
	./tostfs_fuse /tmp/tosfs -d

stop:
	fusermount -u /tmp/tosfs