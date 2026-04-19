CC = cc
CFLAGS = -O3 -Wall -Wextra
OPENSSL_FLAGS = $(shell pkg-config --cflags --libs openssl)
BLAKE3_FLAGS = $(shell pkg-config --cflags --libs libblake3)

all: de_bench

de_bench: dimensional_encryption.c
	$(CC) $(CFLAGS) -o de_bench dimensional_encryption.c $(OPENSSL_FLAGS) $(BLAKE3_FLAGS)

clean:
	rm -f de_bench

.PHONY: all clean
