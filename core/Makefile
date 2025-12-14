# Makefile for compiling Dilithium NTT C library

CC = gcc
CFLAGS = -O3 -Wall -Wextra -fPIC -march=native
LDFLAGS = -shared

TARGET = libdilithium_ntt.so
SRC = dilithium_ntt.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
