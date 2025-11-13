CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lpcap

all: deceptor

deceptor: deceptor.c
	$(CC) $(CFLAGS) deceptor.c -o deceptor $(LIBS)

clean:
	rm -f deceptor
