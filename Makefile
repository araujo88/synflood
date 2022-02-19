CC=gcc
CFLAGS=-g -Wall
CCLIBS=-lpthread
BINS=synflood

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(CCLIBS)

clean:
	rm -rf *.dSYM $(BINS)
