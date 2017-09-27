CC		= gcc
LD		= gcc
OPT 	= -O2 -s 
CFLAGS 	= -D_POSIX_SOURCE -D_GNU_SOURCE $(OPT) -c -std=c11 -maes -DWITH_AESNI
LDFLAGS	= -DPTW32_STATIC_LIB $(OPT)
LIBS	= -ljansson -lOpenCL -lpthread -ldl

all:
	$(CC) $(CFLAGS) crypto/aesb.c -o crypto/aesb.o
	$(CC) $(CFLAGS) crypto/aesb-x86-impl.c -o crypto/aesb-x86-impl.o
	$(CC) $(CFLAGS) crypto/c_blake256.c -o crypto/c_blake256.o
	$(CC) $(CFLAGS) crypto/c_groestl.c -o crypto/c_groestl.o
	$(CC) $(CFLAGS) crypto/c_keccak.c -o crypto/c_keccak.o
	$(CC) $(CFLAGS) crypto/c_jh.c -o crypto/c_jh.o
	$(CC) $(CFLAGS) crypto/c_skein.c -o crypto/c_skein.o
	$(CC) $(CFLAGS) crypto/oaes_lib.c -o crypto/oaes_lib.o
	$(CC) $(CFLAGS) cryptonight.c -o cryptonight.o
	$(CC) $(CFLAGS) log.c -o log.o
	$(CC) $(CFLAGS) net.c -o net.o
	$(CC) $(CFLAGS) minerutils.c -o minerutils.o
	$(CC) $(CFLAGS) gpu.c -o gpu.o
	$(CC) $(CFLAGS) main.c -o main.o
	$(LD) $(LDFLAGS) crypto/aesb.o crypto/aesb-x86-impl.o crypto/c_blake256.o crypto/c_groestl.o crypto/c_keccak.o crypto/c_jh.o crypto/c_skein.o crypto/oaes_lib.o cryptonight.o log.o net.o minerutils.o gpu.o main.o $(LIBS) -o miner

clean:
	rm -f *.o crypto/*.o miner
