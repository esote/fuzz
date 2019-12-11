CFLAGS=		-g -I.. -Wall -Wextra -Wconversion -Wundef
LDFLAGS=	-L.. -lfuzz -Wl,-rpath=..

SF=		sf
SF_SRCS=	sf.c

sf: $(SF_SRCS) ../libfuzz.so
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SF).out $(SF_SRCS)

EX=		ex
EX_SRCS=	ex.c

ex: $(EX_SRCS) ../libfuzz.so
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(EX).out $(EX_SRCS)

BENCH=		bench
BENCH_SRCS=	bench.c

bench: $(BENCH_SRCS) ../libfuzz.so
	$(CC) -O2 -Wall -I.. $(LDFLAGS) -o $(BENCH).out $(BENCH_SRCS)

clean:
	rm -f $(SF).out $(EX).out $(BENCH).out
