LIB=	fuzz
SRCS=	fuzz.c
OBJS=	fuzz.o

CFLAGS=		-Wall -O2 -fPIC
LDFLAGS=	-Wl,-z,now -Wl,-z,relro

$(LIB): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)
	$(CC) -shared $(LDFLAGS) -o lib$(LIB).so $(OBJS)

debug: $(SRCS)
	$(CC) -g -Wall -Wextra -Wconversion -Wundef -c $(SRCS)
	$(CC) -shared $(LDFLAGS) -o lib$(LIB).so $(OBJS)

clean:
	rm -f $(OBJS) lib$(LIB).so
