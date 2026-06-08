CFLAGS += -Wall
LDLIBS += -lpcap

all: tls-block

tls-block: main.c
	gcc $(CFLAGS) -o tls-block main.c $(LDLIBS)

clean:
	rm -f tls-block *.o
