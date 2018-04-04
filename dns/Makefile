TARGET=sdns

OBJS=smart_dns.o debug.o str.o

CC=gcc

CFLAGS=-Wall
LDFLAGS=-Wall

$(TARGET):$(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rfv $(TARGET)
	find . -name "*.o" | xargs rm -rfv
