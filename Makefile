CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap -lncurses -pthread
TARGET = isa-top
SRCS = isa-top.c hashtable.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
