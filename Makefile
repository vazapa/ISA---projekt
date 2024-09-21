CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lncurses
TARGET = isa-top
SRCS = isa-top.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)