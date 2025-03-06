CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g

SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:%.c=%.o)
TARGET = c_decoder

.PHONY = clean

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@

clean:
	rm $(TARGET)
