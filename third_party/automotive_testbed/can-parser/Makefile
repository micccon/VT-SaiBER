# CAN Frame Parser Makefile
CC = gcc
CFLAGS_COMMON = -Wall -Wextra -I.
CFLAGS_DEBUG = $(CFLAGS_COMMON) -g -DDEBUG
CFLAGS_VULN = $(CFLAGS_COMMON) -fno-stack-protector -z execstack -no-pie

# Source files
SRCS = can_frame_parser.c
OBJS = $(SRCS:.c=.o)
TARGET = can_frame_parser

# Default target - build vulnerable version for pentesting
all: CFLAGS = $(CFLAGS_VULN)
all: $(TARGET)

# Debug build with symbols and debug output
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: clean $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean debug
