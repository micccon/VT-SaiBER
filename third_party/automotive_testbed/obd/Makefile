# Makefile for OBD-II Simulator Server
# Part of the Automotive Pentesting Testbed
#
# NOTE: This server is INTENTIONALLY compiled with vulnerable flags
# for educational purposes (V8 Buffer Overflow challenge)
#
# Security features disabled:
# - Stack protector disabled (-fno-stack-protector)
# - Executable stack enabled (-z execstack)
# - No ASLR mitigation (-no-pie)
# These allow exploitation of the buffer overflow in handle_vin_write()

CC = gcc
# Standard flags for warnings and debugging
CFLAGS = -Wall -Wextra -g
# VULNERABLE FLAGS: Disable security protections for educational exploitation
VULN_FLAGS = -fno-stack-protector -z execstack -no-pie
TARGET = obd_server
SRC = obd_server.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(VULN_FLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
