CC = gcc
CFLAGS = -Wall -fPIC -shared
TARGET = libsyscall_scanner.so
SOURCES = syscall_scanner.c pmparser.c

all: $(TARGET)

$(TARGET): $(SOURCES) pmparser.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

test:  $(TARGET)
	@echo "Testing with /bin/ls..."
	LD_PRELOAD=./$(TARGET) /bin/ls

.PHONY: all clean test
