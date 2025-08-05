# Compiler & Flags
CC = gcc # Use gcc compiler
CFLAGS = -Wall -g -I/opt/homebrew/include # Enable all warnings and include debug info
LDFLAGS = -lpcap -L/opt/homebrew/lib -ljson-c # Linker flags: include libpcap
TARGET = pinids # Variable - name of final executable

all: $(TARGET) # Default target to build executable

# Rule to build the final executable from object files
$(TARGET): main.o sniffer.o parser.o cli.o  # Link object files into the executable
	$(CC) $(CFLAGS) -o $(TARGET) main.o sniffer.o parser.o cli.o $(LDFLAGS)

main.o: main.c     
	$(CC) $(CFLAGS) -c main.c 
sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) -c sniffer.c
parser.o: parser.c parser.h
	$(CC) $(CFLAGS) -c parser.c
cli.o: cli.c cli.h
	$(CC) $(CFLAGS) -c cli.c
rules.o: rules.c rules.h
	$(CC) $(CFLAGS) -c rules.c

# Rule to clean build
clean: # Clean up build
	rm -f *.o $(TARGET)