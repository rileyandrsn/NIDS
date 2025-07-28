# Compiler & Flags
CC = gcc # Use gcc compiler
CFLAGS = -Wall -g # Enable all warnings and include debug info
LDFLAGS = -lpcap # Linker flags: include libpcap
TARGET = OSNIDS # Variable - name of final executable

all: $(TARGET) # Default target to build executable

# Rule to build the final executable from object files
$(TARGET): main.o sniffer.o  # Link object files into the executable
	$(CC) $(CFLAGS) -o $(TARGET) main.o sniffer.o $(LDFLAGS)

main.o: main.c     
	$(CC) $(CFLAGS) -c main.c 
sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c

# Rule to clean build
clean: # Clean up build
	rm -f *.o $(TARGET)