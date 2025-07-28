# Compiler & Flags
CC = gcc # Use gcc compiler
CFLAGS = -Wall -g -libpcap # Enable all warnings and include debug info

TARGET = main # Variable - name of final executable

all: $(TARGET) # Default target to build executable

# Rule to build the final executable from object files
$(TARGET): main.o  # Link object files into the executable
	$(CC) $(CFLAGS) -o $(TARGET) main.o

main.o: main.c     #  main.c -> main.o
	$(CC) $(CFLAGS) -c main.c

# Rule to clean build
clean: # Clean up build
	rm -f *.o $(TARGET)