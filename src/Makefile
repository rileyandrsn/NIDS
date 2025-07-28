# Compiler & Flags
CC = gcc # Use gcc compiler
CFLAGS = -Wall -g # Enable all warnings and include debug info

TARGET = main # Variable - name of final executable

all: $(TARGET) # Default target to build executable

# Rule to build the final executable from object files
$(TARGET): main.o  # Link object files into the executable
	$(CC) $(CFLAGS) -o $(TARGET) main.o

# Rule to compile main.c into an object file
main.o: main.c     # Compile main.c into main.o
	$(CC) $(CFLAGS) -c main.c

# Rule to clean the build (remove generated files)
clean: # Clean up build artifacts
	rm -f *.o $(TARGET)