CC=g++
CFLAGS=-Wall -I/usr/lib/sage/local/include/
LDFLAGS= -L/usr/lib/sage/local/lib/
SOURCES=client.cpp dmmt.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=test
LIBS=-lgcrypt -lntl

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(LIBS) $(OBJECTS) -o $@

.cc.o:
	$(CC) $(CFLAGS) -c $< -o $@



clean:
	rm -f *.o $(EXECUTABLE)
