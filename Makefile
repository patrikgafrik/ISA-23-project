CC = g++
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lstdc++ -lresolv

TARGET = dns
SRCS = dns.cpp

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

test:
	python3 tester.py

clean:
	rm -f $(TARGET)
