CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wpedantic -O2 -pthread -std=gnu11
LDFLAGS = -pthread

all: test_wheel_timer

wheel_timer.o: wheel_timer.c wheel_timer.h list.h
	$(CC) $(CFLAGS) -c wheel_timer.c -o wheel_timer.o

test_wheel_timer.o: test_wheel_timer.c wheel_timer.h
	$(CC) $(CFLAGS) -c test_wheel_timer.c -o test_wheel_timer.o

test_wheel_timer: test_wheel_timer.o wheel_timer.o
	$(CC) $(LDFLAGS) test_wheel_timer.o wheel_timer.o -o test_wheel_timer

clean:
	rm -f *.o test_wheel_timer

test: all
	./test_wheel_timer

.PHONY: all clean test
