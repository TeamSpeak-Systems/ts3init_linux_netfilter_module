CC      = gcc
CFLAGS  = -g
RM      = rm -f


default: all

all: test_siphash

%_test.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

test_siphash: test_siphash_test.o siphash24_ref_test.o ../src/siphash24_test.o
	$(CC) $(CFLAGS) -o $@ $^

clean veryclean:
	$(RM) test_siphash *.o ../src/siphash24_test.o

