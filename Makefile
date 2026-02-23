all: libdummymutator.so
clean:
	rm -f libdummymutator.so

libdummymutator.so: mutator.c | AFLplusplus
	$(CC) $(CFLAGS) -O3 -fPIC -shared -g -I AFLplusplus/include $? -o $@

AFLplusplus:
	git clone https://github.com/AFLplusplus/AFLplusplus
