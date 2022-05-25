all:
	gcc -fPIC -Wall -o ec_lib.o -c ./encryption_lib.c
	ar rc libec_lib.a ec_lib.o
	gcc -shared -Wl,-soname,ec_lib.so -o ec_lib.so ec_lib.o
	gcc -I. -g -o a.out -c dr_showcase.c
	gcc a.out -Wl,--export-dynamic -Wall -pedantic -Werror -Wextra  -ldl -L. -lec_lib -o out.o

clean:
	rm *.a
	rm *.o
	rm *.so
	rm *.out