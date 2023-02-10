import.o: import.c
	gcc import.c -c -o import.o -g 
	pahole -J import.o

import.wit: import.o
	btf2wit import.o -o import.wit

host.rs: import.wit
	wit-bindgen import.wit
clean:
	rm -rf import.o
	rm -rf import.wit