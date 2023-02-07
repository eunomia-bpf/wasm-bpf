generate:
	clang -target bpf -g event-def.c -c -o event.def.o
	cargo install btf2wit
	btf2wit event.def.o -o event-def.wit
	cp *.wit ../wit/

import.o: import.c
	gcc import.c -c -o import.o -g 
	pahole -J import.o

import.wit: import.o
	btf2wit import.o -o import.wit

host.rs: import.wit
	wit-bindgen import.wit

clean:
	rm -rf *.o *.wit
