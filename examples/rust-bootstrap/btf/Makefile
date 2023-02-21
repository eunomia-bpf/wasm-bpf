generate: install-deps import.wit
	clang -target bpf -g event-def.c -c -o event.def.o
	cargo install btf2wit
	btf2wit event.def.o -o event-def.wit --world-name event-def
	cp *.wit ../wit/

install-deps:
	cargo install btf2wit
	sudo apt install pahole

import.o: import.c
	gcc import.c -c -o import.o -g 
	pahole -J import.o

import.wit: import.o
	btf2wit import.o -o import.wit --world-name import
	
	# Currently, WIT doesn't support identifiers with two continuous `-`
	sed -i 's/--/s-/g' import.wit 

host.rs: import.wit
	wit-bindgen import.wit

clean:
	rm -rf *.o *.wit
