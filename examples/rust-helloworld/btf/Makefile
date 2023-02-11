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
	rm -rf event-def.o
	rm -rf event-def.wit
event-def.wit:
	gcc event-def.c -c -o event-def.o -g
	pahole -J event-def.o
	btf2wit event-def.o -o event-def.wit