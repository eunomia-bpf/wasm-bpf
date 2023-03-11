
DEL = rm -rf
FILES = $(shell ls *.bpf.o | awk '{split($$0,a,".");print a[1]}')

all: $(FILES)

$(FILES) : % : %.bpf.o
	$(DEL) $@.data.h
	touch $@.data.h
	echo "#ifndef _$@_H" >> $@.data.h
	echo "#define _$@_H" >> $@.data.h
	echo "const char* $@_data = \"$$(cat $< | base64 -w 0)\";" >> $@.data.h
	echo "#endif" >> $@.data.h

%.data.h : %

clean:
	$(DEL) *.data.h