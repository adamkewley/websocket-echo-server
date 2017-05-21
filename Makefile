bin:
	mkdir bin

bin/main: main.c base64.c | bin
	gcc $^ -lhttp_parser -lssl -lcrypto -o $@

.PHONY: all

all: bin/main
