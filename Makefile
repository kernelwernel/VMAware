all: run

clear:
	@clear

compile: clear
	@clang++ -std=c++20 -O0 -w -Wall -Wextra -Werror -Wshadow -Wpedantic -pedantic -pedantic-errors src/vmtest.cpp -o vm

run: compile
	./vm

clean:
	@rm -rf ./cli
	@rm -rf ./vm
	@rm -rf ./vmaware

cli:
	@clang++ -std=c++20 -O3 -Wall src/cli.cpp -o vmaware

install: cli
	@cp src/vmaware.hpp /usr/include/
	@chmod +x vmaware
	@mv vmaware /usr/bin/