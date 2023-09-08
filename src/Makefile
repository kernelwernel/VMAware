all: run

clear:
	@clear

compile: clear
	@clang++ -std=c++20 -O0 -w -Wall -Wextra -Werror -Wshadow -Wpedantic -pedantic -pedantic-errors vmtest.cpp -o vm

run: compile
	./vm
	@echo "" 