all: run

clear:
	@clear

compile: clear
	@g++ -std=c++20 -O3 -w -Wall -Wextra -Werror -Wshadow -Wpedantic -pedantic -pedantic-errors vmtest.cpp -o vm

run: compile
	./vm
	@echo "" 