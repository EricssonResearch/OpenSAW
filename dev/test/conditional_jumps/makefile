
test: program.out
	python -m opensaw -c -i initial.in -- program.out {}

asm.o: asm.S
	gcc asm.S -c -o asm.o

program.out: program.c asm.o
	gcc -Wall -Wextra program.c asm.o -o program.out

clean:
	rm *.out
	rm -rf opensaw_dir/
