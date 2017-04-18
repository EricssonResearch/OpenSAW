
test: program.out
	python -m opensaw -c -i initial.in -- program.out {}

program.out: program.c
	gcc -Wall -Wextra program.c -o program.out

clean:
	rm *.out
	rm -rf opensaw_dir/
