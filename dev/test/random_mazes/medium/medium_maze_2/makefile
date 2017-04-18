smart: program.out
	 python -m opensaw -c -i initial.in -- program.out {}

fuzz: program.out
	python -m opensaw -c -s z program.out -i initial.in

test: program.out
	 python -m opensaw -c -i initial.in -- program.out {}

program.out: program.cpp
	g++ -Wall -Wextra program.cpp -o program.out
clean:
	rm *.out
	rm -rf opensaw_dir/
