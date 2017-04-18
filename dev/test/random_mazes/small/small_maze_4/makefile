test: program.out
	 python -m opensaw -c -i initial.in -- program.out {}

program.out: program.cpp
	g++ -Wall -Wextra program.cpp -o program.out
clean:
	rm *.out
	rm -rf opensaw_dir/
