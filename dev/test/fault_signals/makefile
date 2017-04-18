
test: program.out
	python -m opensaw -i initial.in -- program.out {}

program.out: program.c
	gcc -Wall -Wextra program.c -o program.out

pin: program.out
	pin -injection child \
		-t /opt/bap-0.7/pintraces/obj-ia32/gentrace.so \
		-- ./program.out initial.in
