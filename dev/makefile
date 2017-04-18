## OpenSAW makefile

# Run development-tests while developing, to ensure
# that code changes don't break code.
development-tests:
	python2.7 /usr/bin/py.test -f opensaw/

# Run one-off unit tests to check that the current
# state of the source tree isn't broken.
unit-tests:
	python2.7 /usr/bin/py.test \
		-vv \
		opensaw/

# Run one-off unit tests and generate a coverage
# report in the coverage/ directory.
test-coverage:
	python2.7 /usr/bin/py.test --cov opensaw \
		--cov-config coverage_config \
		--cov-report html \
		opensaw/

# Generate documentation into the documentation/ folder.
docs:
	pycco -p -d documentation \
		opensaw/**/**/*.py opensaw/**/*.py opensaw/*.py
	echo "code { font-size: 12px; }" >> documentation/pycco.css

# Copy an updated gentrace.cpp file to the pintraces
# directory and build the updated version.
gentrace: opensaw/gentrace.cpp
	cp opensaw/gentrace.cpp /opt/bap-0.7/pintraces/.
	cd /opt/bap-0.7/pintraces/ && \
		make obj-ia32/gentrace.o && \
		make obj-ia32/gentrace.so
