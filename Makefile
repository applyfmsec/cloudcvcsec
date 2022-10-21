build-core:
	docker build -t applyfmsec/cloudcvcsec .

build-tests: build-core
	docker build -t applyfmsec/cloudcvcsec-tests-cvc -f Dockerfile-tests-cvc .

build-perf: build-tests
	docker build -t applyfmsec/cloudcvcsec-perf-cvc -f Dockerfile-perf-cvc .

build: build-core build-tests build-perf

test: build
	docker run --rm -it applyfmsec/cloudcvcsec-tests-cvc

