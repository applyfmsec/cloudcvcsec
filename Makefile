build-core:
	docker build -t applyfmsec/cloudcvcsec .

build-tests: build-core
	docker build -t applyfmsec/cloudcvcsec-tests-cvc -f Dockerfile-tests-cvc .

build: build-core build-tests

test: build
	docker run --rm -it applyfmsec/cloudcvcsec-tests-cvc