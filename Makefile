build-core:
	docker build -t jstubbs/cloudz3sec .

build-tests: build-core
	docker build -t jstubbs/cloudz3sec-tests-cvc -f Dockerfile-tests-cvc .

build: build-core build-tests

test: build
	docker run --rm -it jstubbs/cloudz3sec-tests-cvc