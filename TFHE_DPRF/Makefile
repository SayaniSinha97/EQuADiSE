TFHE_PREFIX = /usr/local
TFHE_OPTIONS = C_INCLUDE_PATH=$$C_INCLUDE_PATH:${TFHE_PREFIX}/include CPLUS_INCLUDE_PATH=$$CPLUS_INCLUDE_PATH:${TFHE_PREFIX}/include LIBRARY_PATH=$$LIBRARY_PATH:${TFHE_PREFIX}/lib LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:${TFHE_PREFIX}/lib
TFHE_LIB = -ltfhe-spqlios-fma
# BLAS_LIB = -lopenblas

all: bin/ckt_dist_eval

bin/ckt_dist_eval: src/Ckt_dist_eval.cpp
	${TFHE_OPTIONS} g++ -g -fopenmp src/Ckt_dist_eval.cpp -o bin/ckt_dist_eval ${TFHE_LIB}

.PHONY: clean
clean:
	rm -rf bin/*
	touch bin/.gitkeep
	touch test/.gitkeep
	mkdir -p test/secret.key_shards
	touch test/secret.key_shards/,gitkeep
