
myhash: myhash.cpp
	mpicxx -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto myhash.cpp -Ddebug_myhash -o myhash

rel: myhash.cpp
	mpicxx -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto myhash.cpp -o myhash

generate: generate.cpp
	g++ -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto generate.cpp -o generate

baseline: baseline.cpp
	mpicxx -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto baseline.cpp -o baseline

baseline_debug: baseline.cpp
	mpicxx -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto baseline.cpp -DDEBUG -o baseline

test_block:
	g++ -O3 -L/lustre/toolchain/openssl/lib64/ -lcrypto test_sha512block.cpp -o test_sha512block

clean:
	rm generate baseline