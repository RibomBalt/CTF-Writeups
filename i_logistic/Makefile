all: mp_log.cpp
	g++ -g -fopenmp -mavx512f mp_log.cpp -o mp_log

baseline: baseline.cpp
	g++ -O3 -fopenmp -mavx512f baseline.cpp -o baseline