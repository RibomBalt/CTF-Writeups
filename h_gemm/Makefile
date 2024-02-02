all: baseline quick

baseline: baseline.cpp
	g++ -O3 -fopenmp -mavx512f baseline.cpp -o baseline
quick: quick.cpp
	g++ -O3 -fopenmp -mavx512f quick.cpp -o quick

clean:
	rm baseline quick