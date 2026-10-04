CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic

cryptor: cryptor.cc
	$(CXX) $(CXXFLAGS) cryptor.cc -o cryptor

.PHONY: clean
clean:
	rm -f cryptor
