CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic

HELPERS := atomic_output.cc secure_memory.cc

cryptor: cryptor.cc $(HELPERS)
	$(CXX) $(CXXFLAGS) cryptor.cc -o cryptor -lsodium

.PHONY: clean
clean:
	rm -f cryptor
