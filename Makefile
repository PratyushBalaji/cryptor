CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic

SOURCE := src/cryptor.cc
HELPERS := src/atomic_output.cc src/secure_memory.cc src/password_input.cc

cryptor: $(SOURCE) $(HELPERS)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o cryptor -lsodium

.PHONY: clean
clean:
	rm -f cryptor
