CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic

SOURCE := src/cryptor.cc
HELPERS := src/atomic_output.cc src/secure_memory.cc src/terminal_io.cc src/console.cc src/password_input.cc

cryptor: $(SOURCE) $(HELPERS)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o cryptor -lsodium

.PHONY: clean test

test: cryptor
	bash tests/integration.sh ./cryptor

clean:
	rm -f cryptor
