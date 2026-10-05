#include <iostream>
#include <fstream>
#include <filesystem>

#include <array>
#include <stdexcept>
#include <cstdint>

#include <sodium.h>

using namespace std;

using Key = array<unsigned char, crypto_stream_xchacha20_KEYBYTES>; // 32-byte key
using Salt = array<unsigned char, crypto_pwhash_SALTBYTES>; // 16-byte salt
using Nonce = array<unsigned char, crypto_stream_xchacha20_NONCEBYTES>; // 24-byte nonce

constexpr Salt UNSAFE_SALT { // hardcoded salt for simple involution mode
	'c', 'r', 'y', 'p', 't', 'o', 'r', '-', 's', 'a', 'l', 't', '-', '1', '.', '0'
};

Key deriveKey(const string& password, const Salt& salt) {
    Key key {};

    int result = crypto_pwhash(
        key.data(), // raw array to contain key
        key.size(), // 32 bytes
        password.data(),
        static_cast<unsigned long long>(password.size()),
        salt.data(), // random salt (publicly stored)
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13 // argon2id algorithm
    );

    if (result != 0) {
        throw runtime_error("Could not derive key");
    }

    return key;
}

void encrypt(istream& f, ostream& o, const string& password){
	constexpr size_t CHUNK_SIZE = 64 * 1024; // buffer size
	constexpr uint64_t BLOCK_SIZE = 64; // xchacha20 block size
	
	Key key = deriveKey(password, UNSAFE_SALT);
	Nonce nonce {}; // initialise empty (zero) for unsafe involution mode
	
	array<unsigned char, CHUNK_SIZE> input {};
	array<unsigned char, CHUNK_SIZE> output {};
	uint64_t blockIndex = 0;

	while (f) {
		f.read(reinterpret_cast<char*>(input.data()), input.size()); // write f to buffer
		
		unsigned long long bytesRead = f.gcount();
		
		if (!bytesRead) break;
		
		crypto_stream_xchacha20_xor_ic( // use _ic() version to specify counter (blockIndex)
			output.data(),
			input.data(),
			bytesRead,
			nonce.data(),
			blockIndex, // keystream idx inc'd as read to avoid repetition
			key.data()
		);

		o.write(reinterpret_cast<const char*>(output.data()), bytesRead); // write xor-ed data to o
		
		blockIndex += (bytesRead + BLOCK_SIZE - 1) / BLOCK_SIZE; // inc blockIndex depending on read bytes
	}

	sodium_memzero(key.data(), key.size()); // zero out key from ram
}

int main(int argc, char* argv[]) {
	// keygen dep
	if (sodium_init() < 0) {
		cerr << "Error: could not initialize libsodium." << endl;
		return 1;
	}
	
	// argument and file validation + encryption
	if (argc == 4){
		filesystem::path input_path {argv[1]};
		filesystem::path output_path {argv[2]};
		
		string password = argv[3];
		if (password.empty()){
			cerr << "Error: password cannot be empty." << endl;
			return 1;
		}

		error_code path_error;
		bool same_file = filesystem::equivalent(input_path, output_path, path_error);
		bool same_path = filesystem::absolute(input_path).lexically_normal()
			== filesystem::absolute(output_path).lexically_normal();

		if (same_file || same_path){
			cerr << "Error: input and output must be different files." << endl;
			return 1;
		}

		ifstream f {argv[1], ios::binary};
		if (!f.is_open()){
			cerr << "Error: could not open input file: " << argv[1] << endl;
			return 1;
		}

		ofstream o {argv[2], ios::binary};
		if (!o.is_open()){
			cerr << "Error: could not open output file: " << argv[2] << endl;
			return 1;
		}

		encrypt(f,o,password);

		if (!f.eof()){
			cerr << "Error: failed while reading input file." << endl;
			return 1;
		}
		if (!o){
			cerr << "Error: failed while writing output file." << endl;
			return 1;
		}
	} else {
		cerr << "Usage : " << argv[0] << " <inputfile> <outputfile> <key>" << endl;
		return 1;
	}

	return 0;
}
