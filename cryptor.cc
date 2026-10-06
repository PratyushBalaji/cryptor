#include <iostream>
#include <fstream>
#include <filesystem>

#include <array>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include <sodium.h> 	// encryption
#include <CLI/CLI.hpp>  // arg handling

using namespace std;

using Key = array<unsigned char, crypto_stream_xchacha20_KEYBYTES>;       // 32-byte key
using Salt = array<unsigned char, crypto_pwhash_SALTBYTES>;               // 16-byte salt
using Nonce = array<unsigned char, crypto_stream_xchacha20_NONCEBYTES>;   // 24-byte nonce

// secure format variables (safe mode)
using StreamHeader = array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>;
using SerialisedHeader = array<unsigned char, 64>; // 64-byte header / file signature

// header consists of : 	64-bytes
// "CRYPTOR"			7
// <version>			1
// <Argon2 ops limit> 		8
// <Argon2 mem limit>		8
// <random salt>		16
// <secretstream header> 	24

constexpr array<unsigned char, 7> FILE_SIG { // 7-byte magic
	'C','R','Y','P','T','O','R'
};
constexpr uint8_t FORMAT_VERSION = 0x01; // 1-byte version

constexpr uint32_t SAFE_CHUNK_SIZE = 64 * 1024;
constexpr size_t SECURE_HEADER_SIZE = 64;

constexpr Salt UNSAFE_SALT { // 16-byte hardcoded salt for simple involution / unsafe mode
	'c', 'r', 'y', 'p', 't', 'o', 'r', '-', 's', 'a', 'l', 't', '-', '1', '.', '0'
};

Key deriveKey(const string& password, const Salt& salt,
	      uint64_t operationsLimit=crypto_pwhash_OPSLIMIT_INTERACTIVE,
	      uint64_t memoryLimit=crypto_pwhash_MEMLIMIT_INTERACTIVE) {
    	Key key {};

    	int result = crypto_pwhash(
		key.data(), // raw array to contain key
	        key.size(), // 32 bytes
	        password.data(),
        	static_cast<unsigned long long>(password.size()),
	        salt.data(), // random salt (publicly stored)
	        operationsLimit,
	        memoryLimit,
		crypto_pwhash_ALG_ARGON2ID13 // argon2id algorithm for hashing
	);

	if (result != 0) {
    		throw runtime_error("Could not derive key");
	}

	return key;
}

void encryptUnsafe(istream& f, ostream& o, const string& password){
	constexpr size_t CHUNK_SIZE = 64 * 1024;   // buffer size
	constexpr uint64_t BLOCK_SIZE = 64;        // xchacha20 block size
	
	Key key = deriveKey(password, UNSAFE_SALT);
	Nonce nonce {}; // empty nonce (zeros) for unsafe involution mode
	
	array<unsigned char, CHUNK_SIZE> input {};
	array<unsigned char, CHUNK_SIZE> output {};
	uint64_t blockIndex = 0;

	while (f) {
		f.read(reinterpret_cast<char*>(input.data()), input.size()); // write f to buffer
		
		unsigned long long bytesRead = f.gcount();
		
		if (!bytesRead) break;
		
		crypto_stream_xchacha20_xor_ic( // use xor_ic() to specify counter (blockIndex)
			output.data(),
			input.data(),
			bytesRead,
			nonce.data(),
			blockIndex, // keystream idx inc'd as read to avoid repetition
			key.data()
		);

		o.write(reinterpret_cast<const char*>(output.data()), bytesRead); // write xor-ed data to o
		
		blockIndex += (bytesRead + BLOCK_SIZE - 1) / BLOCK_SIZE; // ++blockIndex depending on read bytes
	}

	sodium_memzero(key.data(), key.size()); // zero out key from ram
}

void encryptSafe(istream& f, ostream& o, const string& password) {
	uint64_t operationsLimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
	uint64_t memoryLimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
	
	Salt salt{};
	randombytes_buf(salt.data(), salt.size()); // random salt
	
	Key key = deriveKey(password, salt, operationsLimit, memoryLimit);
	crypto_secretstream_xchacha20poly1305_state state;
	StreamHeader streamHeader {};

	crypto_secretstream_xchacha20poly1305_init_push(&state, streamHeader.data(), key.data());
	
	// construct cryptor header
	SerialisedHeader header {};
	auto index = header.begin();

	index = copy(FILE_SIG.begin(), FILE_SIG.end(), index);
	*index++ = FORMAT_VERSION;
	for (int shift = 64; shift > 0;) *index++ = static_cast<unsigned char>(operationsLimit >> (shift -= 8));
	for (int shift = 64; shift > 0;) *index++ = static_cast<unsigned char>(memoryLimit >> (shift -= 8));
	index = copy(salt.begin(), salt.end(), index);
	index = copy(streamHeader.begin(), streamHeader.end(), index);

	if (index != header.end()) throw logic_error("Header size mismatch");

	o.write(reinterpret_cast<const char*>(header.data()), header.size()); // write 64-byte array
	
	// authenticated chunk encryption
	array<unsigned char, SAFE_CHUNK_SIZE> input {};
	array<unsigned char, SAFE_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES> output {};
	unsigned long long cipherLen {};
	bool isFinalChunk = false;

	while (f && !isFinalChunk) {
		f.read(reinterpret_cast<char*>(input.data()), input.size()); // write f to buffer
		if (f.bad() || (f.fail() && !f.eof())) throw runtime_error("Unable to read stream");

		unsigned long long bytesRead = f.gcount();
		
		isFinalChunk = f.eof() || (f.peek() == EOF);
		if (f.bad()) throw runtime_error("Bad stream");

		auto tag = isFinalChunk ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

		int pushFailed = crypto_secretstream_xchacha20poly1305_push(&state, output.data(), &cipherLen, input.data(), bytesRead, header.data(), header.size(), tag);
		if (pushFailed) throw runtime_error("Encryption failed");
		
		o.write(reinterpret_cast<const char*>(output.data()), cipherLen);
	}


	sodium_memzero(key.data(), key.size());
}

void decryptSafe(istream& f, ostream& o, const string& password) {
	// validate header
	SerialisedHeader header {};
	f.read(reinterpret_cast<char*>(header.data()), header.size()); // read 64-bytes of f into header
	
	auto ERR_invalidFile = [](string reason){
		return runtime_error("Error: invalid Cryptor safe encrypted file (" + reason + ").\nIf this file was encrypted in unsafe mode, retry with --unsafe.");
	};
	
	if (f.gcount() != 64) throw ERR_invalidFile("no header");

	auto idx = header.begin();

	// sig check
	if (!equal(FILE_SIG.begin(), FILE_SIG.end(), idx)) throw ERR_invalidFile("invalid signature");
	idx += 7;

	// schema version
	if (!(header[0x07] == FORMAT_VERSION)) throw ERR_invalidFile("unsupported version");
	idx += 1;

	// load ops limit
	unsigned long long operationsLimit = 0;
	for (int i = 0; i < 8; ++i){
		operationsLimit <<= 8; // shl one byte
		operationsLimit |= *idx;
		++idx;
	}

	// load mem limit
	unsigned long long memoryLimit = 0;
	for (int i = 0; i < 8; ++i){
		memoryLimit <<= 8; // shl one byte
		memoryLimit |= *idx;
		++idx;
	}

	// v1 : only accept hardcoded limits
	if ((operationsLimit != crypto_pwhash_OPSLIMIT_INTERACTIVE) || (memoryLimit != crypto_pwhash_MEMLIMIT_INTERACTIVE)) throw ERR_invalidFile("invalid argon2id params");

	// copy salt
	Salt salt{};
	copy(idx, idx+16, salt.begin());
	idx+=16;

	// copy argon header
	StreamHeader streamHeader{};
	copy(idx, idx+24, streamHeader.begin());
	idx+=24;

	if (idx != header.end()) throw logic_error("Header parsing mismatch");

	// run decryption
	Key key = deriveKey(password, salt, operationsLimit, memoryLimit);
	crypto_secretstream_xchacha20poly1305_state state;

	if (crypto_secretstream_xchacha20poly1305_init_pull(&state, streamHeader.data(), key.data())) throw ERR_invalidFile("invalid stream header");

	array<unsigned char, SAFE_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES> cipherText {};
	array<unsigned char, SAFE_CHUNK_SIZE> plainText {};
	unsigned long long plainLen {};
	bool authFinal = false;

	while (f && !authFinal) {
		f.read(reinterpret_cast<char*>(cipherText.data()), cipherText.size()); // write f to buffer
		if (f.bad() || (f.fail() && !f.eof())) throw runtime_error("Unable to read stream");

		unsigned long long bytesRead = f.gcount();
		if (bytesRead < crypto_secretstream_xchacha20poly1305_ABYTES) throw ERR_invalidFile("invalid authentication");
		
		bool atFileEnd = f.eof() || (f.peek() == EOF);
		if (f.bad()) throw runtime_error("Bad stream");

		unsigned char tag{};

		int pullFailed = crypto_secretstream_xchacha20poly1305_pull(&state, plainText.data(), &plainLen, &tag, cipherText.data(), bytesRead, header.data(), header.size());
		if (pullFailed) throw runtime_error("ERROR: decryption failed (wrong password or corrupted file)");
		
		if (tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) throw ERR_invalidFile("unsupported auth tag");

		authFinal = (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);

		if (authFinal && !atFileEnd) throw ERR_invalidFile("data exists after final chunk");
		if (!authFinal && atFileEnd) throw ERR_invalidFile("missing final chunk");

		o.write(reinterpret_cast<const char*>(plainText.data()), plainLen);

		if (!o) throw runtime_error("Unable to write decrypted file");
	}

	sodium_memzero(key.data(), key.size());
}

int main(int argc, char* argv[]) {
	// arg parser
	CLI::App app {"Cryptor file encryption"};
	
	string input;
	string output;
	string password;

	// op selection
	CLI::Option_group* operations = app.add_option_group("Operation");
	bool encryptRequested = false;
	bool decryptRequested = false;
	bool unsafeRequested = false;
	
	operations->add_flag("-e,--encrypt", encryptRequested, "Encrypt a file");
	operations->add_flag("-d,--decrypt", decryptRequested, "Decrypt a file");
	operations->add_flag("-u,--unsafe", unsafeRequested, "Use involutive file encryption (not as secure)");
	operations->require_option(1); // exactly one of -e, -d, -u is required

	// params
	app.add_option("input", input, "Input file")->required();
	app.add_option("output", output, "Output file")->required();
	app.add_option("password", password, "Encryption password")->required();

	CLI11_PARSE(app, argc, argv);

	// keygen dep check
	if (sodium_init() < 0) {
		cerr << "Error: could not initialize libsodium." << endl;
		return 1;
	}
	
	// pre-encryption validation
	filesystem::path input_path {input};
	filesystem::path output_path {output};
	
	if (password.empty()){
		cerr << "Error: password cannot be empty." << endl;
		return 1;
	}

	error_code path_error;
	bool same_file = filesystem::equivalent(input_path, output_path, path_error);
	bool same_path = filesystem::absolute(input_path).lexically_normal() == filesystem::absolute(output_path).lexically_normal();

	if (same_file || same_path){
		cerr << "Error: input and output must be different files." << endl;
		return 1;
	}

	ifstream f {input, ios::binary};
	if (!f.is_open()){
		cerr << "Error: could not open input file: " << input << endl;
		return 1;
	}

	ofstream o {output, ios::binary};
	if (!o.is_open()){
		cerr << "Error: could not open output file: " << output << endl;
		return 1;
	}

	// encryption
	try {
		if (encryptRequested) {
			encryptSafe(f,o,password);
		} else if (decryptRequested) {
			decryptSafe(f,o,password);
		} else {
			encryptUnsafe(f,o,password); // involutive so encryption == decryption
		}
	} catch (const exception& error) {
		cerr << error.what() << endl;
		return 1;
	}

	// post-encryption validation
	if (!f.eof()){
		cerr << "Error: failed while reading input file." << endl;
		return 1;
	}
	if (!o){
		cerr << "Error: failed while writing output file." << endl;
		return 1;
	}

	return 0;
}
