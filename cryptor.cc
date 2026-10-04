#include <iostream>
#include <fstream>
#include <filesystem>

using namespace std;

void encrypt(istream& f, ostream& o, const string& key){
	char c; // input file char
	int i = 0; // key index
	int m = key.size(); // mod
	f >> noskipws;
	while (f >> c){
		o.put(static_cast<char>(c^key[i++ % m]));
	}
}

int main(int argc, char* argv[]) {
	if (argc == 4){
		filesystem::path input_path {argv[1]};
		filesystem::path output_path {argv[2]};
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

		string key = argv[3];
		encrypt(f,o,key);

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
