#include <iostream>
#include <fstream>

using namespace std;

// void encrypt

int main(int argc, char* argv[]) {
	// Usage : ./cryptor <inputfile> <outputfile> 
	if (argc == 3){
		ifstream f {argv[1]};
		ofstream o {argv[2]};
		char c;
		f >> noskipws;
		while (f >> c){
			cout << hex << static_cast<int>(c);
			cout << (c == '\n' ? c : ' ');
			o << c;
		}
		cout << endl;
	} else {
		cout << "Usage : " << argv[0] << " <inputfile> <outputfile>" << endl;
	}
}
