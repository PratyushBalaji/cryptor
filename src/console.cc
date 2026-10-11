#include <iostream>
#include <string>

using namespace std;

class Console {
	bool warningsEnabled;

	static bool asciiSpace(char character) {
		return character == ' ' || character == '\t' || character == '\r'
			|| character == '\n' || character == '\v' || character == '\f';
	}

public:
	explicit Console(bool enabled = true) : warningsEnabled(enabled) {}

	void warn(const string& message) const {
		if (warningsEnabled) cerr << "cryptor: warning: " << message << '\n';
	}

	void error(const string& message) const {
		cerr << "cryptor: error: " << message << '\n';
	}

	bool confirm(const string& message, bool defaultAnswer = false) const {
		cerr << "cryptor: warning: " << message << '\n';
		TerminalDescriptor terminal;
		while (true) {
			writeToTerminal(terminal.descriptor(), defaultAnswer ? "Continue? [Y/n]: " : "Continue? [y/N]: ");
			string response;
			while (true) {
				char character;
				ssize_t count = read(terminal.descriptor(), &character, 1);
				if (count < 0) {
					if (errno == EINTR) continue;
					throw system_error(errno, generic_category(), "unable to read confirmation");
				}
				if (count == 0) return false;
				if (character == '\n') break;
				response.push_back(character);
			}
			size_t first = 0;
			size_t last = response.size();
			while (first < last && asciiSpace(response[first])) ++first;
			while (last > first && asciiSpace(response[last - 1])) --last;
			string answer = response.substr(first, last - first);
			for (char& character : answer) {
				if (character >= 'A' && character <= 'Z') character += 'a' - 'A';
			}
			if (answer.empty()) return defaultAnswer;
			if (answer == "y" || answer == "yes") return true;
			if (answer == "n" || answer == "no") return false;
			writeToTerminal(terminal.descriptor(), "Please answer yes or no.\n");
		}
	}
};
