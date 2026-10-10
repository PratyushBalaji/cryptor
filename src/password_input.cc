#include <array>
#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sodium.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

using namespace std;

class TerminalEchoGuard {
	int terminalDescriptor = -1;
	termios originalSettings {};

public:
	TerminalEchoGuard() {
		terminalDescriptor = open("/dev/tty", O_RDWR);
		if (terminalDescriptor < 0) {
			throw system_error(errno, generic_category(), "Unable to open terminal");
		}

		if (tcgetattr(terminalDescriptor, &originalSettings) != 0) {
			int terminalError = errno;
			close(terminalDescriptor);
			throw system_error(terminalError, generic_category(), "Unable to read terminal settings");
		}

		termios hiddenSettings = originalSettings;
		hiddenSettings.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL));

		if (tcsetattr(terminalDescriptor, TCSAFLUSH, &hiddenSettings) != 0) {
			int terminalError = errno;
			close(terminalDescriptor);
			throw system_error(terminalError, generic_category(), "Unable to hide password input");
		}
	}

	TerminalEchoGuard(const TerminalEchoGuard&) = delete;
	TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

	~TerminalEchoGuard() {
		if (terminalDescriptor >= 0) {
			tcsetattr(terminalDescriptor, TCSANOW, &originalSettings);
			close(terminalDescriptor);
		}
	}

	int descriptor() const {
		return terminalDescriptor;
	}
};

void writeToTerminal(int descriptor, const string& text) {
	size_t totalWritten = 0;

	while (totalWritten < text.size()) {
		ssize_t written = write(
			descriptor,
			text.data() + totalWritten,
			text.size() - totalWritten
		);

		if (written < 0) {
			if (errno == EINTR) continue;
			throw system_error(errno, generic_category(), "Unable to write to terminal");
		}

		if (written == 0) throw runtime_error("Unable to write to terminal");
		totalWritten += static_cast<size_t>(written);
	}
}

string readPassword(const string& prompt) {
	TerminalEchoGuard terminal;
	writeToTerminal(terminal.descriptor(), prompt);

	string password;
	char buffer[256];

	try {
		while (true) {
			ssize_t bytesRead = read(terminal.descriptor(), buffer, sizeof(buffer));

			if (bytesRead < 0) {
				if (errno == EINTR) continue;
				throw system_error(errno, generic_category(), "Unable to read password");
			}

			if (bytesRead == 0) {
				writeToTerminal(terminal.descriptor(), "\n");
				throw runtime_error("Password input cancelled");
			}

			for (ssize_t i = 0; i < bytesRead; ++i) {
				if (buffer[i] == '\n' || buffer[i] == '\r') {
					writeToTerminal(terminal.descriptor(), "\n");
					sodium_memzero(buffer, sizeof(buffer));
					return password;
				}
				password.push_back(buffer[i]);
			}
		}
	} catch (...) {
		if (!password.empty()) sodium_memzero(password.data(), password.size());
		sodium_memzero(buffer, sizeof(buffer));
		throw;
	}
}

void readPasswordFile(const filesystem::path& path, string& password) {
	struct stat fileStatus {};
	if (stat(path.c_str(), &fileStatus) != 0) {
		throw system_error(errno, generic_category(), "Unable to inspect password file");
	}

	if ((fileStatus.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		cerr << "WARNING: password file is accessible by group or other users: "
		     << path << endl;
	}

	ifstream file {path, ios::binary};
	if (!file.is_open()) {
		throw runtime_error("Error: could not open password file: " + path.string());
	}

	password.clear();
	if (fileStatus.st_size > 0) {
		password.reserve(static_cast<size_t>(fileStatus.st_size));
	}

	array<char, 4096> buffer {};

	try {
		while (file) {
			file.read(buffer.data(), buffer.size());
			streamsize bytesRead = file.gcount();

			if (bytesRead > 0) {
				password.append(buffer.data(), static_cast<size_t>(bytesRead));
			}
		}

		if (!file.eof()) {
			throw runtime_error("Error: failed while reading password file.");
		}

		if (!password.empty() && password.back() == '\n') {
			password.pop_back();
			if (!password.empty() && password.back() == '\r') {
				password.pop_back();
			}
		}

		if (password.empty()) {
			throw runtime_error("Error: password file is empty.");
		}

		sodium_memzero(buffer.data(), buffer.size());
		return;
	} catch (...) {
		if (!password.empty()) sodium_memzero(password.data(), password.size());
		sodium_memzero(buffer.data(), buffer.size());
		throw;
	}
}

bool confirmAction(const string& prompt) {
	int terminalDescriptor = open("/dev/tty", O_RDWR);
	if (terminalDescriptor < 0) {
		throw system_error(errno, generic_category(), "Unable to open terminal for confirmation");
	}

	string response;
	array<char, 64> buffer {};

	try {
		writeToTerminal(terminalDescriptor, prompt);

		bool finished = false;
		while (!finished) {
			ssize_t bytesRead = read(terminalDescriptor, buffer.data(), buffer.size());
			if (bytesRead < 0) {
				if (errno == EINTR) continue;
				throw system_error(errno, generic_category(), "Unable to read confirmation");
			}
			if (bytesRead == 0) break;

			for (ssize_t i = 0; i < bytesRead; ++i) {
				char character = buffer[static_cast<size_t>(i)];
				if (character == '\n' || character == '\r') {
					finished = true;
					break;
				}
				response.push_back(character);
			}
		}
		close(terminalDescriptor);
	} catch (...) {
		close(terminalDescriptor);
		throw;
	}

	auto first = find_if_not(response.begin(), response.end(), [](unsigned char character) {
		return isspace(character);
	});
	auto last = find_if_not(response.rbegin(), response.rend(), [](unsigned char character) {
		return isspace(character);
	}).base();
	string answer = first < last ? string(first, last) : string {};
	transform(answer.begin(), answer.end(), answer.begin(), [](unsigned char character) {
		return static_cast<char>(tolower(character));
	});

	return answer == "y" || answer == "yes";
}
