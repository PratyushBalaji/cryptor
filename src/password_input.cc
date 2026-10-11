#include <array>
#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sodium.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

using namespace std;

class TerminalEchoGuard {
	TerminalDescriptor terminal;
	termios originalSettings {};

public:
	TerminalEchoGuard() {
		if (tcgetattr(terminal.descriptor(), &originalSettings) != 0) {
			int terminalError = errno;
			throw system_error(terminalError, generic_category(), "Unable to read terminal settings");
		}

		termios hiddenSettings = originalSettings;
		hiddenSettings.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL));

		if (tcsetattr(terminal.descriptor(), TCSAFLUSH, &hiddenSettings) != 0) {
			int terminalError = errno;
			throw system_error(terminalError, generic_category(), "Unable to hide password input");
		}
	}

	TerminalEchoGuard(const TerminalEchoGuard&) = delete;
	TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

	~TerminalEchoGuard() {
		tcsetattr(terminal.descriptor(), TCSANOW, &originalSettings);
	}

	int descriptor() const {
		return terminal.descriptor();
	}
};

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

void readPasswordFile(const filesystem::path& path, string& password, const Console& console) {
	struct stat fileStatus {};
	if (stat(path.c_str(), &fileStatus) != 0) {
		throw system_error(errno, generic_category(), "Unable to inspect password file");
	}

	if ((fileStatus.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		console.warn("password file is accessible by group or other users: " + path.string());
	}

	ifstream file {path, ios::binary};
	if (!file.is_open()) {
		throw runtime_error("could not open password file: " + path.string());
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
			throw runtime_error("failed while reading password file.");
		}

		if (!password.empty() && password.back() == '\n') {
			password.pop_back();
			if (!password.empty() && password.back() == '\r') {
				password.pop_back();
			}
		}

		if (password.empty()) {
			throw runtime_error("password file is empty.");
		}

		sodium_memzero(buffer.data(), buffer.size());
		return;
	} catch (...) {
		if (!password.empty()) sodium_memzero(password.data(), password.size());
		sodium_memzero(buffer.data(), buffer.size());
		throw;
	}
}
