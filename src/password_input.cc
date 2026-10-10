#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sodium.h>
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
