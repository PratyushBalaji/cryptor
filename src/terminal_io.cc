#include <cerrno>
#include <fcntl.h>
#include <string>
#include <system_error>
#include <stdexcept>
#include <unistd.h>

using namespace std;

class TerminalDescriptor {
	int descriptorValue;

public:
	TerminalDescriptor() : descriptorValue(-1) {
		do {
			descriptorValue = open("/dev/tty", O_RDWR);
		} while (descriptorValue < 0 && errno == EINTR);
		if (descriptorValue < 0)
			throw system_error(errno, generic_category(), "unable to open terminal");
	}
	TerminalDescriptor(const TerminalDescriptor&) = delete;
	TerminalDescriptor& operator=(const TerminalDescriptor&) = delete;
	~TerminalDescriptor() { close(descriptorValue); }
	int descriptor() const { return descriptorValue; }
};

void writeToTerminal(int descriptor, const string& text) {
	size_t totalWritten = 0;
	while (totalWritten < text.size()) {
		ssize_t written = write(descriptor, text.data() + totalWritten, text.size() - totalWritten);
		if (written < 0) {
			if (errno == EINTR) continue;
			throw system_error(errno, generic_category(), "unable to write to terminal");
		}
		if (written == 0) throw runtime_error("unable to write to terminal");
		totalWritten += static_cast<size_t>(written);
	}
}
