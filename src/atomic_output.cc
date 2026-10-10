#include <cstddef>
#include <cstdio>
#include <filesystem>

#include <cerrno>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

using namespace std;

class AtomicOutput {
	filesystem::path destination;
	filesystem::path temporary;
	FILE* file = nullptr;
	bool committed = false;

	static void throwOutputError(const char* message) { // always throws
		if (errno != 0) throw system_error(errno, generic_category(), message);
		throw runtime_error(message);
	}

public:
	explicit AtomicOutput(const filesystem::path& outputPath)
		: destination(filesystem::absolute(outputPath).lexically_normal()) {
		string pattern = destination.string() + ".tmp.XXXXXX";
		vector<char> writablePattern(pattern.begin(), pattern.end());
		writablePattern.push_back('\0');

		int descriptor = mkstemp(writablePattern.data());
		if (descriptor < 0) throwOutputError("Unable to create temporary output file");

		temporary = writablePattern.data();
		file = fdopen(descriptor, "wb");
		if (file == nullptr) {
			int openError = errno;
			close(descriptor);
			error_code ignored;
			filesystem::remove(temporary, ignored);
			errno = openError;
			throwOutputError("Unable to open temporary output file");
		}
	}

	AtomicOutput(const AtomicOutput&) = delete;
	AtomicOutput& operator=(const AtomicOutput&) = delete;

	~AtomicOutput() {
		if (file != nullptr) fclose(file);
		if (!committed) {
			error_code ignored;
			filesystem::remove(temporary, ignored);
		}
	}

	void write(const char* data, size_t size) {
		if (size == 0) return;

		if (fwrite(data, 1, size, file) != size) throwOutputError("Unable to write output file");
	}

	void commit() {
		if (fflush(file) != 0) throwOutputError("Unable to flush output file");

		if (fsync(fileno(file)) != 0) throwOutputError("Unable to synchronise output file");

		FILE* stream = file;
		file = nullptr;
		if (fclose(stream) != 0) throwOutputError("Unable to close output file");

		if (rename(temporary.c_str(), destination.c_str()) != 0) throwOutputError("Unable to replace output file");
		committed = true;
	}
};
