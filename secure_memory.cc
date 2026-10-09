#include <cstring>
#include <string>
#include <type_traits>

#include <sodium.h>

using namespace std;

template <typename T>
class WipeOnDestruction {
	static_assert(is_trivially_copyable_v<T>); // must be able to copy bits directly

	T value {};

public:
	WipeOnDestruction() = default;
	WipeOnDestruction(const WipeOnDestruction&) = delete;
	WipeOnDestruction& operator=(const WipeOnDestruction&) = delete;

	WipeOnDestruction(WipeOnDestruction&& other) noexcept {
		memcpy(&value, &other.value, sizeof(value));
		other.wipe();
	}

	WipeOnDestruction& operator=(WipeOnDestruction&& other) noexcept {
		if (this != &other) {
			wipe();
			memcpy(&value, &other.value, sizeof(value));
			other.wipe();
		}
		return *this;
	}

	~WipeOnDestruction() {
		wipe();
	}

	T& get() noexcept {
		return value;
	}

	const T& get() const noexcept {
		return value;
	}

	void wipe() noexcept {
		sodium_memzero(&value, sizeof(value));
	}
};

class PasswordWiper {
	string& password;

public:
	explicit PasswordWiper(string& passwordValue) : password(passwordValue) {}
	PasswordWiper(const PasswordWiper&) = delete;
	PasswordWiper& operator=(const PasswordWiper&) = delete;

	~PasswordWiper() {
		if (!password.empty()) sodium_memzero(password.data(), password.size());
	}
};
