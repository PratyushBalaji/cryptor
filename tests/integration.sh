#!/usr/bin/env bash
set -euo pipefail

CRYPTOR=${1:-./cryptor}
CRYPTOR=$(realpath "$CRYPTOR")
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURES="$PROJECT_ROOT/tests/fixtures"
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cryptor-tests.XXXXXX")

cleanup() {
    chmod -R u+rwX "$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_failure() {
    if "$@"; then
        fail "command unexpectedly succeeded: $*"
    fi
}

assert_contains() {
    local needle=$1
    local file=$2
    grep -Fqi -- "$needle" "$file" || fail "expected '$needle' in $file"
}

assert_no_temporary_output() {
    local output=$1
    if compgen -G "${output}.tmp.*" > /dev/null; then
        fail "temporary output remains beside $output"
    fi
}

confirm() {
    local response=$1
    shift
    local command
    printf -v command '%q ' "$@"
    printf '%s\n' "$response" | script --quiet --return --command "$command" /dev/null
}

PASSWORD="$TEST_DIR/password"
WRONG_PASSWORD="$TEST_DIR/wrong-password"
printf 'integration-test-password\n' > "$PASSWORD"
printf 'definitely-the-wrong-password\n' > "$WRONG_PASSWORD"
chmod 600 "$PASSWORD" "$WRONG_PASSWORD"

printf 'Running round-trip boundary tests...\n'
for size in 0 1 65535 65536 65537 131072; do
    input="$TEST_DIR/input-$size"
    safe="$TEST_DIR/safe-$size"
    safe_restored="$TEST_DIR/safe-restored-$size"
    unsafe="$TEST_DIR/unsafe-$size"
    unsafe_restored="$TEST_DIR/unsafe-restored-$size"

    head -c "$size" /dev/urandom > "$input"
    "$CRYPTOR" -e "$input" "$safe" --password-file "$PASSWORD"
    "$CRYPTOR" -d "$safe" "$safe_restored" --password-file "$PASSWORD"
    cmp "$input" "$safe_restored" || fail "safe round trip failed for $size bytes"

    "$CRYPTOR" -u "$input" "$unsafe" --password-file "$PASSWORD" 2> /dev/null
    "$CRYPTOR" -u "$unsafe" "$unsafe_restored" --password-file "$PASSWORD" 2> /dev/null
    cmp "$input" "$unsafe_restored" || fail "unsafe round trip failed for $size bytes"
done

printf 'Checking randomness, determinism and size...\n'
SOURCE="$TEST_DIR/properties-input"
head -c 70000 /dev/urandom > "$SOURCE"
"$CRYPTOR" -e "$SOURCE" "$TEST_DIR/safe-random-a" --password-file "$PASSWORD"
"$CRYPTOR" -e "$SOURCE" "$TEST_DIR/safe-random-b" --password-file "$PASSWORD"
if cmp -s "$TEST_DIR/safe-random-a" "$TEST_DIR/safe-random-b"; then
    fail 'safe ciphertext was deterministic'
fi

"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/unsafe-a" --password-file "$PASSWORD" 2> /dev/null
"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/unsafe-b" --password-file "$PASSWORD" 2> /dev/null
cmp "$TEST_DIR/unsafe-a" "$TEST_DIR/unsafe-b" || fail 'unsafe ciphertext was not deterministic'
[[ $(stat -c %s "$SOURCE") == $(stat -c %s "$TEST_DIR/unsafe-a") ]] || fail 'unsafe mode changed the file size'

printf 'Checking authenticated failure handling...\n'
AUTH_CIPHER="$TEST_DIR/auth-cipher"
"$CRYPTOR" -e "$SOURCE" "$AUTH_CIPHER" --password-file "$PASSWORD"

check_failed_decryption() {
    local damaged=$1
    local name=$2
    local destination="$TEST_DIR/failure-output-$name"
    printf 'preserve me\n' > "$destination"
    cp "$destination" "$destination.expected"
    expect_failure "$CRYPTOR" -d -f "$damaged" "$destination" --password-file "$PASSWORD"
    cmp "$destination.expected" "$destination" || fail "$name replaced an existing output"
    assert_no_temporary_output "$destination"
}

WRONG_DESTINATION="$TEST_DIR/wrong-password-output"
printf 'preserve me\n' > "$WRONG_DESTINATION"
cp "$WRONG_DESTINATION" "$WRONG_DESTINATION.expected"
expect_failure "$CRYPTOR" -d -f "$AUTH_CIPHER" "$WRONG_DESTINATION" --password-file "$WRONG_PASSWORD"
cmp "$WRONG_DESTINATION.expected" "$WRONG_DESTINATION" || fail 'wrong password replaced an existing output'
assert_no_temporary_output "$WRONG_DESTINATION"

cp "$AUTH_CIPHER" "$TEST_DIR/tampered"
original_byte=$(od -An -tu1 -j 64 -N 1 "$TEST_DIR/tampered")
replacement_byte=$((original_byte ^ 1))
printf "\\$(printf '%03o' "$replacement_byte")" | dd of="$TEST_DIR/tampered" bs=1 seek=64 count=1 conv=notrunc status=none
check_failed_decryption "$TEST_DIR/tampered" tampering

cp "$AUTH_CIPHER" "$TEST_DIR/truncated"
truncate -s -1 "$TEST_DIR/truncated"
check_failed_decryption "$TEST_DIR/truncated" truncation

cp "$AUTH_CIPHER" "$TEST_DIR/trailing"
printf 'trailing data' >> "$TEST_DIR/trailing"
check_failed_decryption "$TEST_DIR/trailing" trailing-data

printf 'Checking password-file handling...\n'
printf 'line-ending-password\n' > "$TEST_DIR/password-lf"
printf 'line-ending-password\r\n' > "$TEST_DIR/password-crlf"
printf 'line-ending-password' > "$TEST_DIR/password-raw"
chmod 600 "$TEST_DIR/password-lf" "$TEST_DIR/password-crlf" "$TEST_DIR/password-raw"
"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/lf-output" --password-file "$TEST_DIR/password-lf" 2> /dev/null
"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/crlf-output" --password-file "$TEST_DIR/password-crlf" 2> /dev/null
"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/raw-output" --password-file "$TEST_DIR/password-raw" 2> /dev/null
cmp "$TEST_DIR/lf-output" "$TEST_DIR/crlf-output" || fail 'LF and CRLF passwords differed'
cmp "$TEST_DIR/lf-output" "$TEST_DIR/raw-output" || fail 'trailing newline was not removed exactly once'

: > "$TEST_DIR/empty-password"
chmod 600 "$TEST_DIR/empty-password"
expect_failure "$CRYPTOR" -u "$SOURCE" "$TEST_DIR/empty-output" --password-file "$TEST_DIR/empty-password"
expect_failure "$CRYPTOR" -u "$SOURCE" "$TEST_DIR/missing-output" --password-file "$TEST_DIR/missing-password"
printf 'unreadable-password\n' > "$TEST_DIR/unreadable-password"
chmod 000 "$TEST_DIR/unreadable-password"
expect_failure "$CRYPTOR" -u "$SOURCE" "$TEST_DIR/unreadable-output" --password-file "$TEST_DIR/unreadable-password"
chmod 600 "$TEST_DIR/unreadable-password"

chmod 604 "$TEST_DIR/password-lf"
"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/loose-output" --password-file "$TEST_DIR/password-lf" 2> "$TEST_DIR/loose-warning"
assert_contains 'accessible by group or other users' "$TEST_DIR/loose-warning"
"$CRYPTOR" -u -w "$SOURCE" "$TEST_DIR/quiet-output" --password-file "$TEST_DIR/password-lf" 2> "$TEST_DIR/quiet-warning"
[[ ! -s "$TEST_DIR/quiet-warning" ]] || fail '--no-warnings did not suppress informational warnings'

printf 'Checking confirmations and in-place operations...\n'
printf 'existing destination\n' > "$TEST_DIR/existing-output"
cp "$TEST_DIR/existing-output" "$TEST_DIR/existing-output.expected"
if confirm n "$CRYPTOR" -u -w "$SOURCE" "$TEST_DIR/existing-output" --password-file "$PASSWORD" > "$TEST_DIR/cancel-log" 2>&1; then
    fail 'declined replacement succeeded'
fi
assert_contains 'existing output file will be replaced' "$TEST_DIR/cancel-log"
assert_contains 'Operation cancelled' "$TEST_DIR/cancel-log"
cmp "$TEST_DIR/existing-output.expected" "$TEST_DIR/existing-output" || fail 'declined replacement changed output'

for response in '' ' No '; do
    if confirm "$response" "$CRYPTOR" -u -w "$SOURCE" "$TEST_DIR/existing-output" --password-file "$PASSWORD" > "$TEST_DIR/default-log" 2>&1; then
        fail 'negative or default-no confirmation succeeded'
    fi
    cmp "$TEST_DIR/existing-output.expected" "$TEST_DIR/existing-output" || fail 'cancelled confirmation changed output'
done

confirm $'invalid\n YeS ' "$CRYPTOR" -u -w "$SOURCE" "$TEST_DIR/existing-output" --password-file "$PASSWORD" > "$TEST_DIR/affirmative-log" 2>&1
assert_contains 'Please answer yes or no' "$TEST_DIR/affirmative-log"
cmp "$TEST_DIR/unsafe-a" "$TEST_DIR/existing-output" || fail 'affirmative confirmation did not produce the expected output'

expect_failure "$CRYPTOR" -u -w -f "$SOURCE" "$TEST_DIR/quiet-error-output" --password-file "$TEST_DIR/empty-password" 2> "$TEST_DIR/quiet-error-log"
assert_contains 'cryptor: error:' "$TEST_DIR/quiet-error-log"
expect_failure "$CRYPTOR" -u -w -f "$SOURCE" "$SOURCE" --password-file "$SOURCE" 2> "$TEST_DIR/quiet-validation-log"
assert_contains 'cryptor: error:' "$TEST_DIR/quiet-validation-log"

"$CRYPTOR" -u -f "$SOURCE" "$TEST_DIR/existing-output" --password-file "$PASSWORD" 2> "$TEST_DIR/force-warning"
assert_contains 'existing output file will be replaced' "$TEST_DIR/force-warning"
if cmp -s "$TEST_DIR/existing-output.expected" "$TEST_DIR/existing-output"; then
    fail '--force did not replace output'
fi

"$CRYPTOR" -u -w -f "$SOURCE" "$TEST_DIR/existing-output" --password-file "$PASSWORD" 2> "$TEST_DIR/quiet-force-warning"
[[ ! -s "$TEST_DIR/quiet-force-warning" ]] || fail '--no-warnings --force did not suppress replacement warnings'

cp "$SOURCE" "$TEST_DIR/safe-in-place"
"$CRYPTOR" -e -f "$TEST_DIR/safe-in-place" "$TEST_DIR/safe-in-place" --password-file "$PASSWORD" 2> "$TEST_DIR/safe-in-place-warning"
assert_contains 'safe in-place' "$TEST_DIR/safe-in-place-warning"
"$CRYPTOR" -d -f "$TEST_DIR/safe-in-place" "$TEST_DIR/safe-in-place" --password-file "$PASSWORD" 2> /dev/null
cmp "$SOURCE" "$TEST_DIR/safe-in-place" || fail 'safe in-place round trip failed'

cp "$SOURCE" "$TEST_DIR/unsafe-in-place"
"$CRYPTOR" -u -f "$TEST_DIR/unsafe-in-place" "$TEST_DIR/unsafe-in-place" --password-file "$PASSWORD" 2> "$TEST_DIR/unsafe-in-place-warning"
assert_contains 'same password again' "$TEST_DIR/unsafe-in-place-warning"
"$CRYPTOR" -u -f "$TEST_DIR/unsafe-in-place" "$TEST_DIR/unsafe-in-place" --password-file "$PASSWORD" 2> /dev/null
cmp "$SOURCE" "$TEST_DIR/unsafe-in-place" || fail 'unsafe in-place round trip failed'

"$CRYPTOR" -u "$SOURCE" "$TEST_DIR/correct-unsafe" --password-file "$PASSWORD" 2> /dev/null
"$CRYPTOR" -u "$TEST_DIR/correct-unsafe" "$TEST_DIR/wrong-attempt" --password-file "$WRONG_PASSWORD" 2> /dev/null
"$CRYPTOR" -u "$TEST_DIR/wrong-attempt" "$TEST_DIR/recovered-unsafe" --password-file "$WRONG_PASSWORD" 2> /dev/null
cmp "$TEST_DIR/correct-unsafe" "$TEST_DIR/recovered-unsafe" || fail 'unsafe wrong-password reversal failed'

printf 'Checking path collisions...\n'
ln "$SOURCE" "$TEST_DIR/input-hardlink"
expect_failure "$CRYPTOR" -u -f "$SOURCE" "$TEST_DIR/input-hardlink" --password-file "$PASSWORD"
ln -s "$SOURCE" "$TEST_DIR/input-symlink"
expect_failure "$CRYPTOR" -u -f "$SOURCE" "$TEST_DIR/input-symlink" --password-file "$PASSWORD"
expect_failure "$CRYPTOR" -u -f "$PASSWORD" "$TEST_DIR/password-input-output" --password-file "$PASSWORD"

cp "$PASSWORD" "$TEST_DIR/password-backup"
if confirm n "$CRYPTOR" -e "$SOURCE" "$PASSWORD" --password-file "$PASSWORD" > "$TEST_DIR/password-output-cancel" 2>&1; then
    fail 'declined password-file replacement succeeded'
fi
assert_contains 'credential file' "$TEST_DIR/password-output-cancel"
cmp "$PASSWORD" "$TEST_DIR/password-backup" || fail 'declined password-file replacement changed it'

"$CRYPTOR" -e -f "$SOURCE" "$PASSWORD" --password-file "$PASSWORD" 2> "$TEST_DIR/password-output-warning"
assert_contains 'credential file' "$TEST_DIR/password-output-warning"
"$CRYPTOR" -d "$PASSWORD" "$TEST_DIR/password-output-restored" --password-file "$TEST_DIR/password-backup"
cmp "$SOURCE" "$TEST_DIR/password-output-restored" || fail 'password-file/output replacement produced invalid ciphertext'

printf 'Checking the frozen v1 fixture...\n'
"$CRYPTOR" -d "$FIXTURES/v1-ciphertext.bin" "$TEST_DIR/v1-restored" --password-file "$FIXTURES/v1-password.txt"
cmp "$FIXTURES/v1-plaintext.bin" "$TEST_DIR/v1-restored" || fail 'v1 compatibility fixture failed'

printf 'All integration tests passed.\n'
