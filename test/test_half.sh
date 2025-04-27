#!/bin/bash

# Simulate a connection break and check how the file is sent
# if part of it is already present at the stx-recv

SEND_BIN="../build/src/stx-send/stx-send"
RECV_BIN="../build/src/stx-recv/stx-recv"

HOST="127.0.0.1"
PORT=8989
OUTPUT_DIR="/home/roman/Downloads/test"
TEST_FILE="test_data.bin"
OUTPUT_FILE="${OUTPUT_DIR}/${TEST_FILE}"

FILE_SIZE_MB=5
FILE_SIZE_BYTES=$((FILE_SIZE_MB * 1024 * 1024))
HALF_SIZE_BYTES=$((FILE_SIZE_BYTES / 2))

echo "Generating test file ${FILE_SIZE_MB}MB..."
dd if=/dev/urandom of="$TEST_FILE" bs=1 count="$FILE_SIZE_BYTES" status=progress
ORIG_HASH=$(sha256sum "$TEST_FILE" | awk '{print $1}')
echo "Original hash: $ORIG_HASH"

echo "Creating a file with the first half of the data in '$OUTPUT_DIR'..."
mkdir -p "$OUTPUT_DIR"
head -c "$HALF_SIZE_BYTES" "$TEST_FILE" > "$OUTPUT_FILE"
echo "File '$OUTPUT_FILE' with the first half of the data has been created."

echo "Starting stx-recv..."
"$RECV_BIN" --listen "$PORT" --out "$OUTPUT_DIR" &
RECV_PID=$!
sleep 2

echo "Starting stx-send..."
"$SEND_BIN" "$HOST" "$PORT" "$TEST_FILE"

sleep 3

echo "Finishing stx-recv (PID: $RECV_PID)"
if ps -p "$RECV_PID" > /dev/null; then
  kill "$RECV_PID"
else
  echo "Process stx-recv was not found."
fi
wait "$RECV_PID" 2>/dev/null
sleep 2

echo "Data integrity check..."
if [ -f "$OUTPUT_FILE" ]; then
  RECV_HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')

  if [ "$ORIG_HASH" == "$RECV_HASH" ]; then
    echo "SUCCESS: Files are identical (hash: $RECV_HASH)"
    rm "$TEST_FILE"
    rm "$OUTPUT_FILE"
    exit 0
  else
    echo "FAIL: Hashes do not match!"
    echo "Original: $ORIG_HASH"
    echo "Received: $RECV_HASH"
    rm "$TEST_FILE"
    rm "$OUTPUT_FILE"
    exit 1
  fi
else
  echo "ERROR: File '$OUTPUT_FILE' was not found!"
  rm "$TEST_FILE"
  rm "$OUTPUT_FILE"
  exit 1
fi
