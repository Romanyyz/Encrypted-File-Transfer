#!/bin/bash

# Check how the whole file is sent

SEND_BIN="../build/src/stx-send/stx-send"
RECV_BIN="../build/src/stx-recv/stx-recv"

HOST="127.0.0.1"
PORT=8989
OUTPUT_DIR="/home/roman/Downloads/test"
TEST_FILE="test_data.bin"
OUTPUT_FILE="${OUTPUT_DIR}/${TEST_FILE}"

echo "Generating test file 5MB..."
dd if=/dev/urandom of="$TEST_FILE" bs=1M count=5 status=progress
ORIG_HASH=$(sha256sum "$TEST_FILE" | awk '{print $1}')
echo "Original hash: $ORIG_HASH"

echo "Starting stx-recv..."
mkdir -p "$OUTPUT_DIR"
"$RECV_BIN" --listen "$PORT" --out "$OUTPUT_DIR" &
RECV_PID=$!
sleep 2

echo "Starting stx-send..."
"$SEND_BIN" "$HOST" "$PORT" "$TEST_FILE"

sleep 3

echo "Finishing stx-recv (PID: $RECV_PID)..."
if ps -p "$RECV_PID" > /dev/null; then
  kill "$RECV_PID"
else
  echo "Process stx-recv was not found."
fi
wait "$RECV_PID" 2>/dev/null

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
