# TestTask
## Requirements
Linux 5.15+. Tested on 6.14
## Dependencies
1. OpenSSL
2. liburing
## How to build
```bash
git clone git@github.com:Romanyyz/TestTask.git
cd TestTask
mkdir build
cd build
cmake ..
make
```
## How to run
```bash
./stx-recv --listen <port> --out <out directory>
./stx-send <host> <port> path/to/file.bin
```
