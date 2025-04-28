# TestTask
## Requirements
1. Linux 5.15+
2. gcc
3. cmake
4. make
5. pkgconf
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
For a more detailed description of the design, please check out the [DESIGN.md](DESIGN.md)
