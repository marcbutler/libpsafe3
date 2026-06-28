libpsafe3
=========

C++ library for reading [Password Safe v3][pwsafe] databases, with a `psafe3dump` command-line utility for inspecting database contents.

[![Build Status](https://github.com/marcbutler/libpsafe3/actions/workflows/cmake-test.yml/badge.svg)](https://github.com/marcbutler/libpsafe3/actions/workflows/cmake-test.yml)

See [LICENSE](./LICENSE) file for licensing details.

Requirements
------------

* C++23 compiler — GCC 14+ or Clang 18+
* [CMake][cmake] 3.14+
* [libgcrypt][libgcrypt]
* [libuuid][libuuid]

On Ubuntu 24.04:

```sh
sudo apt install g++-14 libgcrypt-dev uuid-dev
```

On macOS (Homebrew):

```sh
brew install libgcrypt ossp-uuid
```

Building
--------

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

Usage
-----

```sh
psafe3dump <file.psafe3> <password>
```

[pwsafe]: http://pwsafe.org/
[cmake]: https://cmake.org/
[libgcrypt]: https://www.gnu.org/software/libgcrypt/
[libuuid]: https://linux.die.net/man/3/uuid
