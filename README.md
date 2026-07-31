# shadowlink

A Rust networking utility for creating lightweight, secure tunnels between hosts. Designed for low-overhead point-to-point communication on local and remote networks.

## Requirements

- Rust 1.70+
- Cargo

## Installation

```sh
git clone https://github.com/innocous06/shadowlink.git
cd shadowlink
cargo build --release
```

## Usage

```sh
./target/release/shadowlink
```

Refer to the in-binary help for available flags and connection options:

```sh
./target/release/shadowlink --help
```

## License

MIT License

Copyright (c) 2024 innocous06

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
