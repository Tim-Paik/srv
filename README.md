# Srv Dev Server

This is a simple HTTP Server for use in a development environment, inspired by [simple-http-server](https://github.com/TheWaWaR/simple-http-server) and [caddy2](https://github.com/caddyserver/caddy), and it is also a practice project for me to learn rust.

### Screenshot
![screenshot](screenshot.png)

### Built With

- [clap](https://github.com/clap-rs/clap) Provide command line parameter analysis
- [askama](https://github.com/djc/askama) Provide template support
- [actix-web](https://github.com/actix/actix-web) Main frame
- [actix-files](https://github.com/actix/actix-web/tree/master/actix-files) Provide static resources
- [actix-web-httpauth](https://github.com/actix/actix-extras/tree/master/actix-web-httpauth) Provide authentication
- [rustls](https://github.com/rustls/rustls) Provide TLS and HTTP/2 support
- [env_logger](https://github.com/env-logger-rs/env_logger) Provide log output


## Features

- Automatic generation of directory listings (default enabled)
- Relative path/absolute path/support
- Brotli/Gzip/Deflate streaming compression support (default disabled, disables Content-length and segmented downloads when enabled)
- Control whether dotfiles are displayed and can be accessed (default disabled)
- HTTP cache support, 304 support, Last-Modified/ETag support, of course you can also turn off cache
- Clearly colored organized log
- Disable access logging or disable all logging support
- Automatically open default browser (default disabled)
- Single-Page Application mode (always serve /index.html when the file is not found)
- Custom listening address (default 0.0.0.0) Custom listening port number (default 8000)
- HTTP Basic Authentication Support
- TLS/SSL support, HTTP/2 support
- One click to enable CORS, custom CORS header support
- cargo doc support

## Install

### Pre-compiled Version

#### Linux

##### Archlinux

```shell
yay -S srv-bin
```

##### Other Linux

Download the pre-compiled `srv-x86_64-unknown-linux-musl.tar.gz` on the [releases](https://github.com/Tim-Paik/srv/releases/latest), and copy the srv file in the compressed package to `/usr/bin` as a ROOT user with 755 permissions.

```shell
wget https://github.com/Tim-Paik/srv/releases/download/v1.0.1/srv-v1.0.1-x86_64-unknown-linux-musl.tar.gz
tar -xzvf srv-v1.0.1-x86_64-unknown-linux-musl.tar.gz
install -Dm0755 -t /usr/bin/ srv
rm srv srv-v1.0.1-x86_64-unknown-linux-musl.tar.gz
```
for reference only

#### MacOS

I'm sorry I don't have the corresponding equipment, but I can only provide `srv-x86_64-apple-darwin.tar.gz` (Of course, if someone can sponsor me a Mac I would be very grateful)

#### Windows

Download the pre-compiled `srv-x86_64-pc-windows-msvc.zip` in the [releases](https://github.com/Tim-Paik/srv/releases/latest), unzip the srv.exe and copy it to your `%PATH%` (if you don’t know what this is, move `srv.exe` to `%SystemRoot%\System32`)

### Compile and Install

You Need:

 - Rust & Cargo Installation
 - Git Installation
 - Gcc/Msvc Toolchain Installation

```shell
git clone git@github.com:Tim-Paik/srv.git
cd srv
cargo build --release
```

Then you can find the compiled executable file named `srv` in the `target/release/` folder.

## Usage

Execute `srv --help` to get all the usage methods

Waiting to be added...

## Contributing

All contributions are welcome and I will reply as soon as I see it :)

## License

```text
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
```