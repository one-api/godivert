# GoDivert

A high-performance, pure Go implementation of the WinDivert user-mode library.
This package allows you to capture and inject network packets on Windows
without the complexity of CGO or external C dependencies.

## Features

🚀 Zero CGO Dependency: Built entirely in pure Go using syscall/windows APIs. No GCC or MinGW required for your build
pipeline.

🐹 Idiomatic Go: Designed with a Go-first mentality. Includes friendly error handling and structured types instead of raw
C pointers.

📦 Embedded Driver: Utilizes go:embed to bundle the .sys drivers directly into your binary. No more manual file
management.

⚡ Optimized Loading: Advanced driver loading and unloading logic to ensure stability and prevent resource leaks.

📚 Educational & Clean: Highly readable codebase designed to be a learning resource for Windows kernel-mode/user-mode
communication in Go.

## Quick Start

### Installation

```shell
go get github.com/one-api/godivert
```

### simple example

```go
package main

import (
	"github.com/one-api/godivert"
)

func main() {

	// Open driver
	filter := "!loopback and (tcp or udp)"
	divert, err := godivert.New(filter, godivert.LayerNetwork, 0, 0)
	if err != nil {
		panic(err)
	}
	defer divert.Close()

	// Buffer for packet data
	packet := make([]byte, 2000)
	var addr godivert.Address

	// Recv Send Loop
	for i := 0; ; i++ {
		readLen, err := divert.Recv(packet, &addr)
		if err != nil {
			panic(err)
		}
		_, err = divert.Send(packet[:readLen], &addr)
		if err != nil {
			panic(err)
		}
	}
}

```

Note: This demo code requires *Administrator Privileges* to run

## Filter Syntax Examples

```
// Match outbound TCP traffic on port 443
outbound && tcp.DstPort == 443

// Match DNS queries
udp.DstPort == 53

// Inbound HTTP traffic
inbound && (tcp.DstPort == 80 || tcp.DstPort == 8080)
```

## Testing

Run tests with:

```bash
go test ./...
```

## References

- [WinDivert Official Documentation](https://www.reqrypt.org/windivert-doc.html)

## Acknowledgments

This project is a Go implementation based on the excellent work of Basil and the WinDivert project. 

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the LICENSE file for details.

This project embeds the WinDivert32.sys and WinDivert64.sys binaries, which are part of the WinDivert project. These binaries are licensed under the GNU Lesser General Public License v3.0 (LGPL-3.0). Copyright (c) Basil. For more information, please refer to the LICENSE-WINDIVERT file.

## Contact

If you have any questions, feedback, please feel free to reach out:

* **GitHub Issues**: For bug reports and feature requests.
* **Email**: [hello@one-api.net](mailto:hello@one-api.net)
