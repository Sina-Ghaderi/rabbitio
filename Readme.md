# rabbitio
rabbitio is a rabbit stream cipher packge based on RFC 4503 for golang  
rabbit is a super-fast lightweight stream cipher which uses a 128-bit key and a 64-bit initialization vector, this cipher was designed in 2003 and released in 2008   


this is a mirror repository, rabbitio also lives on [snix.ir public git service](https://snix.ir/rabbitio)

### usage and docs
simple encrypt/decrypting plain text and cipher text with rabbitio  
key must be exactly 16 byte len, iv is optional but must be either zero (for nothing) or 8 byte len  
you can replace `"snix.ir/rabbitio"` to `"github.com/sina-ghaderi/rabbitio"` to use github mirror repository

```go
package main
import (
  "encoding/hex"
  "fmt"
  
  "snix.ir/rabbitio"
)


func main() {
    key := []byte("key-gen-rabbitio")
    ivx := []byte("abcd8795")
    ptx := "plain text -- dummy text to encrypt and decrypt with rabbit"
    str, err := rabbitio.NewCipher(key, ivx)
    if err != nil { panic(err) }
  
    cpt := make([]byte, len(ptx))
    str.XORKeyStream(cpt, []byte(ptx))
    fmt.Println("cipher text ---:", hex.EncodeToString(cpt))
  
    str, err = rabbitio.NewCipher(key, ivx)
    if err != nil { panic(err) }
  
    // decrypt cipher text and print orginal text
    plx := make([]byte, len(cpt))
    str.XORKeyStream(plx, cpt)
    fmt.Println("plain text ----:", string(plx))
}

```
  
io interfaces, reader and writer methods: working with writer

```go
package main
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"snix.ir/rabbitio"
)

func main() {
	key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
	txt := "dummy text to test NewWriterCipher"
	twr := strings.NewReader(txt)
	iw := new(bytes.Buffer)
	cw, err := rabbitio.NewWriterCipher(key, ivt, iw)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(cw, twr); err != nil {
		panic(err)
	}
	fmt.Println("cipher-text:", hex.EncodeToString(iw.Bytes()))
	fmt.Println("decrypting cipher text ---")
	ir := new(bytes.Buffer)
	cr, err := rabbitio.NewWriterCipher(key, ivt, ir)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(cr, iw); err != nil {
		panic(err)
	}
	fmt.Println(ir.String())
}
```
  
io interfaces, reader and writer methods: working with reader

```go
package main
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"snix.ir/rabbitio"
)

func main() {
	key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
	txt := "test NewReadercipher text dummy tx"
	twr := strings.NewReader(txt)
	iw := new(bytes.Buffer)
	cw, err := rabbitio.NewReaderCipher(key, ivt, twr)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(iw, cw); err != nil {
		panic(err)
	}
	fmt.Println("cipher-text:", hex.EncodeToString(iw.Bytes()))
	fmt.Println("decrypting cipher text ---")
	ir := new(bytes.Buffer)
	cr, err := rabbitio.NewReaderCipher(key, ivt, iw)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(ir, cr); err != nil {
		panic(err)
	}
	fmt.Println(ir.String())
}

```

### test and benchmarking 
unit test and benchmarking provided too, run `go test -v` or `go test -bench=. -benchmem` on project root directory

```
=== RUN   TestNewWriterCipher
    io_test.go:21: encrypting plain text ---
    io_test.go:31: cipher-text: 592dc2be03869c48222805050eedd698e1ae8f39dee6bb8fdbae8b2fa18f50116a23
    io_test.go:32: decrypting cipher text ---
--- PASS: TestNewWriterCipher (0.00s)
=== RUN   TestNewReaderCipher
    io_test.go:56: encrypting plain text ---
    io_test.go:66: cipher-text: 493ddca75ae88d5a0839441504bfc194e2b2ca059be58985c6fa8a288f8b59597b29
    io_test.go:67: decrypting cipher text ---
--- PASS: TestNewReaderCipher (0.00s)
=== RUN   TestNewCipher
    io_test.go:93: cipher-text: 493ddca75ae88d5a0839441504bfc194e2b2ca059be58985c6fa8a288f8b59597b29
--- PASS: TestNewCipher (0.00s)
goos: linux
goarch: amd64
pkg: github.com/sina-ghaderi/rabbitio
cpu: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
BenchmarkNewCipher
BenchmarkNewCipher/bench_1
BenchmarkNewCipher/bench_1-8             1000000              1084 ns/op             368 B/op          5 allocs/op
PASS
ok      github.com/sina-ghaderi/rabbitio        1.100s
```

feel free to email me sina@snix.ir if you want to contribute to this project

Copyright 2022 SNIX LLC sina@snix.ir
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.




