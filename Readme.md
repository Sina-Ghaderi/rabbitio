# rabbitio
rabbitio is a rabbit stream cipher packge based on [RFC 4503](https://datatracker.ietf.org/doc/html/rfc4503) for golang  
rabbit is a super-fast lightweight stream cipher which uses a 128-bit key and a 64-bit initialization vector, this cipher was designed in 2003 and released in 2008   


this is a mirror repository, rabbitio also lives on [snix.ir public git service](https://snix.ir/rabbitio)

### usage and docs
simple encrypt/decrypting plain text and cipher text with rabbitio  
key must be exactly 16 byte len, iv is optional but must be either zero (for nothing) or 8 byte len  
you can replace `"snix.ir/rabbitio"` with `"github.com/sina-ghaderi/rabbitio"` to use github mirror repository

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



feel free to email me sina@snix.ir if you want to contribute to this project

Copyright 2022 SNIX LLC sina@snix.ir Apache License




