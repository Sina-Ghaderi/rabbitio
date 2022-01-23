package rabbitio_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"snix.ir/rabbitio"
)

func TestNewWriterCipher(t *testing.T) {
	key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
	txt := "dummy text to test NewWriterCipher"
	twr := strings.NewReader(txt)

	iw := new(bytes.Buffer)

	t.Logf("encrypting plain text ---")
	cw, err := rabbitio.NewWriterCipher(key, ivt, iw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(cw, twr); err != nil {
		t.Fatal(err)
	}

	t.Logf("cipher-text: %v", hex.EncodeToString(iw.Bytes()))
	t.Logf("decrypting cipher text ---")

	ir := new(bytes.Buffer)
	cr, err := rabbitio.NewWriterCipher(key, ivt, ir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(cr, iw); err != nil {
		t.Fatal(err)
	}

	if ir.String() != txt {
		t.Error("error: ir.String() is not equal to txt")
	}
}

func TestNewReaderCipher(t *testing.T) {
	key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
	txt := "test NewReadercipher text dummy tx"
	twr := strings.NewReader(txt)

	iw := new(bytes.Buffer)

	t.Logf("encrypting plain text ---")
	cw, err := rabbitio.NewReaderCipher(key, ivt, twr)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(iw, cw); err != nil {
		t.Fatal(err)
	}

	t.Logf("cipher-text: %v", hex.EncodeToString(iw.Bytes()))
	t.Logf("decrypting cipher text ---")

	ir := new(bytes.Buffer)
	cr, err := rabbitio.NewReaderCipher(key, ivt, iw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(ir, cr); err != nil {
		t.Fatal(err)
	}

	if ir.String() != txt {
		t.Error("error: ir.String() is not equal to txt")
	}
}

func TestNewCipher(t *testing.T) {
	key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
	txt := "test NewReadercipher text dummy tx"
	cph, err := rabbitio.NewCipher(key, ivt)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(txt))
	cph.XORKeyStream(dst, []byte(txt))
	t.Logf("cipher-text: %v", hex.EncodeToString(dst))

	cph, err = rabbitio.NewCipher(key, ivt)
	if err != nil {
		t.Fatal(err)
	}

	nds := make([]byte, len(dst))
	cph.XORKeyStream(nds, dst)
	if string(nds) != txt {
		t.Error("error: nds is not equal to txt")
	}

}
