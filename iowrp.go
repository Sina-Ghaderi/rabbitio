package rabbitio

import (
	"crypto/cipher"
	"io"
)

// NewWriterCipher warp a rabbit cipher stream with an io.Writer, returned StreamWriter
// interface witch can be used to encrypt or decrypting data
func NewWriterCipher(key []byte, iv []byte, wr io.Writer) (*cipher.StreamWriter, error) {
	stream, err := NewCipher(key, iv)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamWriter{S: stream, W: wr}, err
}

// NewWriterCipher warp a rabbit cipher stream with an io.Reader, returned StreamReader
// interface witch can be used to encrypt or decrypting data
func NewReaderCipher(key []byte, iv []byte, re io.Reader) (*cipher.StreamReader, error) {
	stream, err := NewCipher(key, iv)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{S: stream, R: re}, err
}
