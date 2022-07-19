package rabbitio

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	RabbitKeyLen = 0x10
	RabbitIVXLen = 0x08
)

var (
	ErrInvalidKey = errors.New("rabbitio: key must be 16 byte len, not more not less")
	ErrInvalidIVX = errors.New("rabbitio: iv must be 8 byte len or nothing (zero) at all")
)

var aro = []uint32{
	0x4D34D34D, 0xD34D34D3, 
	0x34D34D34, 0x4D34D34D, 
	0xD34D34D3, 0x34D34D34, 
	0x4D34D34D, 0xD34D34D3,
}

type rabbitCipher struct {
	xbit  [8]uint32
	cbit  [8]uint32
	ks    []byte
	carry uint32
	sbit  [16]byte
}

// NewCipher returns a chpher.Stream interface that implemented an XORKeyStream method
// according to RFC 4503, key must be 16 byte len, iv on the other hand is optional but
// must be either zero len or 8 byte len, error will be returned on wrong key/iv len
func NewCipher(key []byte, iv []byte) (cipher.Stream, error) {
	if len(key) != RabbitKeyLen {
		return nil, ErrInvalidKey
	}
	if len(iv) != 0x00 && len(iv) != RabbitIVXLen {
		return nil, ErrInvalidIVX
	}
	var k [0x04]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[i*0x04:])
	}
	var r rabbitCipher
	r.setupKey(k[:])
	if len(iv) != 0x00 {
		var v [0x04]uint16
		for i := range v {
			v[i] = binary.LittleEndian.Uint16(iv[i*0x02:])
		}
		r.setupIV(v[:])
	}
	return &r, nil
}

func (r *rabbitCipher) setupKey(key []uint32) {
	r.xbit[0] = key[0]
	r.xbit[1] = key[3]<<16 | key[2]>>16
	r.xbit[2] = key[1]
	r.xbit[3] = key[0]<<16 | key[3]>>16
	r.xbit[4] = key[2]
	r.xbit[5] = key[1]<<16 | key[0]>>16
	r.xbit[6] = key[3]
	r.xbit[7] = key[2]<<16 | key[1]>>16
	r.cbit[0] = bits.RotateLeft32(key[2], 0x10)
	r.cbit[1] = key[0]&0xffff0000 | key[1]&0xffff
	r.cbit[2] = bits.RotateLeft32(key[3], 0x10)
	r.cbit[3] = key[1]&0xffff0000 | key[2]&0xffff
	r.cbit[4] = bits.RotateLeft32(key[0], 0x10)
	r.cbit[5] = key[2]&0xffff0000 | key[3]&0xffff
	r.cbit[6] = bits.RotateLeft32(key[1], 0x10)
	r.cbit[7] = key[3]&0xffff0000 | key[0]&0xffff
	for i := 0; i < 4; i++ {
		r.nextState()
	}
	r.cbit[0] ^= r.xbit[4]
	r.cbit[1] ^= r.xbit[5]
	r.cbit[2] ^= r.xbit[6]
	r.cbit[3] ^= r.xbit[7]
	r.cbit[4] ^= r.xbit[0]
	r.cbit[5] ^= r.xbit[1]
	r.cbit[6] ^= r.xbit[2]
	r.cbit[7] ^= r.xbit[3]
}

func (r *rabbitCipher) setupIV(iv []uint16) {
	r.cbit[0] ^= uint32(iv[1])<<0x10 | uint32(iv[0])
	r.cbit[1] ^= uint32(iv[3])<<0x10 | uint32(iv[1])
	r.cbit[2] ^= uint32(iv[3])<<0x10 | uint32(iv[2])
	r.cbit[3] ^= uint32(iv[2])<<0x10 | uint32(iv[0])
	r.cbit[4] ^= uint32(iv[1])<<0x10 | uint32(iv[0])
	r.cbit[5] ^= uint32(iv[3])<<0x10 | uint32(iv[1])
	r.cbit[6] ^= uint32(iv[3])<<0x10 | uint32(iv[2])
	r.cbit[7] ^= uint32(iv[2])<<0x10 | uint32(iv[0])
	for i := 0; i < 4; i++ {
		r.nextState()
	}
}

func (r *rabbitCipher) nextState() {
	var GRX [0x08]uint32
	for i := range r.cbit {
		r.carry, r.cbit[i] = bits.Sub32(aro[i], r.cbit[i], r.carry)
	}
	for i := range GRX {
		GRX[i] = gfunction(r.xbit[i], r.cbit[i])
	}
	r.xbit[0x00] = GRX[0] + bits.RotateLeft32(GRX[7], 0x10) + bits.RotateLeft32(GRX[6], 0x10)
	r.xbit[0x01] = GRX[1] + bits.RotateLeft32(GRX[0], 0x08) + GRX[7]
	r.xbit[0x02] = GRX[2] + bits.RotateLeft32(GRX[1], 0x10) + bits.RotateLeft32(GRX[0], 0x10)
	r.xbit[0x03] = GRX[3] + bits.RotateLeft32(GRX[2], 0x08) + GRX[1]
	r.xbit[0x04] = GRX[4] + bits.RotateLeft32(GRX[3], 0x10) + bits.RotateLeft32(GRX[2], 0x10)
	r.xbit[0x05] = GRX[5] + bits.RotateLeft32(GRX[4], 0x08) + GRX[3]
	r.xbit[0x06] = GRX[6] + bits.RotateLeft32(GRX[5], 0x10) + bits.RotateLeft32(GRX[4], 0x10)
	r.xbit[0x07] = GRX[7] + bits.RotateLeft32(GRX[6], 0x08) + GRX[5]
}

func (r *rabbitCipher) extract() {
	var sw [0x04]uint32
	r.nextState()
	sw[0] = r.xbit[0] ^ (r.xbit[5]>>0x10 | r.xbit[3]<<0x10)
	sw[1] = r.xbit[2] ^ (r.xbit[7]>>0x10 | r.xbit[5]<<0x10)
	sw[2] = r.xbit[4] ^ (r.xbit[1]>>0x10 | r.xbit[7]<<0x10)
	sw[3] = r.xbit[6] ^ (r.xbit[3]>>0x10 | r.xbit[1]<<0x10)
	for i := range sw {
		binary.LittleEndian.PutUint32(r.sbit[i*0x04:], sw[i])
	}
	r.ks = r.sbit[:]
}

// XORKeyStream read from src and perform xor on every elemnt of src and
// write result on dst
func (r *rabbitCipher) XORKeyStream(dst, src []byte) {
	for i := range src {
		if len(r.ks) == 0x00 {
			r.extract()
		}
		dst[i] = src[i] ^ r.ks[0x00]
		r.ks = r.ks[0x01:]
	}
}

func gfunction(u, v uint32) uint32 {
	uv := uint64(u + v)
	uv *= uv
	return uint32(uv>>0x20) ^ uint32(uv)
}
