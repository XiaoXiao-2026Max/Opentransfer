package crypt

import (
	"encoding/binary"
	"errors"
)

var NetEaseIV = []byte("163 NetEase\n")

var chachaSigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

type ChaCha8 struct {
	state     [16]uint32
	keyStream [64]byte
	index     int
}

func NewChaCha8(key, iv []byte) (*ChaCha8, error) {
	if len(key) != 32 {
		return nil, errors.New("crypt: chacha8 key must be 32 bytes")
	}
	if len(iv) != 12 {
		return nil, errors.New("crypt: chacha8 iv must be 12 bytes")
	}
	c := &ChaCha8{}
	copy(c.state[0:4], chachaSigma[:])
	for i := 0; i < 8; i++ {
		c.state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	c.state[12] = 0
	for i := 0; i < 3; i++ {
		c.state[13+i] = binary.LittleEndian.Uint32(iv[i*4:])
	}
	c.generate()
	return c, nil
}

func NewNetEaseChaCha8(key []byte) (*ChaCha8, error) {
	return NewChaCha8(key, NetEaseIV)
}

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = d<<16 | d>>16
	c += d
	b ^= c
	b = b<<12 | b>>20
	a += b
	d ^= a
	d = d<<8 | d>>24
	c += d
	b ^= c
	b = b<<7 | b>>25
	return a, b, c, d
}

func (c *ChaCha8) generate() {
	var x [16]uint32
	copy(x[:], c.state[:])
	for i := 0; i < 4; i++ {
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(c.keyStream[i*4:], x[i]+c.state[i])
	}
}

func (c *ChaCha8) XORKeyStream(buf []byte) {
	for i := range buf {
		buf[i] ^= c.keyStream[c.index]
		c.index = (c.index + 1) & 63
		if c.index == 0 {
			c.state[12]++
			c.generate()
		}
	}
}

func (c *ChaCha8) Process(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	c.XORKeyStream(dst)
	return dst
}
