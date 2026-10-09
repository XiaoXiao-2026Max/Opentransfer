package crypt

import (
	"crypto/aes"
	"errors"
)

func AESECBEncrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(src) == 0 || len(src)%block.BlockSize() != 0 {
		return nil, errors.New("crypt: ecb input must be a non-zero multiple of the block size")
	}
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		block.Encrypt(dst[i:i+block.BlockSize()], src[i:i+block.BlockSize()])
	}
	return dst, nil
}
