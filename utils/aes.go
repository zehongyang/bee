package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func AesGcmEncrypt(plaintext []byte, key []byte, aad ...[]byte) ([]byte, error) {
	// 创建 AES 算法实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建 GCM 模式实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 创建随机 Nonce（临时随机数）
	// GCM 标准 Nonce 长度为 12 字节
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal 进行加密并进行身份认证
	// 第一个参数是前缀，通常将 nonce 放在密文头部以便解密时取出
	var aadData []byte
	if len(aad) > 0 {
		aadData = aad[0]
	}
	return gcm.Seal(nonce, nonce, plaintext, aadData), nil
}

func AesGcmDecrypt(ciphertext []byte, key []byte, aad ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文过短")
	}

	// 分离 Nonce 和真正的密文
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Open 进行解密并验证完整性
	var aadData []byte
	if len(aad) > 0 {
		aadData = aad[0]
	}
	return gcm.Open(nil, nonce, actualCiphertext, aadData)
}
