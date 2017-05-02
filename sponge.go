// This source form is subject to the Creative Commons "CC0" license


package spongecrypto

import "golang.org/x/crypto/salsa20/salsa"

type Crypto struct{
	Len uint // 0 < Len < 64
	Off uint
	State [64]byte
}

func (c *Crypto) EncryptInplace(p []byte) {
	for i,b := range p {
		if c.Off==c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		c.State[i] ^= b
		p[i] = c.State[i]
	}
	return
}

func (c *Crypto) Write(p []byte) (n int, err error) {
	for i,b := range p {
		if c.Off==c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		c.State[i] ^= b
	}
	return len(p),nil
}
func (c *Crypto) Read(p []byte) (n int, err error) {
	for i := range p {
		if c.Off==c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		p[i] = c.State[i]
	}
	return len(p),nil
}
func (c *Crypto) CloneCipher() *Crypto {
	d := new(Crypto)
	*d = *c
	return d
}
func (c *Crypto) Sum(b []byte) []byte {
	if c.Off > 0 {
		salsa.Core208(&c.State,&c.State)
		c.Off = 0
	}
	return append(b,c.State[:c.Len]...)
}
func (c *Crypto) Encrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off==c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		c.State[i] ^= b
		dst[i] = c.State[i]
	}
	return
}
func (c *Crypto) Decrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off==c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		dst[i] = c.State[i] ^ b
		c.State[i] = b
	}
	return
}
func (c *Crypto) Size() int { return int(c.Len) }
func (c *Crypto) BlockSize() int { return int(64-c.Len) }
