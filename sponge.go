// This software is subject to the Creative Commons "CC0" license


package spongecrypto

import "golang.org/x/crypto/salsa20/salsa"
import "fmt"

type Crypto struct{
	Len uint8 // 0 < Len < 64
	Off uint8 // 0 <= Off < Len
	State [64]byte
}

func (c *Crypto) Construct(l int) error{
	if !((0<l)&&(l<64)) { return fmt.Errorf("Must be 0 < size < 64 : %d",l) }
	c.Len = uint8(l)
	c.Off = 0
	for i:=0 ; i<64 ; i++ {
		c.State[i] = 0
	}
	return nil
}

func (c *Crypto) Write(p []byte) (n int, err error) {
	for _,b := range p {
		if c.Off>=c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		c.State[c.Off] ^= b
		c.Off++
	}
	return len(p),nil
}

func (c *Crypto) Read(p []byte) (n int, err error) {
	for i := range p {
		if c.Off>=c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		p[i] = c.State[c.Off]
		c.Off++
	}
	return len(p),nil
}

func (c *Crypto) CloneCipher() *Crypto {
	d := new(Crypto)
	*d = *c
	return d
}

func (c *Crypto) Pad() {
	if c.Off > 0 {
		salsa.Core208(&c.State,&c.State)
		c.Off = 0
	}
}

func (c *Crypto) Sum(b []byte) []byte {
	c.Pad()
	return append(b,c.State[:c.Len]...)
}

func (c *Crypto) Encrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off>=c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		c.State[c.Off] ^= b
		dst[i] = c.State[c.Off]
		c.Off++
	}
}

func (c *Crypto) Decrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off>=c.Len {
			salsa.Core208(&c.State,&c.State)
			c.Off = 0
		}
		dst[i] = c.State[c.Off] ^ b
		c.State[c.Off] = b
		c.Off++
	}
}

func (c *Crypto) Reset() {
	for i := 0; i<64 ; i++ { c.State[i] = 0 }
	c.Off = 0
	c.Len = 0
}

func (c *Crypto) Size() int { return int(c.Len) }

func (c *Crypto) BlockSize() int { return int(64-c.Len) }

type Encrypter struct{
	Crypto
}

func (c *Encrypter) XORKeyStream(dst, src []byte) {
	c.Encrypt(dst,src)
}

type Decrypter struct{
	Crypto
}

func (c *Decrypter) XORKeyStream(dst, src []byte) {
	c.Decrypt(dst,src)
}

type Mac struct{
	Crypto
	Bak Crypto
}
func (m *Mac) Construct(l int, key []byte) error{
	e := m.Bak.Construct(l)
	if e!=nil { return e }
	m.Bak.Write(key)
	m.Reset()
	return nil
}

func (m *Mac) Reset() {
	m.Crypto = m.Bak
}
