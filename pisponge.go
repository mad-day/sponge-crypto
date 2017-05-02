// This software is subject to the Creative Commons "CC0" license


package spongecrypto

import "encoding/binary"
import "fmt"

var cl = [6][4]uint64{
	[4]uint64{0x271E1D1B170FF0E8,0xE4E2E1D8D4D2D1CC,0xCAC9C6C5C3B8B4B2,0xB1ACAAA9A6A5A39C},
	[4]uint64{0x9A999695938E8D8B,0x87787472716C6A69,0x6665635C5A595655,0x534E4D4B473C3A39},
	[4]uint64{0x3635332E2D2B271E,0x1D1B170FF0E8E4E2,0xE1D8D4D2D1CCCAC9,0xC6C5C3B8B4B2B1AC},
	[4]uint64{0xAAA9A6A5A39C9A99,0x9695938E8D8B8778,0x7472716C6A696665,0x635C5A595655534E},
	[4]uint64{0x4D4B473C3A393635,0x332E2D2B271E1D1B,0x170FF0E8E4E2E1D8,0xD4D2D1CCCAC9C6C5},
	[4]uint64{0xC3B8B4B2B1ACAAA9,0xA6A5A39C9A999695,0x938E8D8B87787472,0x716C6A696665635C},
}

func rotll(x uint64, s uint) uint64 {
	return (x<<s)|(x>>(32-s))
}

func arxl(x,y [4]uint64) (z [4]uint64) {
	// μ–transformation for X
	T6 := rotll(0xF0E8E4E2E1D8D4D2+x[0]+x[1]+x[2],7)
	T7 := rotll(0xD1CCCAC9C6C5C3B8+x[0]+x[1]+x[3],19)
	T4 := rotll(0xB4B2B1ACAAA9A6A5+x[0]+x[2]+x[3],31)
	T5 := rotll(0xA39C9A999695938E+x[1]+x[2]+x[3],53)
	r  := T4^T5^T6^T7
	T4 ^=r
	T5 ^=r
	T6 ^=r
	T7 ^=r
	
	// ν–transformation for Y
	T8 := rotll(0x8D8B87787472716C+y[0]+y[2]+y[3],11)
	T9 := rotll(0x6A696665635C5A59+y[1]+y[2]+y[3],23)
	T10:= rotll(0x5655534E4D4B473C+y[0]+y[1]+y[2],37)
	T11:= rotll(0x3A393635332E2D2B+y[0]+y[1]+y[3],59)
	r   = T8^T9^T10^T11
	T8 ^=r
	T9 ^=r
	T10^=r
	T11^=r
	
	// σ–transformation for both μ(X) and ν(Y)
	z[3] = T4+T8
	z[0] = T5+T9
	z[1] = T6+T10
	z[2] = T7+T11
	return
}

func e1l(C [4]uint64, I [8][4]uint64) (J [8][4]uint64) {
	J[0] = arxl(C,I[0])
	J[1] = arxl(J[0],I[1])
	J[2] = arxl(J[1],I[2])
	J[3] = arxl(J[2],I[3])
	J[4] = arxl(J[3],I[4])
	J[5] = arxl(J[4],I[5])
	J[6] = arxl(J[5],I[6])
	J[7] = arxl(J[6],I[7])
	return
}
func e2l(C [4]uint64, I [8][4]uint64) (J [8][4]uint64) {
	J[7] = arxl(I[7],C)
	J[6] = arxl(I[6],J[7])
	J[5] = arxl(I[5],J[6])
	J[4] = arxl(I[4],J[5])
	J[3] = arxl(I[3],J[4])
	J[2] = arxl(I[2],J[3])
	J[1] = arxl(I[1],J[2])
	J[0] = arxl(I[0],J[1])
	return
}

// 6 round 64-bit-Pi
func pil(I [8][4]uint64) ([8][4]uint64) {
	return (
	e2l(cl[5],
	e1l(cl[4],
	e2l(cl[3],
	e1l(cl[2],
	e2l(cl[1],
	e1l(cl[0],I)))))))
}
func zpi(in,out *[256]byte) {
	//var rw bwriter
	var V [8][4]uint64
	o := 0
	for i:=0;i<8;i++{
		for j:=0;j<4;j++{
			V[i][j] = binary.BigEndian.Uint64(in[o:])
			o+=8
		}
	}
	V = pil(V)
	o = 0
	for i:=0;i<8;i++{
		for j:=0;j<4;j++{
			binary.BigEndian.PutUint64(in[o:],V[i][j])
			o+=8
		}
	}
}

type PiCrypto struct{
	Len uint8 // 0 < Len < 256
	Off uint8 // 0 <= Off < Len
	State [256]byte
}

func (c *PiCrypto) Construct(l int) error{
	if !((0<l)&&(l<256)) { return fmt.Errorf("Must be 0 < size < 256 : %d",l) }
	c.Len = uint8(l)
	c.Off = 0
	for i:=0 ; i<256 ; i++ {
		c.State[i] = 0
	}
	return nil
}

func (c *PiCrypto) Write(p []byte) (n int, err error) {
	for _,b := range p {
		if c.Off>=c.Len {
			zpi(&c.State,&c.State)
			c.Off = 0
		}
		c.State[c.Off] ^= b
		c.Off++
	}
	return len(p),nil
}

func (c *PiCrypto) Read(p []byte) (n int, err error) {
	for i := range p {
		if c.Off>=c.Len {
			zpi(&c.State,&c.State)
			c.Off = 0
		}
		p[i] = c.State[c.Off]
		c.Off++
	}
	return len(p),nil
}

func (c *PiCrypto) CloneCipher() *PiCrypto {
	d := new(PiCrypto)
	*d = *c
	return d
}

func (c *PiCrypto) Pad() {
	if c.Off > 0 {
		zpi(&c.State,&c.State)
		c.Off = 0
	}
}

func (c *PiCrypto) Sum(b []byte) []byte {
	c.Pad()
	return append(b,c.State[:c.Len]...)
}

func (c *PiCrypto) Encrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off>=c.Len {
			zpi(&c.State,&c.State)
			c.Off = 0
		}
		c.State[c.Off] ^= b
		dst[i] = c.State[c.Off]
		c.Off++
	}
}

func (c *PiCrypto) Decrypt(dst,src []byte) {
	for i,b := range src {
		if c.Off>=c.Len {
			zpi(&c.State,&c.State)
			c.Off = 0
		}
		dst[i] = c.State[c.Off] ^ b
		c.State[c.Off] = b
		c.Off++
	}
}

func (c *PiCrypto) Reset() {
	for i := 0; i<256 ; i++ { c.State[i] = 0 }
	c.Off = 0
	c.Len = 0
}

func (c *PiCrypto) Size() int { return int(c.Len) }

func (c *PiCrypto) BlockSize() int { return int(c.Len) }

type PiEncrypter struct{
	PiCrypto
}

func (c *PiEncrypter) XORKeyStream(dst, src []byte) {
	c.Encrypt(dst,src)
}

type PiDecrypter struct{
	PiCrypto
}

func (c *PiDecrypter) XORKeyStream(dst, src []byte) {
	c.Decrypt(dst,src)
}

type PiMac struct{
	PiCrypto
	Bak PiCrypto
}
func (m *PiMac) Construct(l int, key []byte) error{
	e := m.Bak.Construct(l)
	if e!=nil { return e }
	m.Bak.Write(key)
	m.Reset()
	return nil
}

func (m *PiMac) Reset() {
	m.PiCrypto = m.Bak
}

