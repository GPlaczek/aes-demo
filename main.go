package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"crypto/aes"
	"crypto/cipher"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/connesc/cipherio"
)

const (
	BUF_SIZE = 4096
)

type CBCEncrypter struct {
	ecb  cipher.BlockMode
	blk  []byte
	work []byte
}

func (c *CBCEncrypter) BlockSize() int {
	return c.ecb.BlockSize()
}

func (c *CBCEncrypter) CryptBlocks(dst, src []byte) {
	bs := c.BlockSize()
	if len(src)%bs != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		for i := 0; i < bs; i++ {
			c.work[i] = c.blk[i] ^ src[i]
		}
		c.ecb.CryptBlocks(c.blk, c.work)
		for i := 0; i < bs; i++ {
			dst[i] = c.blk[i]
		}
		src = src[bs:]
		dst = dst[bs:]
	}
}

type CBCDecrypter struct {
	ecb  cipher.BlockMode
	blk  []byte
	work []byte
}

func (c *CBCDecrypter) BlockSize() int {
	return c.ecb.BlockSize()
}

func (c *CBCDecrypter) CryptBlocks(dst, src []byte) {
	bs := c.BlockSize()
	if len(src)%bs != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		c.ecb.CryptBlocks(c.work, src[:bs])
		for i := 0; i < bs; i++ {
			tmp := src[i]
			dst[i] = c.blk[i] ^ c.work[i]
			c.blk[i] = tmp
		}

		src = src[bs:]
		dst = dst[bs:]
	}
}

func NewCBCEncrypter(cphr cipher.Block, iv []byte) cipher.BlockMode {
	bs := cphr.BlockSize()
	work := make([]byte, bs)
	blk := make([]byte, 0, bs)
	blk = append(blk, iv...)

	ecb := ecb.NewECBEncrypter(cphr)

	return &CBCEncrypter{
		ecb,
		blk,
		work,
	}
}

func NewCBCDecrypter(cphr cipher.Block, iv []byte) cipher.BlockMode {
	bs := cphr.BlockSize()
	work := make([]byte, bs)
	blk := make([]byte, 0, bs)
	blk = append(blk, iv...)

	ecb := ecb.NewECBDecrypter(cphr)

	return &CBCDecrypter{
		ecb,
		blk,
		work,
	}
}

type byteArray []byte

func (b *byteArray) String() string {
	return string(*b)
}

func (b *byteArray) Set(s string) error {
	*b = []byte(s)
	return nil
}

func EcbReader(decrypt bool, stream io.Reader, cphr cipher.Block) io.Reader {
	var bm cipher.BlockMode
	if decrypt {
		bm = ecb.NewECBDecrypter(cphr)
	} else {
		bm = ecb.NewECBEncrypter(cphr)
	}
	return cipherio.NewBlockReaderWithPadding(stream, bm, cipherio.ZeroPadding)
}

func OfbReader(iv []byte, stream io.Reader, cphr cipher.Block) io.Reader {
	ofb := cipher.NewOFB(cphr, iv)
	return cipher.StreamReader{
		S: ofb,
		R: stream,
	}
}

func CfbReader(decrypt bool, iv []byte, stream io.Reader, cphr cipher.Block) io.Reader {
	var cfb cipher.Stream
	if decrypt {
		cfb = cipher.NewCFBDecrypter(cphr, iv)
	} else {
		cfb = cipher.NewCFBEncrypter(cphr, iv)
	}
	return cipher.StreamReader{
		S: cfb,
		R: stream,
	}
}

func CbcReader(decrypt bool, iv []byte, stream io.Reader, cphr cipher.Block) io.Reader {
	var bm cipher.BlockMode
	if decrypt {
		// bm = cipher.NewCBCDecrypter(cphr, iv)
		bm = NewCBCDecrypter(cphr, iv)
	} else {
		// bm = cipher.NewCBCEncrypter(cphr, iv)
		bm = NewCBCEncrypter(cphr, iv)
	}
	return cipherio.NewBlockReaderWithPadding(stream, bm, cipherio.ZeroPadding)
}

func CtrReader(iv []byte, stream io.Reader, cphr cipher.Block) io.Reader {
	ctr := cipher.NewCTR(cphr, iv)
	return cipher.StreamReader{
		S: ctr,
		R: stream,
	}
}

func main() {
	var iv byteArray = []byte("0123456789abcdef")
	var key byteArray = nil
	var mode string
	var decrypt bool = false
	var stream io.Reader

	flag.Var(&key, "key", "What key to use")
	flag.StringVar(&mode, "mode", "ecb", "What mode to use")
	flag.BoolVar(&decrypt, "decrypt", false, "Whether to decrypt stream")
	flag.Var(&iv, "initial-value", "Initial value")

	flag.Parse()

	positionals := flag.Args()
	switch len(positionals) {
	case 0:
		stream = os.Stdin
	case 1:
		s, err := os.Open(positionals[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open %s\n", positionals[0])
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		stream = s
	default:
		fmt.Fprintln(os.Stderr, "Too many files specified")
		os.Exit(1)
	}

	if key == nil {
		fmt.Fprintln(os.Stderr, "No key specified")
		flag.PrintDefaults()
		os.Exit(1)
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create aes instance: %s\n", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var ostream io.Reader
	switch mode {
	case "ecb":
		ostream = EcbReader(decrypt, stream, aes)
	case "ofb":
		ostream = OfbReader(iv, stream, aes)
	case "cfb":
		ostream = CfbReader(decrypt, iv, stream, aes)
	case "cbc":
		ostream = CbcReader(decrypt, iv, stream, aes)
	case "ctr":
		ostream = CtrReader(iv, stream, aes)
	default:
		fmt.Fprintln(os.Stderr, "Invalid mode")
		os.Exit(1)
	}

	buf := make([]byte, 256)

	for {
		len, err := ostream.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "read error %s\n", err)
			os.Exit(1)
		}
		if len == 0 {
			return
		}
		_, err = os.Stdout.Write(buf[0:len])
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "write error %s\n", err)
			os.Exit(1)
		}
	}
}
