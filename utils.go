package rsa

import (
	"bytes"
	"unsafe"
)

// converts string to byte slice without a memory allocation.
func string2bytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

// converts byte slice to string without a memory allocation.
func bytes2string(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// split the string by the specified size.
func stringSplit(s string, n int) string {
	substr, strings := "", ""
	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		substr = substr + string(r)
		if (i+1)%n == 0 {
			strings = strings + substr + "\n"
			substr = ""
		} else if (i + 1) == l {
			strings = strings + substr + "\n"
		}
	}
	return strings
}

// split the byte slice by the specified size.
func bytesSplit(buf []byte, size int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/size+1)
	for len(buf) >= size {
		chunk, buf = buf[:size], buf[size:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func leftPad(src []byte, size int) (dst []byte) {
	dst = make([]byte, size)
	copy(dst[len(dst)-len(src):], src)
	return
}

func leftUnPad(src []byte) (dst []byte) {
	n := len(src)
	t := 2
	for i := 2; i < n; i++ {
		if src[i] == 0xff {
			t = t + 1
		} else {
			if src[i] == src[0] {
				t = t + int(src[1])
			}
			break
		}
	}
	dst = make([]byte, n-t)
	copy(dst, src[t:])
	return
}
