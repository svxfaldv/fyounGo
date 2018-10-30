package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func encode(urlstring string) string {
	u, _ := url.Parse(urlstring)
	q := u.Query()
	u.RawQuery = q.Encode()
	return u.String()
}

func newClient(timeoutSecond time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(netw, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(netw, addr, time.Second*timeoutSecond)
			return c, err
		},
		// MaxIdleConnsPerHost:   10,
		// ResponseHeaderTimeout: time.Second * 2,
	}
	client := &http.Client{Transport: tr}

	return client
}

func md5f(text string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(text))
	cipherStr := md5Ctx.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(cipherStr))
}

func DecryptDES_ECB(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out, nil
}

//明文减码算法
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func RandInt64(min,max int64) int64{
	maxBigInt:=big.NewInt(max)
	i,_:=rand.Int(rand.Reader,maxBigInt)
	if i.Int64()<min{
		RandInt64(min,max)
	}
	return i.Int64()
}

func exit() {
	fmt.Println("Press any key to exit.")
	var e byte
	fmt.Scanf("%b", &e)
	os.Exit(0)
}
