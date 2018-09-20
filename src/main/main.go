package main

import (
	"fmt"
	"time"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"crypto/cipher"
	"crypto/aes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/binary"
	"github.com/dgrijalva"
	"uuid"
	//"log"
	//"sort"
	"io"
	"bytes"
)




var ClientId = "a14100ad-9346-48cb-b3b3-a61dfb9857da"
var ClientSecret = "82cc69fa9a1924f24e68ed749b81bfcc2db7cc6adea0b0aa6281123bc756b321"

var PinCode = "161969";

var SessionId = "51a6612e-47dd-46dd-96c2-97877588a955"

var PinToken = "X6QzcO480NVZPNL1Kvzn/omfAPVDUZZrreAWJo5TJ2qR273dxZ0w4yjhRX4e0ABp+Wykyufd4cldzAo795AdKbmQXQ4lVL9wcuqsrGMvYVMXalPygqCqjlzHbBfGHkJ2NP2WMUHUUJ3Np/V00e50kGqa8Ze2yQrX+UhFVZ2S06k="

var PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCKhzIeYSUdYhirtxQfBiIx6J8+cgZ6thpJV2Jf+gxJuZPpaVXY
hmHKU46gbsVYzlYWJngjsN8XdqVuk6drSX4ZTDG+jFtPZ8ENH/46BmtdDefSr0r2
mLwT4jPKg42F9euZG8EDBl2IAdoixQct4D/gczysX1uh/7fi5yK05v5CLwIDAQAB
AoGATf85NOm1oAmvol9+sMkfT8KOhvZkt4r42fqdpTSA3rHimjV45GUlgmnxkFtO
OmZTCj22v0HDGs7u7oesaDgFCxyW/MAYrmDlTSxdkFRIjNesio5bXAePu8xBMZD8
ldM0ZwFyZdbT+8AOol7GJlMFMA4CgBi+7F0HG7CHs9jTl0ECQQDMfdLWqqt3EToq
OZhQgHSoN//noOfAS7z0/VN4xwyUassFh7XgGwNyVSX8B9r7iV+TwrXXj1fdBqnS
/CpqCzC5AkEArWve5TBxXhULT2JALpJKxZVjpWgbF0u2jjceTtxLXygZOQqL4p5p
AQDSZmxgWCi7Sy/TisYtP1WrIvIlI5GGJwJASgfrQof7F1oHQq4jNFGs6hGL9aFN
BVLmD5N+mqUFKt4WrePZtk5RSx0EaV+2qYWsMmQ1TNq6Jmx5Isbj3Aw9EQJATaK7
70hniCHNpWUrrG2rcZa2PEdF0YEAodwFAnLWfyv5VrLk+rfF9EAE8PtVikH5zugD
QN4FRZQ5f/R9MdYlAwJAe1HUiNboziXYftkwtoGfGbniROePHbifkg5aDBKUtWrF
MqKiGhNuYq+4IRwlXSzFyL+ljvwYT2tBEjfIrd7qPQ==
-----END RSA PRIVATE KEY-----`

var homeurl = "http://diaoyudaren.qlgame.net:8080"



func main() {

	fmt.Println("start => ")



	signToken()
	ePin();
}



func signToken (){


	//uid: ClientId or Bear User Id
	//sid: SessionId or Bear User SessionId
	//privateKey: PrivateKey
	//method: HTTP Request method, e.g.: GET, POST
	//url: URL path without hostname, e.g.: /transfers
	//body: HTTP Request body, e.g.: {"pin": "encrypted pin token"}

	uid := ClientId
	sid := SessionId
	secret := PrivateKey
	method := "GET"
	uri := homeurl
	body := `{"pin": "`+PinToken+`"}`


	var AuthenticationToken, err = SignAuthenticationToken(uid,sid,secret,method,uri,body);
	if(err != nil){
		fmt.Println("AuthenticationToken==Err=: ", err)
	}else
	{
		fmt.Println("AuthenticationToken===: ", AuthenticationToken)
	}


}
//
func SignAuthenticationToken(uid, sid, secret, method, uri, body string) (string, error) {


	expire := time.Now().UTC().Add(time.Hour * 24 * 30 * 3)
	sum := sha256.Sum256([]byte(method + uri + body))
	var wwluuid, errr = uuid.NewV4();

	fmt.Println("wwluuid  ",wwluuid, errr, expire.Unix(), time.Now().UTC().Unix(), sum[:], hex.EncodeToString(sum[:]))

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"uid": uid,
		"sid": sid,
		"iat": time.Now().UTC().Unix(),
		"exp": expire.Unix(),
		"jti": wwluuid.String(),
		"sig": hex.EncodeToString(sum[:]),
	})

	block, _ := pem.Decode([]byte(secret))
	fmt.Println("block==", block, []byte(secret));


	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	return token.SignedString(key)

}

func ePin (){

	//pin: PinCode e.g.: 1234
	//pinToken: PinToken
	//sessionId: SessionId
	//key: PrivateKey
	//iterator: must be bigger than the previous, the first time must be greater than 0. After a new session created, it will be reset to 0.


	pin := PinCode
	sessionId := SessionId
	pinToken := PinToken
	privateKey := PrivateKey
	var iterator uint64 = 101

	var encPin = EncryptPIN(pin, pinToken, sessionId, privateKey, iterator)
	fmt.Println("EncryptPIN : ", encPin)
}

func EncryptPIN(pin, pinToken, sessionId, privateKey string, iterator uint64) string {
	keyBlock, _ := pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return ""
	}
	token, _ := base64.StdEncoding.DecodeString(pinToken)
	keyBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, token, []byte(sessionId))
	if err != nil {
		return ""
	}
	pinByte := []byte(pin)
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	pinByte = append(pinByte, timeBytes...)
	iteratorBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(iteratorBytes, iterator)
	pinByte = append(pinByte, iteratorBytes...)
	padding := aes.BlockSize - len(pinByte)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	pinByte = append(pinByte, padtext...)
	block, _ := aes.NewCipher(keyBytes)
	ciphertext := make([]byte, aes.BlockSize+len(pinByte))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], pinByte)
	return base64.StdEncoding.EncodeToString(ciphertext)
}


