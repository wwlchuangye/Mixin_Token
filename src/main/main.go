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

	uid := "f969a140-4e28-4d81-84ba-a84339178136"
	sid := "1ecf84f4-e017-4321-bfa6-acb1cf7f3348"
	secret := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDCAzc13Gt1IDZcbnN1fdWkkYtKKSIblgydIs1tdQ1APLCBbDYM
t/7hk6oT+uGy8u/aCJhfz68qmBpL1YRSAjhXZ9euLj0E1L5ExGwIUXXE3EPc4Du8
iCUZ3BO12SVIyZjSxfg7t/HdSchWSta4LUT+OYM8KBReUqnxstzB+sbX8wIDAQAB
AoGARt+v2pAz/SyQT0HWEdSvKBg3HxdZq2QsJXciPlslRRMmk5D5SbopdTRhTD05
GAshTbAYIeAXqGK6MHvGg8Ll23xSPgqbkyMjF1s5kVO5axjETlNuzBOqPJihUs7r
8aLPiGm0+k17SfKaFfmNxZMLjDQK19V6JX9igqC3Mdg1dekCQQD6rxlF6Lj6UfT4
IIhSAqtD9CEnqopfPtUnTtMtqqdu5aPe64qm2FDcgwSNQL/mQAn/oSuWdO3uC7ua
kcXF6RFvAkEAxiB2OyZ6zx5CMXY2Ympl2C0ZCom8zLZRgcvwJqocmplmbbDp+EOy
ETQ/RxbXBjf/4AeZKvs6RTO4VSi6yxwXvQJBAN0gq7iBKvqUZPSjLdy5wf11UfG9
e8W8lSXRYHL+ACfQpZa0S2AVnG6Hm/JF1YDzqF43+00C5AaBjwEv6TdE+j0CQEIw
Og9MrZ5f13E6srRyIw/zEPiKRz6EcfpQrSvdjKzBLozam29K/kPtFm6jXLZBIwQu
xaasQy03OA+LCcws2GkCQQDsDtEQqE3Zw9p3lVHfFDlVs8G6UzY9w5RiHxSEEhW/
lUpnwey8w1r8iNc3ErsUAagDEqI4R6lD6i8Lq48ifPBe
-----END RSA PRIVATE KEY-----`
	method := "GET"
	uri := "https://baidu.com"
	body := "SPeshgiSPsPcwKnXCA4Du0R6jAl0adrg3FUIKo2kLwn/sHhE1cSJ76TFf0BNNaBmxGtnt3m4WBgHD8MzRJONnoNjF5rlxoeWskAGFXaioH3lZ9eQ2tcKZ0rJQNUSHejeHYdNcB1DAgKFR0kt6HYEexpG42g4hz1tvlyMj//tPdU="

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


	pin := "804747"
	sessionId := "1ecf84f4-e017-4321-bfa6-acb1cf7f3348"
	pinToken := "SPeshgiSPsPcwKnXCA4Du0R6jAl0adrg3FUIKo2kLwn/sHhE1cSJ76TFf0BNNaBmxGtnt3m4WBgHD8MzRJONnoNjF5rlxoeWskAGFXaioH3lZ9eQ2tcKZ0rJQNUSHejeHYdNcB1DAgKFR0kt6HYEexpG42g4hz1tvlyMj//tPdU="
	privateKey := `
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDCAzc13Gt1IDZcbnN1fdWkkYtKKSIblgydIs1tdQ1APLCBbDYM
t/7hk6oT+uGy8u/aCJhfz68qmBpL1YRSAjhXZ9euLj0E1L5ExGwIUXXE3EPc4Du8
iCUZ3BO12SVIyZjSxfg7t/HdSchWSta4LUT+OYM8KBReUqnxstzB+sbX8wIDAQAB
AoGARt+v2pAz/SyQT0HWEdSvKBg3HxdZq2QsJXciPlslRRMmk5D5SbopdTRhTD05
GAshTbAYIeAXqGK6MHvGg8Ll23xSPgqbkyMjF1s5kVO5axjETlNuzBOqPJihUs7r
8aLPiGm0+k17SfKaFfmNxZMLjDQK19V6JX9igqC3Mdg1dekCQQD6rxlF6Lj6UfT4
IIhSAqtD9CEnqopfPtUnTtMtqqdu5aPe64qm2FDcgwSNQL/mQAn/oSuWdO3uC7ua
kcXF6RFvAkEAxiB2OyZ6zx5CMXY2Ympl2C0ZCom8zLZRgcvwJqocmplmbbDp+EOy
ETQ/RxbXBjf/4AeZKvs6RTO4VSi6yxwXvQJBAN0gq7iBKvqUZPSjLdy5wf11UfG9
e8W8lSXRYHL+ACfQpZa0S2AVnG6Hm/JF1YDzqF43+00C5AaBjwEv6TdE+j0CQEIw
Og9MrZ5f13E6srRyIw/zEPiKRz6EcfpQrSvdjKzBLozam29K/kPtFm6jXLZBIwQu
xaasQy03OA+LCcws2GkCQQDsDtEQqE3Zw9p3lVHfFDlVs8G6UzY9w5RiHxSEEhW/
lUpnwey8w1r8iNc3ErsUAagDEqI4R6lD6i8Lq48ifPBe
-----END RSA PRIVATE KEY-----`
	var iterator uint64 = 100

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


