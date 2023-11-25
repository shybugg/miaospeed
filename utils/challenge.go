package utils

import (
	"crypto/sha512"
	"encoding/base64"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/miaokobot/miaospeed/interfaces"
)

// aws-v4-signature-like signing method
func hashMiaoSpeed(token, request string) string {
	buildTokens := append([]string{token}, strings.Split(strings.TrimSpace(BUILDTOKEN), "|")...)

	hasher := sha512.New()
	hasher.Write([]byte(request))

	for _, t := range buildTokens {
		if t == "" {
			// unsafe, plase make sure not to let token segment be empty
			t = "SOME_TOKEN"
		}

		hasher.Write(hasher.Sum([]byte(t)))
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

//func hashMd5(token string) string {
//	hasher := md5.New()
//	hasher.Write([]byte(token))
//	return hex.EncodeToString(hasher.Sum(nil))
//}

func SignRequest(token string, req *interfaces.SlaveRequest) string {
	awaitSigned := req.Clone()
	awaitSigned.Challenge = ""
	awaitSigned.Configs.Scripts = nil // 这个地方为FullTClash独家修改，因为json反序列化很容易将主端发送过来的数据改动，所以只好置为空
	awaitSignedStr, _ := jsoniter.MarshalToString(&awaitSigned)
	awaitSignedStr = strings.TrimSpace(awaitSignedStr)
	return hashMiaoSpeed(token, awaitSignedStr)
}
