package controllers

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
	"os"
)

func Verify_JWT(jwtToken string) (err error) {
	// verify jwt token
	secret := []byte(os.Getenv("secret"))
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid JWT")
	}
	return nil
}


func TokenGen(username string) (token string, err error) {
	tokenObj := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
	})
	secret := []byte(os.Getenv("secret"))
	token, err = tokenObj.SignedString(secret)
	return token, err
}