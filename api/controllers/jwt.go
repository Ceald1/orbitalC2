package controllers

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
	"os"
)

type UserClaims struct {
	Username string `json:"username"`
    jwt.RegisteredClaims
}

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

func TokenDecode(tokenString string, secretKey []byte) (string, error) {
    // Parse the token with your custom claims type
    token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Check the signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return secretKey, nil
    })

    if err != nil {
        return "", err
    }

    // Type assert to UserClaims
    if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
        return claims.Username, nil
    }

    return "", fmt.Errorf("invalid token")
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

func VerifyAdmin(jwtToken string) (err error) {
	// err = Verify_JWT(jwtToken)
	// if err != nil {
	// 	return err
	// }
	secret := []byte(os.Getenv("secret"))
	username, err := TokenDecode(jwtToken,secret )
	if err != nil {
		return
	}
	if username != "admin" {
		return fmt.Errorf("invalid admin token")
	}
	return nil
	
}