package utils

import (
	"os"

	"github.com/golang-jwt/jwt"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
	"gitlab.com/bshadmehr76/vgang-auth/logger"
)

func JwtTokenFromString(tokenString string) (*jwt.Token, *errs.AppError) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("HMAC_SECRET")), nil
	})

	if err != nil {
		logger.Error(err.Error())
		return nil, errs.NewUnexpectedError("Erro whie trying to decode the token")
	}

	return token, nil
}
