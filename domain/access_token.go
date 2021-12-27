package domain

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
	"gitlab.com/bshadmehr76/vgang-auth/logger"
)

type AccessToken struct {
	AccessToken  string
	RefreshToken string
	UserId       int64
	ExpiresAt    int64
}

type AccessTokenRepository interface {
	IsAuthorized(token AccessToken, route string, vars map[string]string) (bool, *jwt.MapClaims)
	Logout(token AccessToken) *errs.AppError
}

func (at AccessToken) GetExpiresAt() int64 {
	return time.Now().Add(time.Minute * 10).Unix()
}

func (at AccessToken) GetefreshTokenExpiresAt() int64 {
	return time.Now().Add(time.Minute * 10).Unix()
}

func GetNewAccessToken(claims jwt.MapClaims) (*AccessToken, *errs.AppError) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedTokenAsString, err := token.SignedString([]byte(os.Getenv("HMAC_SECRET")))
	if err != nil {
		err := errs.NewUnexpectedError("Error while creating access token")
		return nil, err
	}
	return &AccessToken{
		AccessToken:  signedTokenAsString,
		RefreshToken: "",
	}, nil
}

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
