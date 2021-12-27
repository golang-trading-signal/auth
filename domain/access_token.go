package domain

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
)

type AccessToken struct {
	AccessToken  string
	RefreshToken string
	UserId       int64
	ExpiresAt    int64
}

type AccessTokenRepository interface {
	IsAuthorized(token AccessToken, route string, vars map[string]string) (bool, *jwt.MapClaims)
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

func (at AccessToken) IsExpired() bool {
	now := time.Now().UTC()
	expirationTime := time.Unix(at.ExpiresAt, 0)
	return now.After(expirationTime)
}
