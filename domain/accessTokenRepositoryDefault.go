package domain

import (
	"github.com/golang-jwt/jwt"
)

type AccessTokenRepositoryDefault struct {
}

func (r AccessTokenRepositoryDefault) IsAuthorized(token AccessToken, route string, vars map[string]string) (bool, *jwt.MapClaims) {
	publicApis := []string{"auth-login", "auth-signup", "auth-get_otp", "auth-forget_pass"}
	for _, r := range publicApis {
		if r == route {
			return true, nil
		}
	}

	if jwtToken, err := JwtTokenFromString(token.AccessToken); err != nil {
		return false, nil
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(jwt.MapClaims)
			return true, &claims
		}
	}

	return false, nil
}

func NewAccessTokenRepositoryDefault() AccessTokenRepositoryDefault {
	return AccessTokenRepositoryDefault{}
}
