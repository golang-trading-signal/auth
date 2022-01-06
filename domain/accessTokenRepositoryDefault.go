package domain

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/golang-trading-signal/libs/errs"
	"github.com/golang-trading-signal/libs/logger"
)

var ctx = context.Background()

type AccessTokenRepositoryDefault struct {
	redis *redis.Client
}

func (r AccessTokenRepositoryDefault) IsAuthorized(token AccessToken, route string, vars map[string]string) (bool, *jwt.MapClaims) {
	publicApis := []string{"auth-login", "auth-signup", "auth-get_otp", "auth-forget_pass", "auth-verify", "auth-refresh"}
	for _, r := range publicApis {
		if r == route {
			return true, nil
		}
	}

	val, err := r.redis.Get(ctx, token.AccessToken).Result()
	if err != nil {
		logger.Error(err.Error())
	}
	if val != "" {
		return false, nil
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

func (r AccessTokenRepositoryDefault) Logout(token AccessToken) *errs.AppError {
	if token.AccessToken != "" {
		err := r.redis.Set(ctx, token.AccessToken, token.GetExpiresAt(), time.Hour).Err()
		if err != nil {
			logger.Error("Error while trying to add token to redis: " + err.Error())
			err := errs.NewUnexpectedError("Error while trying to add token to redis")
			return err
		}
	}

	if token.RefreshToken != "" {
		err := r.redis.Set(ctx, token.AccessToken, token.GetefreshTokenExpiresAt(), time.Hour).Err()
		if err != nil {
			logger.Error("Error while trying to add refresh token to redis: " + err.Error())
			err := errs.NewUnexpectedError("Error while trying to add refresh token to redis")
			return err
		}
	}

	return nil
}

func NewAccessTokenRepositoryDefault(redis *redis.Client) AccessTokenRepositoryDefault {
	return AccessTokenRepositoryDefault{redis}
}
