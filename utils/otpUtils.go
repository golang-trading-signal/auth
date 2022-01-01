package utils

import (
	"time"

	"github.com/golang-trading-signal/libs/errs"
	"github.com/pquerna/otp/totp"
)

const (
	OTP_PERIOD_MINUTES = 5
)

func GenerateNewOtp(secret string) (string, *errs.AppError) {
	if secret == "" {
		return "", errs.NewUnexpectedError("User secret key is invalid")
	}
	key, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", errs.NewUnexpectedError("An error eccured while trying to create a secret key")
	}
	return key, nil
}

func ValidateOtp(otp string, secret string) bool {
	return totp.Validate(otp, secret)
}

func GetNewSecretForEmail(email string) (string, *errs.AppError) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "vgang.com",
		AccountName: email,
	})
	if err != nil {
		return "", errs.NewUnexpectedError("Error eccured while trying to generate a key for user")
	}
	return key.Secret(), nil
}
