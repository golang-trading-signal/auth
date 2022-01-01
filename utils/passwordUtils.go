package utils

import (
	"unicode"

	"github.com/golang-trading-signal/libs/errs"
)

func ValidatePassword(p string) *errs.AppError {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	if len(p) >= 7 {
		hasMinLen = true
	}
	for _, char := range p {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasMinLen {
		return errs.NewBadRequestError("Password length should be more than 6")
	}

	if !hasUpper {
		return errs.NewBadRequestError("Password should contain at least one upper case character")
	}

	if !hasLower {
		return errs.NewBadRequestError("Password should contain at least one lower case character")
	}

	if !hasNumber {
		return errs.NewBadRequestError("Password should contain at least one number")
	}

	if !hasSpecial {
		return errs.NewBadRequestError("Password should contain at least one special character")
	}

	return nil
}
