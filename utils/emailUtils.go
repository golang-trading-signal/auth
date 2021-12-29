package utils

import (
	"net/mail"

	"gitlab.com/bshadmehr76/vgang-auth/errs"
)

func ValidateEmail(email string) *errs.AppError {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errs.NewBadRequestError("Invalid email address")
	}
	return nil
}
