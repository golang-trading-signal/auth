package domain

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
	"golang.org/x/crypto/bcrypt"
)

const (
	TOKEN_DURATION_MINUTES = 10
)

type User struct {
	Id        int64
	Email     string
	Name      string
	Password  string
	SecretKey string `db:"secret_key"`
}

type UserRepository interface {
	GetUserByUserEmail(string) (*User, *errs.AppError)
	CreateUser(string, string, string, string) (int64, *errs.AppError)
	UpdateUserPassword(string, string) *errs.AppError
}

func (u User) ValidateUserPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u User) GetJwtClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"user_id": u.Id,
		"email":   u.Email,
		"exp":     time.Now().Add(TOKEN_DURATION_MINUTES * time.Minute).Unix(),
	}
}

func (u User) HashPassword() (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
	return string(bytes), err
}

func (u User) SendUserOtp(otp string) {
	fmt.Println("You'r otp code is: " + otp)
}
