package dto

import "gitlab.com/bshadmehr76/vgang-auth/domain"

type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type SignupResponse struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

func (r SignupRequest) ToDao() domain.User {
	return domain.User{
		Email:    r.Email,
		Password: r.Password,
		Name:     r.Name,
	}
}

func UserToSignupResponse(user domain.User) *SignupResponse {
	return &SignupResponse{
		UserID: user.Id,
		Email:  user.Email,
		Name:   user.Name,
	}
}
