package dto

type GetOtpRequest struct {
	Email string `json:"email"`
}

type GetOtpResponse struct {
	Success bool `json:"success"`
}
