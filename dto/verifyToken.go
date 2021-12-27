package dto

type VerifyTokenRequest struct {
	AccessToken string `json:"otp"`
	Route       string `json:"route"`
}

type VerifyTokenResponse struct {
	Success bool `json:"success"`
}
