package dto

type VerifyTokenRequest struct {
	AccessToken string `json:"token"`
	Route       string `json:"route"`
}

type VerifyTokenResponse struct {
	IsVerified bool `json:"is_verified"`
}
