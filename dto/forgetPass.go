package dto

type ForgetPassRequest struct {
	Email   string `json:"email"`
	Otp     string `json:"otp"`
	NewPass string `json:"new_password"`
}

type ForgetPassResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
