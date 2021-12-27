package dto

type ChangePassRequest struct {
	OldPass string `json:"old_password"`
	NewPass string `json:"new_password"`
}

type ChangePassResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
