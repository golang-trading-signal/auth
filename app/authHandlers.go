package app

import (
	"encoding/json"
	"net/http"

	"github.com/golang-trading-signal/libs/errs"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/service"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

type AuthHandler struct {
	Service service.AuthService
}

func (ah AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		token, err := ah.Service.Login(loginRequest)
		utils.WriteResponse(w, http.StatusOK, token, err)
	}
}

func (ah AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var signupRequest dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		token, err := ah.Service.Signup(signupRequest)
		utils.WriteResponse(w, http.StatusOK, token, err)
	}
}

func (ah AuthHandler) GetOtp(w http.ResponseWriter, r *http.Request) {
	var getOtpRequest dto.GetOtpRequest
	if err := json.NewDecoder(r.Body).Decode(&getOtpRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.Service.GetOtp(getOtpRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) ForgetPassword(w http.ResponseWriter, r *http.Request) {
	var forgetPasswordRequest dto.ForgetPassRequest
	if err := json.NewDecoder(r.Body).Decode(&forgetPasswordRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.Service.ForgetPass(forgetPasswordRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		err := errs.NewUnexpectedError("Error eccured when trying to get the user")
		utils.WriteResponse(w, 0, nil, err)
		return
	}

	var changePAsswordRequest dto.ChangePassRequest
	if err := json.NewDecoder(r.Body).Decode(&changePAsswordRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.Service.ChangePassword(changePAsswordRequest, user)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := domain.AccessToken{AccessToken: authHeader}
	response, err := ah.Service.Logout(token)
	utils.WriteResponse(w, http.StatusOK, response, err)
}

func (ah AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var verifyRequest dto.VerifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&verifyRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.Service.Verify(verifyRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}

}

func (ah AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.Service.Refresh(refreshRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}

}
