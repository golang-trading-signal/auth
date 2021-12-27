package app

import (
	"encoding/json"
	"net/http"

	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
	"gitlab.com/bshadmehr76/vgang-auth/service"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

type AuthHandler struct {
	service service.AuthService
}

func (ah AuthHandler) login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		token, err := ah.service.Login(loginRequest)
		utils.WriteResponse(w, http.StatusOK, token, err)
	}
}

func (ah AuthHandler) signup(w http.ResponseWriter, r *http.Request) {
	var signupRequest dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		token, err := ah.service.Signup(signupRequest)
		utils.WriteResponse(w, http.StatusOK, token, err)
	}
}

func (ah AuthHandler) GetOtp(w http.ResponseWriter, r *http.Request) {
	var getOtpRequest dto.GetOtpRequest
	if err := json.NewDecoder(r.Body).Decode(&getOtpRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.service.GetOtp(getOtpRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) forgetPassword(w http.ResponseWriter, r *http.Request) {
	var forgetPasswordRequest dto.ForgetPassRequest
	if err := json.NewDecoder(r.Body).Decode(&forgetPasswordRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error(), nil)
	} else {
		response, err := ah.service.ForgetPass(forgetPasswordRequest)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) changePassword(w http.ResponseWriter, r *http.Request) {
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
		response, err := ah.service.ChangePassword(changePAsswordRequest, user)
		utils.WriteResponse(w, http.StatusOK, response, err)
	}
}

func (ah AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := domain.AccessToken{AccessToken: authHeader}
	response, err := ah.service.Logout(token)
	utils.WriteResponse(w, http.StatusOK, response, err)
}

func (ah AuthHandler) verify(w http.ResponseWriter, r *http.Request) {

}
