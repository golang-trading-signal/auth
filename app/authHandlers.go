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
		utils.WriteResponse(w, http.StatusBadRequest, err.Error())
	} else {
		token, err := ah.service.Login(loginRequest)
		if err != nil {
			utils.WriteResponse(w, err.Code, err.AsMessage())
		} else {
			utils.WriteResponse(w, http.StatusOK, token)
		}
	}
}

func (ah AuthHandler) signup(w http.ResponseWriter, r *http.Request) {
	var signupRequest dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error())
	} else {
		token, err := ah.service.Signup(signupRequest)
		if err != nil {
			utils.WriteResponse(w, err.Code, err.AsMessage())
		} else {
			utils.WriteResponse(w, http.StatusOK, token)
		}
	}
}

func (ah AuthHandler) GetOtp(w http.ResponseWriter, r *http.Request) {
	var getOtpRequest dto.GetOtpRequest
	if err := json.NewDecoder(r.Body).Decode(&getOtpRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error())
	} else {
		response, err := ah.service.GetOtp(getOtpRequest)
		if err != nil {
			utils.WriteResponse(w, err.Code, err.AsMessage())
		} else {
			utils.WriteResponse(w, http.StatusOK, response)
		}
	}
}

func (ah AuthHandler) forgetPassword(w http.ResponseWriter, r *http.Request) {
	var forgetPasswordRequest dto.ForgetPassRequest
	if err := json.NewDecoder(r.Body).Decode(&forgetPasswordRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error())
	} else {
		response, err := ah.service.ForgetPass(forgetPasswordRequest)
		if err != nil {
			utils.WriteResponse(w, err.Code, err.AsMessage())
		} else {
			utils.WriteResponse(w, http.StatusOK, response)
		}
	}
}

func (ah AuthHandler) changePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		err := errs.NewUnexpectedError("Error eccured when trying to get the user")
		utils.WriteResponse(w, err.Code, err.AsMessage())
		return
	}

	var changePAsswordRequest dto.ChangePassRequest
	if err := json.NewDecoder(r.Body).Decode(&changePAsswordRequest); err != nil {
		utils.WriteResponse(w, http.StatusBadRequest, err.Error())
	} else {
		response, err := ah.service.ChangePassword(changePAsswordRequest, user)
		if err != nil {
			utils.WriteResponse(w, err.Code, err.AsMessage())
		} else {
			utils.WriteResponse(w, http.StatusOK, response)
		}
	}
}

func (ah AuthHandler) verify(w http.ResponseWriter, r *http.Request) {

}
