package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-trading-signal/libs/errs"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"gitlab.com/bshadmehr76/vgang-auth/app"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/mocks/service"
)

var router *mux.Router
var ah app.AuthHandler
var mockService *service.MockAuthService

func setup(t *testing.T) func() {
	ctrl := gomock.NewController(t)
	mockService = service.NewMockAuthService(ctrl)

	ah = app.AuthHandler{mockService}
	router = mux.NewRouter()
	router.HandleFunc("/login", ah.Login)
	router.HandleFunc("/signup", ah.Signup)
	router.HandleFunc("/get_otp", ah.GetOtp)
	router.HandleFunc("/forget_pass", ah.ForgetPassword)
	router.HandleFunc("/change_pass", ah.ChangePassword)
	router.HandleFunc("/logout", ah.Logout)
	router.HandleFunc("/verify", ah.Verify)

	return func() {
		router = nil
		defer ctrl.Finish()
	}
}
func Test_handler_login_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	loginResponse := dto.LoginResponse{AccessToken: "sample-token"}
	mockService.EXPECT().Login(dto.LoginRequest{Email: "sample@sample.com", Password: "123456aA$"}).Return(&loginResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"email":    "sample@sample.com",
		"password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/login", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing login handler")
	}
}

func Test_handler_login_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().Login(dto.LoginRequest{Email: "sample@sample.com", Password: "123456aA$"}).Return(nil, errs.NewUnexpectedError("Database error!"))

	postBody, _ := json.Marshal(map[string]string{
		"email":    "sample@sample.com",
		"password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/login", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing login handler")
	}
}

func Test_handler_signup_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	signupServiceResponse := dto.SignupResponse{UserID: 1, Email: "sample@sample.com", Name: "Sample Sample"}
	mockService.EXPECT().Signup(dto.SignupRequest{Email: "sample@sample.com", Password: "123456aA$", Name: "Sample Sample"}).Return(&signupServiceResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"email":    "sample@sample.com",
		"password": "123456aA$",
		"name":     "Sample Sample",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/signup", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing signup handler")
	}

	var signupResponse dto.SignupResponse

	if err := json.NewDecoder(recorder.Body).Decode(&signupResponse); err != nil {
		t.Error("Error while parsing signup response")
	}
	if signupResponse.Email != "sample@sample.com" {
		t.Error("Signup error wrong email ", signupResponse.Email)
	}
	if signupResponse.Name != "Sample Sample" {
		t.Error("Signup error wrong name " + signupResponse.Name)
	}
	if signupResponse.UserID != 1 {
		t.Error("Signup error wrong user_id")
	}
}

func Test_handler_signup_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().Signup(dto.SignupRequest{Email: "sample@sample.com", Password: "123456aA$", Name: "Sample Sample"}).Return(nil, errs.NewUnexpectedError("Database error!"))

	postBody, _ := json.Marshal(map[string]string{
		"email":    "sample@sample.com",
		"password": "123456aA$",
		"name":     "Sample Sample",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/signup", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing signup handler")
	}
}

func Test_handler_get_otp_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	getOtpServiceResponse := dto.GetOtpResponse{Success: true}
	mockService.EXPECT().GetOtp(dto.GetOtpRequest{Email: "sample@sample.com"}).Return(&getOtpServiceResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"email": "sample@sample.com",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/get_otp", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing get_otp handler")
	}
}

func Test_handler_get_otp_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().GetOtp(dto.GetOtpRequest{Email: "sample@sample.com"}).Return(nil, errs.NewUnexpectedError("Sample error"))

	postBody, _ := json.Marshal(map[string]string{
		"email": "sample@sample.com",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/get_otp", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing get_otp handler")
	}
}

func Test_handler_forget_pass_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	forgetPassServiceResponse := dto.ForgetPassResponse{Success: true, AccessToken: "sample-token"}
	mockService.EXPECT().ForgetPass(dto.ForgetPassRequest{Email: "sample@sample.com", Otp: "123456", NewPass: "123456aA$"}).Return(&forgetPassServiceResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"email":        "sample@sample.com",
		"otp":          "123456",
		"new_password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/forget_pass", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing forget_pass handler")
	}
}

func Test_handler_forget_pass_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().ForgetPass(dto.ForgetPassRequest{Email: "sample@sample.com", Otp: "123456", NewPass: "123456aA$"}).Return(nil, errs.NewUnexpectedError("Sample error"))

	postBody, _ := json.Marshal(map[string]string{
		"email":        "sample@sample.com",
		"otp":          "123456",
		"new_password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/forget_pass", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing get_otp handler")
	}
}

func Test_handler_change_pass_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	u := domain.User{}

	changePassServiceResponse := dto.ChangePassResponse{Success: true, AccessToken: "sample-token"}
	mockService.EXPECT().ChangePassword(dto.ChangePassRequest{OldPass: "123456aA$", NewPass: "123456aA$"}, &u).Return(&changePassServiceResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"old_password": "123456aA$",
		"new_password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/change_pass", responseBody)

	ctx := context.WithValue(request.Context(), "user", &u)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request.WithContext(ctx))

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing change_pass handler" + recorder.Body.String())
	}
}

func Test_handler_change_pass_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	u := domain.User{}

	mockService.EXPECT().ChangePassword(dto.ChangePassRequest{OldPass: "123456aA$", NewPass: "123456aA$"}, &u).Return(nil, errs.NewUnexpectedError("Sample error"))

	postBody, _ := json.Marshal(map[string]string{
		"old_password": "123456aA$",
		"new_password": "123456aA$",
	})
	responseBody := bytes.NewBuffer(postBody)
	request, _ := http.NewRequest(http.MethodGet, "/change_pass", responseBody)

	ctx := context.WithValue(request.Context(), "user", &u)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request.WithContext(ctx))

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing change_pass handler")
	}
}

func Test_handler_logout_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	logoutServiceResponse := dto.LogoutResponse{Status: true}
	mockService.EXPECT().Logout(domain.AccessToken{AccessToken: "sample-token"}).Return(&logoutServiceResponse, nil)

	request, _ := http.NewRequest(http.MethodGet, "/logout", nil)
	request.Header.Set("Authorization", "sample-token")

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing logout handler" + recorder.Body.String())
	}
}

func Test_handler_logout_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().Logout(domain.AccessToken{AccessToken: "sample-token"}).Return(nil, errs.NewUnexpectedError("Sample error"))

	request, _ := http.NewRequest(http.MethodGet, "/logout", nil)
	request.Header.Set("Authorization", "sample-token")

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing logout handler")
	}
}

func Test_handler_verify_should_return_token_with_status_200(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	verifyServiceResponse := dto.VerifyTokenResponse{IsVerified: true}
	mockService.EXPECT().Verify(dto.VerifyTokenRequest{AccessToken: "sample-token", Route: "verify"}).Return(&verifyServiceResponse, nil)

	postBody, _ := json.Marshal(map[string]string{
		"token": "sample-token",
		"route": "verify",
	})
	responseBody := bytes.NewBuffer(postBody)

	request, _ := http.NewRequest(http.MethodGet, "/verify", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusOK {
		t.Error("Failed while testing verify handler" + recorder.Body.String())
	}
}

func Test_handler_verify_should_return_error_500(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	mockService.EXPECT().Verify(dto.VerifyTokenRequest{AccessToken: "sample-token", Route: "verify"}).Return(nil, errs.NewUnexpectedError("sample error"))

	postBody, _ := json.Marshal(map[string]string{
		"token": "sample-token",
		"route": "verify",
	})
	responseBody := bytes.NewBuffer(postBody)

	request, _ := http.NewRequest(http.MethodGet, "/verify", responseBody)

	// Act
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	// Assert
	if recorder.Code != http.StatusInternalServerError {
		t.Error("Failed while testing logout handler")
	}
}
