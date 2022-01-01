package service_test

import (
	"testing"

	"github.com/golang-trading-signal/libs/errs"
	"github.com/golang/mock/gomock"
	mainDomain "gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/mocks/domain"
	"gitlab.com/bshadmehr76/vgang-auth/service"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

var mockUserRepo *domain.MockUserRepository
var mockAccessTokenRepo *domain.MockAccessTokenRepository
var authService service.AuthService

func setup(t *testing.T) func() {
	ctrl := gomock.NewController(t)

	mockUserRepo = domain.NewMockUserRepository(ctrl)
	mockAccessTokenRepo = domain.NewMockAccessTokenRepository(ctrl)

	authService = service.NewDefaultAuthService(mockUserRepo, mockAccessTokenRepo)
	return func() {
		authService = nil
		defer ctrl.Finish()
	}
}

func Test_service_login_should_succeed_when_user_is_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.LoginRequest{
		Email:    "sample@sample.com",
		Password: "123456aA!",
	}

	getUserReporesponse := mainDomain.User{
		Email:    "sample@sample.com",
		Password: "123456aA!",
	}
	hashedPassword, _ := getUserReporesponse.HashPassword()

	getUserReporesponse.Password = hashedPassword
	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)

	// Act
	response, err := authService.Login(request)

	// Assert
	if err != nil {
		t.Error("Login failed")
	}
	if response.AccessToken == "" {
		t.Error("Login failed")
	}
}

func Test_service_login_should_fail_when_password_is_wrong(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.LoginRequest{
		Email:    "sample@sample.com",
		Password: "123456aA!651",
	}

	getUserReporesponse := mainDomain.User{
		Email:    "sample@sample.com",
		Password: "123456aA!",
	}
	hashedPassword, _ := getUserReporesponse.HashPassword()
	getUserReporesponse.Password = hashedPassword

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)

	// Act
	_, err := authService.Login(request)

	// Assert
	if err == nil || err.Code != 404 {
		t.Error("Wrong password login failed")
	}
}

func Test_service_login_should_fail_when_repo_returns_an_error(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.LoginRequest{
		Email:    "sample@sample.com",
		Password: "123456aA!651",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(nil, errs.NewUnexpectedError("Sample error in db"))

	// Act
	_, err := authService.Login(request)

	// Assert
	if err == nil {
		t.Error("Wrong password login failed")
	}
}

func Test_service_signup_should_fail_with_invalid_email(t *testing.T) {
	// Arrange
	request := dto.SignupRequest{
		Email:    "sample",
		Password: "123456aA!",
		Name:     "sample",
	}
	service := service.NewDefaultAuthService(nil, nil)

	// Act
	_, appError := service.Signup(request)

	// Assert
	if appError == nil {
		t.Error("Email validation is not working")
	}
}

func Test_service_signup_should_fail_with_invalid_password(t *testing.T) {
	// Arrange
	request := dto.SignupRequest{
		Email:    "sample@sample.com",
		Password: "123456789",
		Name:     "sample",
	}
	service := service.NewDefaultAuthService(nil, nil)

	// Act
	_, appError := service.Signup(request)

	// Assert
	if appError == nil {
		t.Error("Email validation is not working")
	}
}

func Test_service_signup_should_fail_if_new_user_exists(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.SignupRequest{
		Email:    "sample@sample.com",
		Password: "123456789aA!",
		Name:     "Sample Sample",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&mainDomain.User{}, nil)

	// Act
	_, appError := authService.Signup(request)

	// Assert
	if appError == nil {
		t.Error("Test failed while validating error when user exists")
	}
}

func Test_service_signup_should_fail_if_new_user_cannot_be_created(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.SignupRequest{
		Email:    "sample@sample.com",
		Password: "123456789aA!",
		Name:     "Sample Sample",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(nil, nil)
	mockUserRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), errs.NewUnexpectedError("Database not connected"))

	// Act
	_, appError := authService.Signup(request)
	if appError == nil {
		t.Error("Test failed while validating error for create user")
	}
}

func Test_service_signup_should_succeed_when_user_data_is_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.SignupRequest{
		Email:    "sample@sample.com",
		Password: "123456789aA!",
		Name:     "Sample Sample",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(nil, nil)
	mockUserRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(1), nil)

	// Act
	response, appError := authService.Signup(request)

	// Assert
	if appError != nil {
		t.Error("Test failed while creating a new user")
	}
	if response.Email == "" || response.UserID != 1 || response.Name == "" {
		t.Error("Test failed while creating a new user")
	}
}

func Test_service_get_otp_should_fail_if_user_cannot_be_found(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.GetOtpRequest{
		Email: "sample@sample.com",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(nil, errs.NewUnexpectedError("database is down"))

	// Act
	_, appError := authService.GetOtp(request)

	// Assert
	if appError == nil {
		t.Error("Get otp is not working")
	}
}

func Test_service_get_otp_should_fail_when_user_secret_key_is_empty(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.GetOtpRequest{
		Email: "sample@sample.com",
	}
	getUserReporesponse := mainDomain.User{
		Email:     "sample@sample.com",
		Password:  "123456aA!",
		SecretKey: "",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)

	// Act
	_, appError := authService.GetOtp(request)

	// Assert
	if appError == nil {
		t.Error("Get otp is not working")
	}
}

func Test_service_get_otp_should_success_when_email_exists(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.GetOtpRequest{
		Email: "sample@sample.com",
	}
	getUserReporesponse := mainDomain.User{
		Email:     "sample@sample.com",
		Password:  "123456aA!",
		SecretKey: "samplesecretkey",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)

	// Act
	response, appError := authService.GetOtp(request)

	// Assert
	if appError != nil {
		t.Error("Get otp is not working")
	}
	if response.Success != true {
		t.Error("Get otp is not working")
	}
}

func Test_service_forget_pass_should_fail_when_email_is_not_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ForgetPassRequest{
		Email:   "sample",
		NewPass: "123456aA!",
		Otp:     "123456",
	}

	// Act
	_, appError := authService.ForgetPass(request)

	// Assert
	if appError == nil {
		t.Error("Get otp is not working")
	}
}

func Test_service_forget_pass_should_fail_when_new_pass_is_not_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ForgetPassRequest{
		Email:   "sample@sample.com",
		NewPass: "123456aA",
		Otp:     "123456",
	}

	// Act
	_, appError := authService.ForgetPass(request)

	// Assert
	if appError == nil {
		t.Error("Get otp is not working")
	}
}

func Test_service_forget_pass_should_fail_when_user_does_not_exists_or_db_returns_error(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ForgetPassRequest{
		Email:   "sample@sample.com",
		NewPass: "123456aA!",
		Otp:     "123456",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(nil, errs.NewUnexpectedError("Some error"))

	// Act
	_, appError := authService.ForgetPass(request)

	// Assert
	if appError == nil {
		t.Error("Get otp is not working")
	}
}

func Test_service_forget_pass_should_fail_when_otp_is_not_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ForgetPassRequest{
		Email:   "sample@sample.com",
		NewPass: "123456aA!",
		Otp:     "123456",
	}
	getUserReporesponse := mainDomain.User{
		Email:     "sample@sample.com",
		Password:  "123456aA!",
		SecretKey: "samplesecretkey",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)

	// Act
	_, appError := authService.ForgetPass(request)

	// Assert
	if appError == nil || appError.Code != 401 {
		t.Error("Get otp is not working")
	}
}

func Test_service_forget_pass_should_fail_when_db_is_down_when_updating_user_password(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	otp, _ := utils.GenerateNewOtp("samplesecretkey")
	request := dto.ForgetPassRequest{
		Email:   "sample@sample.com",
		NewPass: "123456aA!",
		Otp:     otp,
	}
	getUserReporesponse := mainDomain.User{
		Email:     "sample@sample.com",
		Password:  "123456aA!",
		SecretKey: "samplesecretkey",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)
	mockUserRepo.EXPECT().UpdateUserPassword("sample@sample.com", gomock.Any()).Return(errs.NewUnexpectedError("DB is down"))

	// Act
	_, appError := authService.ForgetPass(request)

	// Assert
	if appError == nil {
		t.Error("Forget pass is not working")
	}
}

func Test_service_forget_pass_should_success_when_data_is_correct(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	otp, _ := utils.GenerateNewOtp("samplesecretkey")
	request := dto.ForgetPassRequest{
		Email:   "sample@sample.com",
		NewPass: "123456aA!",
		Otp:     otp,
	}
	getUserReporesponse := mainDomain.User{
		Email:     "sample@sample.com",
		Password:  "123456aA!",
		SecretKey: "samplesecretkey",
	}

	mockUserRepo.EXPECT().GetUserByUserEmail("sample@sample.com").Return(&getUserReporesponse, nil)
	mockUserRepo.EXPECT().UpdateUserPassword("sample@sample.com", gomock.Any()).Return(nil)

	// Act
	response, appError := authService.ForgetPass(request)

	// Assert
	if appError != nil {
		t.Error("Forget pass is not working")
	}
	if response.AccessToken == "" {
		t.Error("Forget pass is not working")
	}
	if response.Success == false {
		t.Error("Forget pass is not working")
	}
}

func Test_service_change_password_should_fail_with_invalid_password(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ChangePassRequest{
		NewPass: "123456aA!",
		OldPass: "123456aA!",
	}

	// Act
	_, appError := authService.ChangePassword(request, &mainDomain.User{})

	// Assert
	if appError == nil {
		t.Error("Change pass is not working")
	}
}

func Test_service_change_password_should_fail_when_db_is_down_at_updatepass(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ChangePassRequest{
		NewPass: "123456aA!",
		OldPass: "123456aA!",
	}
	u := mainDomain.User{
		Email:    "sample@sample.com",
		Password: "123456aA!",
	}
	hashedPassword, _ := u.HashPassword()
	u.Password = hashedPassword
	mockUserRepo.EXPECT().UpdateUserPassword("sample@sample.com", gomock.Any()).Return(errs.NewUnexpectedError("DB is down"))

	// Act
	_, appError := authService.ChangePassword(request, &u)

	// Assert
	if appError == nil {
		t.Error("Change pass is not working")
	}
}

func Test_service_change_password_should_succeed_with_correct_data(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	request := dto.ChangePassRequest{
		NewPass: "123456aA!",
		OldPass: "123456aA!",
	}
	u := mainDomain.User{
		Email:    "sample@sample.com",
		Password: "123456aA!",
	}
	hashedPassword, _ := u.HashPassword()
	u.Password = hashedPassword
	mockUserRepo.EXPECT().UpdateUserPassword("sample@sample.com", gomock.Any()).Return(nil)

	// Act
	response, appError := authService.ChangePassword(request, &u)

	// Assert
	if appError != nil {
		t.Error("Change pass is not working")
	}
	if response.Success == false {
		t.Error("Change pass is not working")
	}
	if response.AccessToken == "" {
		t.Error("Change pass is not working")
	}
}

func Test_service_logout_should_fail_in_case_of_repisitory_error(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	token := mainDomain.AccessToken{
		AccessToken: "sample-token",
	}
	mockAccessTokenRepo.EXPECT().Logout(token).Return(errs.NewUnexpectedError("some error"))

	// Act
	_, appError := authService.Logout(token)

	// Assert
	if appError == nil {
		t.Error("Logout is not working")
	}
}

func Test_service_logout_should_work_when_data_is_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	token := mainDomain.AccessToken{
		AccessToken: "sample-token",
	}
	mockAccessTokenRepo.EXPECT().Logout(token).Return(nil)

	// Act
	response, appError := authService.Logout(token)

	// Assert
	if appError != nil {
		t.Error("Logout is not working")
	}
	if response.Status != true {
		t.Error("Logout is not working")
	}
}

func Test_service_verify_should_fail_in_case_of_repisitory_returns_unauthorized(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	token := mainDomain.AccessToken{
		AccessToken: "sample-token",
	}
	mockAccessTokenRepo.EXPECT().IsAuthorized(token, "sample", nil).Return(false, nil)

	request := dto.VerifyTokenRequest{
		AccessToken: "sample-token",
		Route:       "sample",
	}

	// Act
	response, _ := authService.Verify(request)

	// Assert
	if response.IsVerified == true {
		t.Error("Verify is not working")
	}
}

func Test_service_verify_should_work_when_data_is_valid(t *testing.T) {
	// Arrange
	teardown := setup(t)
	defer teardown()

	token := mainDomain.AccessToken{
		AccessToken: "sample-token",
	}
	mockAccessTokenRepo.EXPECT().IsAuthorized(token, "sample", nil).Return(true, nil)

	request := dto.VerifyTokenRequest{
		AccessToken: "sample-token",
		Route:       "sample",
	}

	// Act
	response, _ := authService.Verify(request)

	// Assert
	if response.IsVerified != true {
		t.Error("Verify is not working")
	}
}
