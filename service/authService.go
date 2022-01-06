package service

import (
	"github.com/golang-trading-signal/libs/errs"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

//go:generate mockgen -destination=../mocks/service/mockAuthService.go -package=service gitlab.com/bshadmehr76/vgang-auth/service AuthService
type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Signup(dto.SignupRequest) (*dto.SignupResponse, *errs.AppError)
	GetOtp(dto.GetOtpRequest) (*dto.GetOtpResponse, *errs.AppError)
	ForgetPass(dto.ForgetPassRequest) (*dto.ForgetPassResponse, *errs.AppError)
	ChangePassword(dto.ChangePassRequest, *domain.User) (*dto.ChangePassResponse, *errs.AppError)
	Logout(token domain.AccessToken) (*dto.LogoutResponse, *errs.AppError)
	Verify(dto.VerifyTokenRequest) (*dto.VerifyTokenResponse, *errs.AppError)
	Refresh(dto.RefreshTokenRequest) (*dto.RefreshTokenResponse, *errs.AppError)
}

type DefaultAuthService struct {
	userRrepo       domain.UserRepository
	accessTokenRepo domain.AccessTokenRepository
}

func (s DefaultAuthService) Login(loginRequest dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	u, err := s.userRrepo.GetUserByUserEmail(loginRequest.Email)
	if err != nil {
		return nil, err
	}
	if u.ValidateUserPassword(loginRequest.Password) {
		response := dto.LoginResponse{}
		token, err := domain.GetNewAccessToken(u.GetJwtClaims())
		if err != nil {
			return nil, err
		}

		refresh, err := domain.GetNewRefreshToken(u.GetRefreshJwtClaims())
		if err != nil {
			return nil, err
		}

		response.AccessToken = token.AccessToken
		response.RefreshToken = refresh.RefreshToken
		return &response, nil
	} else {
		// Don't change this
		err := errs.NewNotFoundError("User not fount")
		return nil, err
	}
}

func (s DefaultAuthService) Signup(signupRequest dto.SignupRequest) (*dto.SignupResponse, *errs.AppError) {
	if err := signupRequest.Validate(); err != nil {
		return nil, err
	}
	u, _ := s.userRrepo.GetUserByUserEmail(signupRequest.Email)
	if u != nil {
		err := errs.NewBadRequestError("Email address is taken")
		return nil, err
	}

	user := signupRequest.ToDao()
	hashedPassword, hashingerror := user.HashPassword()
	if hashingerror != nil {
		return nil, errs.NewUnexpectedError("Error while hashing password")
	}

	user.Password = hashedPassword
	secretKey, err := utils.GetNewSecretForEmail(user.Email)

	if err != nil {
		return nil, err
	}

	user.SecretKey = secretKey

	id, err := s.userRrepo.CreateUser(user.Email, user.Name, user.Password, user.SecretKey)
	if err != nil {
		return nil, err
	}

	user.Id = id

	return dto.UserToSignupResponse(user), nil
}

func (s DefaultAuthService) GetOtp(getOtpRequest dto.GetOtpRequest) (*dto.GetOtpResponse, *errs.AppError) {
	u, err := s.userRrepo.GetUserByUserEmail(getOtpRequest.Email)
	if err != nil {
		return nil, err
	}
	otp, err := utils.GenerateNewOtp(u.SecretKey)
	if err != nil {
		return nil, err
	}
	s.userRrepo.SendOtpEmail(u.Email, otp)
	response := dto.GetOtpResponse{
		Success: true,
	}
	return &response, nil
}

func (s DefaultAuthService) ForgetPass(forgetPassRequest dto.ForgetPassRequest) (*dto.ForgetPassResponse, *errs.AppError) {
	if err := forgetPassRequest.Validate(); err != nil {
		return nil, err
	}
	u, err := s.userRrepo.GetUserByUserEmail(forgetPassRequest.Email)
	if err != nil {
		return nil, err
	}
	is_valid := utils.ValidateOtp(forgetPassRequest.Otp, u.SecretKey)
	response := dto.ForgetPassResponse{}
	if is_valid {
		claims := u.GetJwtClaims()
		token, err := domain.GetNewAccessToken(claims)
		if err != nil {
			return nil, err
		}
		response.Success = true
		response.AccessToken = token.AccessToken
		response.RefreshToken = token.RefreshToken

		u.Password = forgetPassRequest.NewPass
		hashedPassword, hashingerror := u.HashPassword()
		if hashingerror != nil {
			return nil, errs.NewUnexpectedError("Error while hashing password")
		}

		err = s.userRrepo.UpdateUserPassword(forgetPassRequest.Email, hashedPassword)
		if err != nil {
			return nil, err
		}

		return &response, nil
	}
	err = errs.NewUnauthorizedError("Wrong credentials")
	return nil, err
}

func (s DefaultAuthService) ChangePassword(changePassRequest dto.ChangePassRequest, user *domain.User) (*dto.ChangePassResponse, *errs.AppError) {
	if err := changePassRequest.Validate(); err != nil {
		return nil, err
	}
	if user.ValidateUserPassword(changePassRequest.OldPass) {
		response := dto.ChangePassResponse{}
		claims := user.GetJwtClaims()
		token, err := domain.GetNewAccessToken(claims)
		if err != nil {
			return nil, err
		}

		user.Password = changePassRequest.NewPass
		hashedPassword, hashingerror := user.HashPassword()
		if hashingerror != nil {
			return nil, errs.NewUnexpectedError("Error while hashing password")
		}

		err = s.userRrepo.UpdateUserPassword(user.Email, hashedPassword)
		if err != nil {
			return nil, err
		}

		response.Success = true
		response.AccessToken = token.AccessToken
		response.RefreshToken = token.RefreshToken
		return &response, nil
	} else {
		err := errs.NewUnauthorizedError("Wrong password")
		return nil, err
	}
}

func (s DefaultAuthService) Logout(token domain.AccessToken) (*dto.LogoutResponse, *errs.AppError) {
	err := s.accessTokenRepo.Logout(token)
	response := dto.LogoutResponse{}
	response.Status = true
	if err != nil {
		response.Status = false
		return &response, err
	}
	return &response, nil
}

func (s DefaultAuthService) Verify(verifyTokenRequest dto.VerifyTokenRequest) (*dto.VerifyTokenResponse, *errs.AppError) {
	token := domain.AccessToken{
		AccessToken: verifyTokenRequest.AccessToken,
	}
	isAuthorized, _ := s.accessTokenRepo.IsAuthorized(token, verifyTokenRequest.Route, nil)
	response := dto.VerifyTokenResponse{
		IsVerified: isAuthorized,
	}
	return &response, nil
}

func (s DefaultAuthService) Refresh(refreshTokenRequest dto.RefreshTokenRequest) (*dto.RefreshTokenResponse, *errs.AppError) {
	token := domain.AccessToken{
		AccessToken: refreshTokenRequest.RefreshToken,
	}
	_, claims := s.accessTokenRepo.IsAuthorized(token, "", nil)

	t, err := domain.GetNewAccessTokenFromRefreshClaims(*claims)
	if err != nil {
		return nil, err
	}
	response := dto.RefreshTokenResponse{
		Token: t.AccessToken,
	}
	return &response, nil
}

func NewDefaultAuthService(userRrepo domain.UserRepository, tokenRrepo domain.AccessTokenRepository) DefaultAuthService {
	return DefaultAuthService{userRrepo: userRrepo, accessTokenRepo: tokenRrepo}
}
