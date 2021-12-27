package service

import (
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/dto"
	"gitlab.com/bshadmehr76/vgang-auth/errs"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Signup(dto.SignupRequest) (*dto.SignupResponse, *errs.AppError)
	GetOtp(dto.GetOtpRequest) (*dto.GetOtpResponse, *errs.AppError)
	ForgetPass(dto.ForgetPassRequest) (*dto.ForgetPassResponse, *errs.AppError)
	ChangePassword(dto.ChangePassRequest, *domain.User) (*dto.ChangePassResponse, *errs.AppError)
	Verify(dto.VerifyTokenRequest) (*dto.VerifyTokenResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo domain.UserRepository
}

func (s DefaultAuthService) Login(loginRequest dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	u, err := s.repo.GetUserByUserEmail(loginRequest.Email)
	if err != nil {
		return nil, err
	}
	if u.ValidateUserPassword(loginRequest.Password) {
		response := dto.LoginResponse{}
		claims := u.GetJwtClaims()
		token, err := domain.GetNewAccessToken(claims)
		if err != nil {
			return nil, err
		}
		response.AccessToken = token.AccessToken
		response.RefreshToken = token.RefreshToken
		return &response, nil
	} else {
		// Don't change this
		err := errs.NewNotFoundError("User not fount")
		return nil, err
	}
}

func (s DefaultAuthService) Signup(signupRequest dto.SignupRequest) (*dto.SignupResponse, *errs.AppError) {
	u, _ := s.repo.GetUserByUserEmail(signupRequest.Email)
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

	id, err := s.repo.CreateUser(user.Email, user.Name, user.Password, user.SecretKey)
	if err != nil {
		return nil, err
	}

	user.Id = id

	return dto.UserToSignupResponse(user), nil
}

func (s DefaultAuthService) GetOtp(getOtpRequest dto.GetOtpRequest) (*dto.GetOtpResponse, *errs.AppError) {
	u, err := s.repo.GetUserByUserEmail(getOtpRequest.Email)
	if err != nil {
		return nil, err
	}
	otp, err := utils.GenerateNewOtp(u.SecretKey)
	if err != nil {
		return nil, err
	}
	u.SendUserOtp(otp)
	response := dto.GetOtpResponse{
		Success: true,
	}
	return &response, nil
}

func (s DefaultAuthService) ForgetPass(forgetPassRequest dto.ForgetPassRequest) (*dto.ForgetPassResponse, *errs.AppError) {
	u, err := s.repo.GetUserByUserEmail(forgetPassRequest.Email)
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

		err = s.repo.UpdateUserPassword(forgetPassRequest.Email, hashedPassword)
		if err != nil {
			return nil, err
		}

		return &response, nil
	}
	err = errs.NewUnauthorizedError("Wrong credentials")
	return nil, err
}

func (s DefaultAuthService) ChangePassword(changePassRequest dto.ChangePassRequest, user *domain.User) (*dto.ChangePassResponse, *errs.AppError) {
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

		err = s.repo.UpdateUserPassword(user.Email, hashedPassword)
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

func (os DefaultAuthService) Verify(verifyTokenRequest dto.VerifyTokenRequest) (*dto.VerifyTokenResponse, *errs.AppError) {
	return nil, nil
}

func NewDefaultAuthService(repo domain.UserRepository) DefaultAuthService {
	return DefaultAuthService{repo}
}
