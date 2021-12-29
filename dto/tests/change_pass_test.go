package dto_test

import (
	"testing"

	"gitlab.com/bshadmehr76/vgang-auth/dto"
)

func Test_change_password_sould_fail_when_password_length_is_less_than_6(t *testing.T) {
	// Arrange
	request := dto.ChangePassRequest{
		NewPass: "123",
	}

	// Act
	err := request.Validate()

	// Assert
	if err.Code != 400 {
		t.Error("Wrong error code")
	}
	if err.Message != "Password length should be more than 6" {
		t.Error("Wrong error message")
	}
}

func Test_change_password_sould_fail_when_no_lower_char_in_password(t *testing.T) {
	// Arrange
	request := dto.ChangePassRequest{
		NewPass: "123456789B",
	}

	// Act
	err := request.Validate()

	// Assert
	if err.Code != 400 {
		t.Error("Wrong error code")
	}
	if err.Message != "Password should contain at least one lower case character" {
		t.Error("Wrong error message")
	}
}

func Test_change_password_sould_fail_when_no_upper_char_in_password(t *testing.T) {
	// Arrange
	request := dto.ChangePassRequest{
		NewPass: "123456789a",
	}

	// Act
	err := request.Validate()

	// Assert
	if err.Code != 400 {
		t.Error("Wrong error code")
	}
	if err.Message != "Password should contain at least one upper case character" {
		t.Error("Wrong error message")
	}
}

func Test_change_password_sould_fail_when_no_int_in_password(t *testing.T) {
	// Arrange
	request := dto.ChangePassRequest{
		NewPass: "aaabbbcccDDD",
	}

	// Act
	err := request.Validate()

	// Assert
	if err.Code != 400 {
		t.Error("Wrong error code")
	}
	if err.Message != "Password should contain at least one number" {
		t.Error("Wrong error message")
	}
}

func Test_change_password_sould_succeed_when_password_contains_everything(t *testing.T) {
	// Arrange
	request := dto.ChangePassRequest{
		NewPass: "123456789aA!",
	}

	// Act
	err := request.Validate()

	// Assert
	if err != nil {
		t.Error("Validating password is failing")
	}
}
