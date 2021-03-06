// Code generated by MockGen. DO NOT EDIT.
// Source: gitlab.com/bshadmehr76/vgang-auth/domain (interfaces: UserRepository)

// Package domain is a generated GoMock package.
package domain

import (
	reflect "reflect"

	errs "github.com/golang-trading-signal/libs/errs"
	gomock "github.com/golang/mock/gomock"
	domain "gitlab.com/bshadmehr76/vgang-auth/domain"
)

// MockUserRepository is a mock of UserRepository interface.
type MockUserRepository struct {
	ctrl     *gomock.Controller
	recorder *MockUserRepositoryMockRecorder
}

// MockUserRepositoryMockRecorder is the mock recorder for MockUserRepository.
type MockUserRepositoryMockRecorder struct {
	mock *MockUserRepository
}

// NewMockUserRepository creates a new mock instance.
func NewMockUserRepository(ctrl *gomock.Controller) *MockUserRepository {
	mock := &MockUserRepository{ctrl: ctrl}
	mock.recorder = &MockUserRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserRepository) EXPECT() *MockUserRepositoryMockRecorder {
	return m.recorder
}

// CreateUser mocks base method.
func (m *MockUserRepository) CreateUser(arg0, arg1, arg2, arg3 string) (int64, *errs.AppError) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(*errs.AppError)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockUserRepositoryMockRecorder) CreateUser(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockUserRepository)(nil).CreateUser), arg0, arg1, arg2, arg3)
}

// GetUserByUserEmail mocks base method.
func (m *MockUserRepository) GetUserByUserEmail(arg0 string) (*domain.User, *errs.AppError) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByUserEmail", arg0)
	ret0, _ := ret[0].(*domain.User)
	ret1, _ := ret[1].(*errs.AppError)
	return ret0, ret1
}

// GetUserByUserEmail indicates an expected call of GetUserByUserEmail.
func (mr *MockUserRepositoryMockRecorder) GetUserByUserEmail(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByUserEmail", reflect.TypeOf((*MockUserRepository)(nil).GetUserByUserEmail), arg0)
}

// SendOtpEmail mocks base method.
func (m *MockUserRepository) SendOtpEmail(arg0, arg1 string) *errs.AppError {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendOtpEmail", arg0, arg1)
	ret0, _ := ret[0].(*errs.AppError)
	return ret0
}

// SendOtpEmail indicates an expected call of SendOtpEmail.
func (mr *MockUserRepositoryMockRecorder) SendOtpEmail(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendOtpEmail", reflect.TypeOf((*MockUserRepository)(nil).SendOtpEmail), arg0, arg1)
}

// UpdateUserPassword mocks base method.
func (m *MockUserRepository) UpdateUserPassword(arg0, arg1 string) *errs.AppError {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserPassword", arg0, arg1)
	ret0, _ := ret[0].(*errs.AppError)
	return ret0
}

// UpdateUserPassword indicates an expected call of UpdateUserPassword.
func (mr *MockUserRepositoryMockRecorder) UpdateUserPassword(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserPassword", reflect.TypeOf((*MockUserRepository)(nil).UpdateUserPassword), arg0, arg1)
}
