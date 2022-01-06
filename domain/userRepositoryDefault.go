package domain

import (
	"database/sql"
	"fmt"

	"github.com/golang-trading-signal/libs/errs"
	"github.com/golang-trading-signal/libs/logger"
	"github.com/hibiken/asynq"
	"gitlab.com/bshadmehr76/vgang-auth/tasks"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type UserRepositoryDefault struct {
	client *sqlx.DB
	asynq  *asynq.Client
}

func (d UserRepositoryDefault) GetUserByUserEmail(email string) (*User, *errs.AppError) {
	getByIDSQL := "select id, email, name, password, secret_key from users where email = ?"

	var u User
	err := d.client.Get(&u, getByIDSQL, email)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewNotFoundError("User not found")
		}
		logger.Error(err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &u, nil
}

func (d UserRepositoryDefault) CreateUser(email string, name string, password string, secret_key string) (int64, *errs.AppError) {
	insertUserQuery := "INSERT INTO users (email, name, password, secret_key) VALUES (?, ?, ?, ?)"

	result := d.client.MustExec(insertUserQuery, email, name, password, secret_key)

	id, err := result.LastInsertId()
	if err != nil {
		return 0, errs.NewUnexpectedError("Error eccured when trying to add user to DB")
	}

	return id, nil
}

func (d UserRepositoryDefault) UpdateUserPassword(email string, password string) *errs.AppError {

	updatePAsswordQuery := "UPDATE users SET password = ? WHERE email = ?"

	result := d.client.MustExec(updatePAsswordQuery, password, email)

	_, err := result.RowsAffected()
	if err != nil {
		return errs.NewUnexpectedError("Error eccured when trying to update user password")
	}

	return nil
}

func (d UserRepositoryDefault) SendOtpEmail(email string, otp string) *errs.AppError {
	task, err := tasks.NewEmailDeliveryTask(42, "some:template:id")
	if err != nil {
		fmt.Println("could not create task:", err)
	}
	info, err := d.asynq.Enqueue(task)
	if err != nil {
		fmt.Println("could not enqueue task:", err)
	}
	fmt.Println("enqueued task:", info.ID, info.Queue)

	return nil
}

func NewUserRepositoryDefault(client *sqlx.DB, asynq *asynq.Client) UserRepositoryDefault {
	return UserRepositoryDefault{client, asynq}
}
