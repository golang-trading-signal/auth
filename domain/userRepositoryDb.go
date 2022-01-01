package domain

import (
	"database/sql"

	"github.com/golang-trading-signal/libs/errs"
	"github.com/golang-trading-signal/libs/logger"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type UserRepositoryDB struct {
	client *sqlx.DB
}

func (d UserRepositoryDB) GetUserByUserEmail(email string) (*User, *errs.AppError) {
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

func (d UserRepositoryDB) CreateUser(email string, name string, password string, secret_key string) (int64, *errs.AppError) {
	insertUserQuery := "INSERT INTO users (email, name, password, secret_key) VALUES (?, ?, ?, ?)"

	result := d.client.MustExec(insertUserQuery, email, name, password, secret_key)

	id, err := result.LastInsertId()
	if err != nil {
		return 0, errs.NewUnexpectedError("Error eccured when trying to add user to DB")
	}

	return id, nil
}

func (d UserRepositoryDB) UpdateUserPassword(email string, password string) *errs.AppError {

	updatePAsswordQuery := "UPDATE users SET password = ? WHERE email = ?"

	result := d.client.MustExec(updatePAsswordQuery, password, email)

	_, err := result.RowsAffected()
	if err != nil {
		return errs.NewUnexpectedError("Error eccured when trying to update user password")
	}

	return nil
}

func NewUserRepositoryDB(client *sqlx.DB) UserRepositoryDB {
	return UserRepositoryDB{client}
}
