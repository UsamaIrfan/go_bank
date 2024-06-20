package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(id int) error
	UpdateAccount(*Account) error
	GetAccountById(id int) (*Account, error)
	LoginAccount(email, password string) (*Account, error)
	GetAccountByNumber(number string) (*Account, error)
	GetAccounts() ([]*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=postgres password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
	sqlStatement := `INSERT INTO account (first_name, last_name, email, encrypted_password, number, balance, created_at) VALUES 
	($1, $2, $3, $4, $5, $6, $7)`
	response, err := s.db.Query(sqlStatement,
		acc.FirstName,
		acc.LastName,
		acc.Email,
		acc.EncryptedPassword,
		acc.Number,
		acc.Balance,
		acc.CreatedAt,
	)

	if err != nil {
		return err
	}

	if err := response.Err(); err != nil {
		return err
	}

	defer response.Close()

	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("DELETE FROM account WHERE id = $1", id)
	return err
}

func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) GetAccountById(id int) (*Account, error) {
	rows, err := s.db.Query("SELECT * FROM account WHERE id = $1", id)

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account with id %d not found", id)
}

func (s *PostgresStore) LoginAccount(email, password string) (*Account, error) {
	rows, err := s.db.Query("SELECT * FROM account WHERE email = $1 LIMIT 1", email)

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		account, err := scanIntoAccount(rows)

		if err != nil {
			return nil, err
		}

		err = bcrypt.CompareHashAndPassword([]byte(account.EncryptedPassword), []byte(password))

		if err != nil {
			return nil, fmt.Errorf("invalid email or password")
		}

		if err == nil {
			return account, nil
		}
	}

	return nil, fmt.Errorf("invalid email or password")

}

func (s *PostgresStore) GetAccountByNumber(number string) (*Account, error) {
	rows, err := s.db.Query("SELECT * FROM account WHERE number = $1", number)

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account with account number %s not found", number)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	rows, err := s.db.Query("SELECT * FROM account")

	if err != nil {
		return nil, err
	}

	accounts := []*Account{}
	for rows.Next() {
		account, err := scanIntoAccount(rows)

		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil

}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
	account := &Account{}
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Email,
		&account.EncryptedPassword,
		&account.Number,
		&account.Balance,
		&account.CreatedAt,
	)

	return account, err
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS account (
		id serial primary key,
		first_name varchar(255),
		last_name varchar(255),
		email varchar(255),
		encrypted_password varchar(255),
		number varchar(255),
		balance bigint,
		created_at timestamp
	)`

	_, err := s.db.Exec(query)

	return err
}
