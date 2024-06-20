package main

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type AuthRequest struct {
	*http.Request
	Account *Account
}

type AuthHandlerFunc func(http.ResponseWriter, *http.Request, *Account) error

type TransferRequest struct {
	ToAccount int `json:"toAccount"`
	Amount    int `json:"amount"`
}

type Account struct {
	ID                int64     `json:"id"`
	FirstName         string    `json:"firstName"`
	LastName          string    `json:"lastName"`
	Email             string    `json:"email"`
	EncryptedPassword string    `json:"encryptedPassword"`
	Number            string    `json:"number"`
	Balance           int64     `json:"balance"`
	CreatedAt         time.Time `json:"createdAt"`
}

func NewAccount(firstName, lastName, email, password string) *Account {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return &Account{
		FirstName:         firstName,
		LastName:          lastName,
		Email:             email,
		EncryptedPassword: string(hashedPassword),
		Number:            uuid.New().String(),
		CreatedAt:         time.Now().UTC(),
	}
}
