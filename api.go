package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func NewApiServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{listenAddr: listenAddr, store: store}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/login", makeHttpHandler(s.handleLogin)).Methods("POST")
	router.HandleFunc("/account", makeHttpHandler(s.handleAccount)).Methods("GET", "POST")
	router.HandleFunc("/transfer", withJWTAuth(makeAuthHttpHandler(s.handleTransfer), s.store)).Methods("POST")
	router.HandleFunc("/account/{id}", withJWTAuth(makeAuthHttpHandler(s.handleAccountWithId), s.store)).Methods("GET", "DELETE")

	log.Println("API server running on ", s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)
}

// Auth Handlers

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	loginReq := &LoginRequest{}

	if err := json.NewDecoder(r.Body).Decode(loginReq); err != nil {
		return err
	}

	account, err := s.store.LoginAccount(loginReq.Email, loginReq.Password)

	if err != nil {
		return err
	}

	token, err := createJWT(account)

	if err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, map[string]interface{}{
		"account": account,
		"token":   string(token),
	})

}

func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// API Handlers

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccounts(w, r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}
	return nil
}

func (s *APIServer) handleAccountWithId(w http.ResponseWriter, r *http.Request, account *Account) error {
	if r.Method == "GET" {
		fmt.Println("ACCOUNT", account)
		return s.handleGetAccountById(w, r, account)
	}
	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r, account)
	}
	return nil
}

func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request, acc *Account) error {

	id, err := getID(r)
	if err != nil {
		return err
	}

	if int64(id) != acc.ID {
		respondPermissionDenied(w)
		return nil
	}

	account, err := s.store.GetAccountById(id)
	if err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, account)
}

func (s *APIServer) handleGetAccounts(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()

	if err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, accounts)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	reqBody := new(CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(reqBody); err != nil {
		return err
	}

	account := NewAccount(reqBody.FirstName, reqBody.LastName, reqBody.Email, reqBody.Password)
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	token, err := createJWT(account)

	if err != nil {
		return err
	}

	fmt.Println("TOKEN ", token)

	return WriteJson(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request, acc *Account) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	if int64(id) != acc.ID {
		respondPermissionDenied(w)
		return nil
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJson(w, http.StatusOK, map[string]int{"deleted": id})

}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request, account *Account) error {
	transferReq := &TransferRequest{}
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}
	defer r.Body.Close()

	return WriteJson(w, http.StatusOK, transferReq)
}

// API Types

type APIServer struct {
	listenAddr string
	store      Storage
}

type ApiFunc func(http.ResponseWriter, *http.Request) error
type AuthApiFunc func(http.ResponseWriter, *http.Request, *Account) error

type ApiError struct {
	Error string `json:"error"`
}

// JWT Functions

func createJWT(account *Account) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"accountNumber": account.Number,
		"email":         account.Email,
		"exp":           time.Now().Add(time.Hour * 24).Unix(),
		"nbf":           time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	secret := os.Getenv("JWT_SECRET")
	return token.SignedString([]byte(secret))
}

func validateJWT(tokenStr string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")

	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

func withJWTAuth(fn AuthHandlerFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT auth")
		authToken := r.Header.Get("Authorization")

		splitToken := strings.Split(authToken, "Bearer ")

		if len(splitToken) != 2 {
			respondPermissionDenied(w)
			return
		}

		jwtToken := splitToken[1]

		token, err := validateJWT(jwtToken)

		if err != nil {
			respondPermissionDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		accountNumber, ok := claims["accountNumber"].(string)

		if !ok {
			respondPermissionDenied(w)
			return
		}

		account, err := s.GetAccountByNumber(accountNumber)

		if err != nil {
			respondPermissionDenied(w)
			return
		}

		// Call the handler function with the account information
		fn(w, r, account)
	}
}

// Req/Res Helpers

func WriteJson(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}

func makeHttpHandler(fn ApiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			WriteJson(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func makeAuthHttpHandler(fn AuthApiFunc) AuthHandlerFunc {
	var authHandler AuthHandlerFunc = func(w http.ResponseWriter, r *http.Request, account *Account) error {
		if err := fn(w, r, account); err != nil {
			WriteJson(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
		return nil
	}
	return authHandler
}

func respondPermissionDenied(w http.ResponseWriter) {
	WriteJson(w, http.StatusUnauthorized, ApiError{Error: "permission denied"})
}

// Data Helpers

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id: %s", idStr)
	}
	return id, err
}
