package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/didip/tollbooth"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/service"
)

func setupMode() {
	if os.Getenv("DEBUG_MODE") == "" ||
		os.Getenv("DEBUG_MODE") == "true" {
		os.Setenv("SERVER_ADDRESS", "localhost")
		os.Setenv("SERVER_PORT", "8000")
		os.Setenv("MYSQL_USERNAME", "root")
		os.Setenv("MYSQL_PASSWORD", "secret")
		os.Setenv("MYSQL_URL", "localhost")
		os.Setenv("MYSQL_PORT", "3306")
		os.Setenv("MYSQL_DATABASE", "auth")
		os.Setenv("HMAC_SECRET", "aefqaw5e8g74qaw6e8g47a56egv4")
	}
}

func sanityCheck() {
	if os.Getenv("SERVER_ADDRESS") == "" ||
		os.Getenv("SERVER_PORT") == "" ||
		os.Getenv("MYSQL_USERNAME") == "" ||
		os.Getenv("MYSQL_PASSWORD") == "" ||
		os.Getenv("MYSQL_URL") == "" ||
		os.Getenv("MYSQL_PORT") == "" ||
		os.Getenv("MYSQL_DATABASE") == "" ||
		os.Getenv("HMAC_SECRET") == "" {
		log.Fatal("Environment variables are no setted correctly...")
	}
}

func getMySQLClient() *sqlx.DB {
	MYSQL_USERNAME := os.Getenv("MYSQL_USERNAME")
	MYSQL_PASSWORD := os.Getenv("MYSQL_PASSWORD")
	MYSQL_URL := os.Getenv("MYSQL_URL")
	MYSQL_PORT := os.Getenv("MYSQL_PORT")
	MYSQL_DATABASE := os.Getenv("MYSQL_DATABASE")
	client, err := sqlx.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", MYSQL_USERNAME, MYSQL_PASSWORD, MYSQL_URL, MYSQL_PORT, MYSQL_DATABASE))
	if err != nil {
		panic(err)
	}

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}

func Start() {
	setupMode()
	sanityCheck()

	mux := mux.NewRouter()

	db := getMySQLClient()
	handlers := AuthHandler{service.NewDefaultAuthService(domain.NewUserRepositoryDB(db))}

	lmt := tollbooth.NewLimiter(1, nil)
	lmt.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"})

	mux.Handle("/login", tollbooth.LimitFuncHandler(tollbooth.NewLimiter(1, nil), handlers.login)).Methods(http.MethodPost).Name("auth-login")
	mux.Handle("/signup", tollbooth.LimitFuncHandler(tollbooth.NewLimiter(1, nil), handlers.signup)).Methods(http.MethodPost).Name("auth-signup")
	mux.HandleFunc("/get_otp", handlers.GetOtp).Methods(http.MethodPost).Name("auth-get_otp")
	mux.HandleFunc("/forget_pass", handlers.forgetPassword).Methods(http.MethodPost).Name("auth-forget_pass")
	mux.HandleFunc("/change_password", handlers.changePassword).Methods(http.MethodPost).Name("auth-change_pass")
	mux.HandleFunc("/verify", handlers.verify).Methods(http.MethodPost)

	authMiddleware := AuthMiddleware{domain.NewAccessTokenRepositoryDefault(), domain.NewUserRepositoryDB(db)}
	mux.Use(authMiddleware.authorizationHandler())

	// Starting server
	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), mux))
}
