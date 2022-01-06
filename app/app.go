package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/didip/tollbooth"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/hibiken/asynq"
	"github.com/jmoiron/sqlx"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/service"
)

func setupMode() {
	if os.Getenv("DEBUG_MODE") == "" ||
		os.Getenv("DEBUG_MODE") == "true" {
		os.Setenv("SERVER_ADDRESS", "0.0.0.0")
		os.Setenv("SERVER_PORT", "8000")
		os.Setenv("MYSQL_USERNAME", "root")
		os.Setenv("MYSQL_PASSWORD", "secret")
		os.Setenv("MYSQL_URL", "localhost")
		os.Setenv("MYSQL_PORT", "3306")
		os.Setenv("MYSQL_DATABASE", "auth")
		os.Setenv("HMAC_SECRET", "aefqaw5e8g74qaw6e8g47a56egv4")
		os.Setenv("REDIS_URI", "localhost")
		os.Setenv("REDIS_PORT", "6379")
		os.Setenv("REDIS_PASSWORD", "")
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
		os.Getenv("HMAC_SECRET") == "" ||
		os.Getenv("REDIS_URI") == "" ||
		os.Getenv("REDIS_PORT") == "" {
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

func getRedisclient() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URI") + ":" + os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"), // no password set
		DB:       0,                           // use default DB
	})
	return rdb
}

func Start() {
	setupMode()
	sanityCheck()

	mux := mux.NewRouter()

	db := getMySQLClient()
	asynq := asynq.NewClient(asynq.RedisClientOpt{Addr: os.Getenv("REDIS_URI") + ":" + os.Getenv("REDIS_PORT")})
	redis := getRedisclient()
	handlers := AuthHandler{service.NewDefaultAuthService(domain.NewUserRepositoryDefault(db, asynq), domain.NewAccessTokenRepositoryDefault(redis))}

	lmt := tollbooth.NewLimiter(1, nil)
	lmt.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"})

	mux.Handle("/login", tollbooth.LimitFuncHandler(tollbooth.NewLimiter(1, nil), handlers.Login)).Methods(http.MethodPost).Name("auth-login")
	mux.Handle("/signup", tollbooth.LimitFuncHandler(tollbooth.NewLimiter(1, nil), handlers.Signup)).Methods(http.MethodPost).Name("auth-signup")
	mux.HandleFunc("/get_otp", handlers.GetOtp).Methods(http.MethodPost).Name("auth-get_otp")
	mux.HandleFunc("/forget_pass", handlers.ForgetPassword).Methods(http.MethodPost).Name("auth-forget_pass")
	mux.HandleFunc("/change_password", handlers.ChangePassword).Methods(http.MethodPost).Name("auth-change_pass")
	mux.HandleFunc("/logout", handlers.Logout).Methods(http.MethodPost).Name("auth-logout")
	mux.HandleFunc("/verify", handlers.Verify).Methods(http.MethodPost).Name("auth-verify")
	mux.HandleFunc("/refresh", handlers.Refresh).Methods(http.MethodPost).Name("auth-refresh")

	authMiddleware := AuthMiddleware{domain.NewAccessTokenRepositoryDefault(redis), domain.NewUserRepositoryDefault(db, asynq)}
	mux.Use(authMiddleware.authorizationHandler())

	// Starting server
	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), mux))
}
