package app

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/golang-trading-signal/libs/errs"
	"github.com/gorilla/mux"
	"gitlab.com/bshadmehr76/vgang-auth/domain"
	"gitlab.com/bshadmehr76/vgang-auth/utils"
)

type AuthMiddleware struct {
	tokenRepo domain.AccessTokenRepository
	userRepo  domain.UserRepository
}

func (a AuthMiddleware) authorizationHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentRoute := mux.CurrentRoute(r)
			CurrentRouteVars := mux.Vars(r)
			authHeader := r.Header.Get("Authorization")

			var token string
			var isAuthorized bool
			var claims *jwt.MapClaims

			if authHeader != "" {
				token = getTokenFromHeader(authHeader)
			}
			isAuthorized, claims = a.tokenRepo.IsAuthorized(domain.AccessToken{AccessToken: token}, currentRoute.GetName(), CurrentRouteVars)
			if isAuthorized {
				var ctx context.Context
				if claims != nil {
					if (*claims)["type"] == "refresh" {
						return
					}
					user_email := (*claims)["email"].(string)
					user, err := a.userRepo.GetUserByUserEmail(user_email)
					if err != nil {
						utils.WriteResponse(w, 0, nil, err)
						return
					}
					ctx = context.WithValue(r.Context(), "user", user)
				}
				if ctx != nil {
					next.ServeHTTP(w, r.WithContext(ctx))
				} else {
					next.ServeHTTP(w, r)
				}

			} else {
				appError := errs.NewForbiddenError("Unauthorized")
				utils.WriteResponse(w, 0, nil, appError)
			}
		})
	}
}

func getTokenFromHeader(token string) string {
	return token
}
