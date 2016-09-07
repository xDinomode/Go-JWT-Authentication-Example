package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Key int

const MyKey Key = 0

// JWT schema of the data it will store
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// create a JWT and put in the clients cookie
func setToken(res http.ResponseWriter, req *http.Request) {
	expireToken := time.Now().Add(time.Hour * 1).Unix()
	expireCookie := time.Now().Add(time.Hour * 1)

	claims := Claims{
		"myusername",
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "localhost:9000",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, _ := token.SignedString([]byte("secret"))

	cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
	http.SetCookie(res, &cookie)

	http.Redirect(res, req, "/profile", 307)
}

// middleware to protect private pages
func validate(page http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("Auth")
		if err != nil {
			http.NotFound(res, req)
			return
		}

		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return []byte("secret"), nil
		})
		if err != nil {
			http.NotFound(res, req)
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			ctx := context.WithValue(req.Context(), MyKey, *claims)
			page(res, req.WithContext(ctx))
		} else {
			http.NotFound(res, req)
			return
		}
	})
}

// only viewable if the client has a valid token
func protectedProfile(res http.ResponseWriter, req *http.Request) {
	claims, ok := req.Context().Value(MyKey).(Claims)
	if !ok {
		http.NotFound(res, req)
		return
	}

	fmt.Fprintf(res, "Hello %s", claims.Username)
}

// deletes the cookie
func logout(res http.ResponseWriter, req *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(res, &deleteCookie)
	return
}

func main() {
	http.HandleFunc("/settoken", setToken)
	http.HandleFunc("/profile", validate(protectedProfile))
	http.HandleFunc("/logout", validate(logout))
	http.ListenAndServe(":9000", nil)
}
