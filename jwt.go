package main

import "github.com/dgrijalva/jwt-go"
import "github.com/gorilla/context"

import "net/http"

import "fmt"
import "strings"
import "time"

type MyCustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func setToken(res http.ResponseWriter, req *http.Request) {
	expireToken := time.Now().Add(time.Hour * 24).Unix()
	expireCookie := time.Now().Add(time.Hour * 24)

	claims := MyCustomClaims{
		"myusername",
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "example.com",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, _ := token.SignedString([]byte("secret"))

	cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
	http.SetCookie(res, &cookie)

	http.Redirect(res, req, "/profile", 301)
}

func validate(protectedPage http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

		cookie, err := req.Cookie("Auth")
		if err != nil {
			http.NotFound(res, req)
			return
		}

		splitCookie := strings.Split(cookie.String(), "Auth=")

		token, err := jwt.ParseWithClaims(splitCookie[1], &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method %v", token.Header["alg"])
			}
			return []byte("secret"), nil
		})

		if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
			context.Set(req, "Claims", claims)
		} else {
			http.NotFound(res, req)
			return
		}

		protectedPage(res, req)
	})
}

func profile(res http.ResponseWriter, req *http.Request) {
	claims := context.Get(req, "Claims").(*MyCustomClaims)
	res.Write([]byte(claims.Username))
	context.Clear(req)
}

func homePage(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("Home Page"))
}
func main() {
	http.HandleFunc("/profile", validate(profile))
	http.HandleFunc("/setToken", setToken)
	http.HandleFunc("/", homePage)
	http.ListenAndServe(":8080", nil)
}
