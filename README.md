### JSON Web Token Authentication Example 

**Uses:**

* [dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go)

* [gorilla/context](https://github.com/gorilla/context)

#### How to run 

Get the two required packages above

```bash
$ go get github.com/dgrijalva/jwt-go
$ go get github.com/gorilla/context
```

Run it and it will be on **port 8080**

```bash
go run jwt.go
```

**/** home page 
**/setToken** Sets the token 
**/profile** Protected page only accessible by users with valid tokens


