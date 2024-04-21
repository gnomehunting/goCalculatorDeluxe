package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var secretKey = []byte("my_secret_key") //ключ для jwt токена

func generateJWTToken(username, password string) (string, error) {
	// Создаем новый токен
	token := jwt.New(jwt.SigningMethodHS256)

	// Устанавливаем клеймы (полезную нагрузку) для токена
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	// Подписываем токен с секретным ключом
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("registration/login.html"))
	tmpl.Execute(w, nil)

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("registration/registration.html"))
	tmpl.Execute(w, nil)
}

func setTokenCookie(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/checkcookie", http.StatusSeeOther)
	//тут сделать редирект на калькулятор

}
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		password := r.URL.Query().Get("password")
		_, _ = generateJWTToken(username, password)
		//jwtToken, _ := generateJWTToken(username, password)

		cookie := &http.Cookie{
			Name: "jwt_token",
			//Value: jwtToken,
			Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTAxNzIsInBhc3N3b3JkIjoiIiwidXNlcm5hbWUiOiIifQ.yl2q1sjI_-V6tXURGbJgrDx4TvjaA9hWBXKjvXtTkpU",
		}
		http.SetCookie(w, cookie)

		next.ServeHTTP(w, r)
	})
}

func CheckCookie(w http.ResponseWriter, r *http.Request) {
	Tokens := []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTAxNzIsInBhc3N3b3JkIjoiIiwidXNlcm5hbWUiOiIifQ.yl2q1sjI_-V6tXURGbJgrDx4TvjaA9hWBXKjvXtTkpU", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTE2NDUsInBhc3N3b3JkIjoiIiwidXNlcm5hbWUiOiIifQ.FF0F6FXV-5mObs2rEAoj2W89DO2nos4OvDTCZvU26wA", "token3"} // Список валидных токенов
	tmpl := template.Must(template.ParseFiles("registration/auth.html"))
	tmpl.Execute(w, map[string]interface{}{"Tokens": Tokens})
}

//это переделать в мидлварь и накрутить на страницы калькулятора

func main() {
	http.Handle("/setcookie", jwtMiddleware(http.HandlerFunc(setTokenCookie)))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/registration", registerHandler)
	http.HandleFunc("/checkcookie", CheckCookie)

	fmt.Println("Server started on port 8080")
	http.ListenAndServe(":8080", nil)
}

//TODO: функция, которая проверяет, есть ли такой пользователь в бд и отказывает в регистрации и даёт залогиниться
//сделать редирект на сам калькулятор
