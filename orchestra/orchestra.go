package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	ID             int    `db:"ID"`
	JWT            string `db:"JWT"`
	Username       string `db:"USERNAME"`
	Password       string `db:"PASSWORD"`
	PlusTiming     int    `db:"PLUS_TIMING"`
	MinusTiming    int    `db:"MINUS_TIMING"`
	MultiplyTiming int    `db:"MULTIPLY_TIMING"`
	DivideTiming   int    `db:"DIVIDE_TIMING"`
	ToShowTiming   int    `db:"TOSHOW_TIMING"`
}

type Expression struct {
	ExpressionID   int    `db:"EXPRESSION_ID"`
	ExpressionText string `db:"EXPRESSION_TEXT"`
	Status         string `db:"STATUS"`
	UserId         int    `db:"USER_ID"`
}

type Agent struct {
	AgentID         int    `db:"AGENT_ID"`
	Status          string `db:"STATUS"`
	Port            string `db:"PORT"`
	NotRespondedFor int    `db:"NOT_RESPONDED_FOR"`
}

var (
	secretkey = "supersecretkey"
)

///////////////////////////////////////////
//INSTRUMENTARY FUNCTIONS
///////////////////////////////////////////

func isValidExpression(expression string) bool { // функция, которая проверяет выражение на правильность (скобки/знаки/цифры)
	re := regexp.MustCompile(`^\d+([\+\-\*\/]\d+)+$`)
	withoutcommas := expression
	withoutcommas = strings.ReplaceAll(withoutcommas, "(", "")
	withoutcommas = strings.ReplaceAll(withoutcommas, ")", "")

	ismatching := re.MatchString(withoutcommas)

	stack := []rune{}

	for _, char := range expression {
		if char == '(' {
			stack = append(stack, '(')
		} else if char == ')' {
			if len(stack) == 0 {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}

	return len(stack) == 0 && ismatching
}

func extractUsernameFromCookie(jwtCookie string) (string, error) { // функция, которая извлекает логин из jwt токена
	var username string
	secretKey := secretkey
	token, err := jwt.Parse(jwtCookie, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username = claims["username"].(string)
	} else {
		return "", fmt.Errorf("Invalid token claims")
	}

	return username, nil
}
func generateJWTToken(username, password string) (string, error) {
	// Создаем новый токен
	token := jwt.New(jwt.SigningMethodHS256)

	// Устанавливаем клеймы (полезную нагрузку) для токена
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	// Подписываем токен с секретным ключом
	tokenString, err := token.SignedString(secretkey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

///////////////////////////////////////////
//REGISTRATION & LOGIN
///////////////////////////////////////////

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/login.html"))
	tmpl.Execute(w, nil)

}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/registration.html"))
	tmpl.Execute(w, nil)
}

func SetJwtCookieMiddleware(next http.Handler) http.Handler { //заставить эту хуету получать данные из формы
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		jwtToken, _ := generateJWTToken(username, password)

		cookie := &http.Cookie{
			Name:  "jwt_token",
			Value: jwtToken,
		}
		http.SetCookie(w, cookie)

		next.ServeHTTP(w, r)
	})
}

func CheckAuthMiddleware(next http.Handler) http.Handler { // надо запихнуть перед всеми страницами за исключением регистрации и логина
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		username, err := extractUsernameFromCookie(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), "username", username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	http.HandleFunc("/registration", RegistrationHandler)
	http.HandleFunc("/login", LoginHandler)

	http.Handle("/submitregistration", SetJwtCookieMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/calculator", http.StatusSeeOther)
	})))
	http.Handle("/calculator", CheckAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to the calculator page!"))
	})))
	http.ListenAndServe(":8080", nil)
}

///////////////////////////////////////////
//CALCULATOR
///////////////////////////////////////////

func ReceiveResult(w http.ResponseWriter, r *http.Request) {
	// агент отправляет сюда номер выражения которое он решал и его результат
}

func AddExpression(w http.ResponseWriter, r *http.Request) {
	// добавляется выражение в дб, которое пользователь отправил
}

func CalculatorPage(w http.ResponseWriter, r *http.Request) { // /calculator/ отрисовка страницы калькулятор, в темплейт передаётся мапа выражений
	//отрисовка
}

func ChangeTimings(w http.ResponseWriter, r *http.Request) {
	//пользователь отправыляет сюда новые тайминги и они меняются в бд
}

func TimingsPage(w http.ResponseWriter, r *http.Request) { // /timings/ отрисовка страницы с таймингами, в темплейт передаются тайминги
	//отрисовка
}

func AddAgent(w http.ResponseWriter, r *http.Request) {
	//добавляется агент в дб(юзер вводит порт)
}

func AgentsPage(w http.ResponseWriter, r *http.Request) { // /agents/ отрисовка страницы с агентами, в темплейт передаётся список агентов
	//отрисовка
}

func heartbeat() {
	//всем подключенным агентам отправляется хартбит через цикл фор, те, кто не принял - not responding

}
func ResetAgent() {
	//обнуляем агента
}
func dbPuller() {} //берём всё из дб, раскидываем по спискам, всем агентам присылаем приказ обнулиться
func solver() {
	//пробегаемся по выражениям и раскидываем их по свободным агентам
}
