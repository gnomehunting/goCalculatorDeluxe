package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	ID             int    `db:"ID"`
	UserName       string `db:"USERNAME"`
	Password       string `db:"PASSWORD"`
	PlusTiming     int    `db:"PLUS_TIMING"`
	MinusTiming    int    `db:"MINUS_TIMING"`
	MultiplyTiming int    `db:"MULTIPLY_TIMING"`
	DivideTiming   int    `db:"DIVIDE_TIMING"`
	ToShowTiming   int    `db:"TOSHOW_TIMING"`
}

type Expression struct {
	ExpressionID      int    `db:"EXPRESSION_ID"`
	ExpressionText    string `db:"EXPRESSION_TEXT"`
	Status            string `db:"STATUS"`
	UserName          string `db:"USER_NAME"`
	ExpressionResult  string `db:"EXPRESSION_RESULT"`
	BeingSolvedByPort string `db:"BEING_SOLVED_BY_PORT"`
}

type Agent struct {
	AgentID         int    `db:"AGENT_ID"`
	Status          string `db:"STATUS"`
	Port            string `db:"PORT"`
	NotRespondedFor int    `db:"NOT_RESPONDED_FOR"`
}

type SharedData struct { // аналог дб, но её я вряд ли реализую)
	ValidCookies   []string     `json:"ValidCookies"`
	AgentList      []Agent      `json:"AgentList"`
	ExpressionList []Expression `json:"ExpressionList"`
	UserList       []User       `json:"UserList"`
	Mu             sync.Mutex   `json:"Mu"`
	FileName       string       `json:"FileName"`
}

// структуры для работы программы и персистентности
type TemplateAgentData struct {
	List     []Agent
	Username string
	ShowFor  int
}

type TemplateExpressionsData struct {
	List     []Expression
	Username string
}

type TemplateUserData struct {
	List     []User
	Username string
}

type UserCredentials struct {
	Username string
	Password string
}

// структуры, для передачи в темплейт

var (
	secretkey     = []byte("supersecretkey") // ключ для jwt токена
	OrchestraPort = ""                       // порт оркестратора
	datapath      = "data/shared_data.json"  //путь к json с сохранёнными данными
)

// /////////////////////////////////////////
// PERSISTENCY FUNCTIONS
// /////////////////////////////////////////

func createJSONFileIfNotExist(FileName string) error { //создание json файла с содержанием {} по пути datapath, если его не существует
	if _, err := os.Stat(FileName); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.Create(FileName)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString("{}")
	if err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	return nil
}

func NewSharedData(FileName string) (*SharedData, error) { //берёт информацию из json файла и помещает его в структуру SharedData
	data := &SharedData{
		FileName: FileName,
	}
	// Load data from file if it exists
	if err := data.loadFromFile(); err != nil {
		// File might not exist, which is okay for initial creation
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load data from file: %w", err)
		}
	}
	return data, nil
}

func (sd *SharedData) saveToFile() error { //сохраняет информацию из структуры SharedData в файл
	sd.Mu.Lock()
	defer sd.Mu.Unlock()

	data, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	file, err := os.Create(sd.FileName)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	return nil
}

func (sd *SharedData) loadFromFile() error { // для функции NewSharedData
	sd.Mu.Lock()
	defer sd.Mu.Unlock()

	data, err := ioutil.ReadFile(sd.FileName)
	if err != nil {
		return fmt.Errorf("failed to read data from file: %w", err)
	}
	err = json.Unmarshal(data, sd)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}

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

func extractDataFromCookie(jwtCookie string) (username, password string, err error) { // функция, которая извлекает логин и пароль из jwt токена
	secretKey := secretkey
	token, err := jwt.Parse(jwtCookie, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username = claims["username"].(string)
		password = claims["password"].(string)
	} else {
		return "", "", fmt.Errorf("invalid token claims")
	}

	return username, password, nil
}
func generateJWTToken(username, password string) (string, error) { //создание jwt токена
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	tokenString, err := token.SignedString(secretkey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func (sd *SharedData) getTimingsByExpression(expr Expression) (plus, minus, Mu, div, toshow string) { //достаёт тайминги из юзера с помошью поля UserName у выражения
	for _, user := range sd.UserList {
		if user.UserName == expr.UserName {
			plus, minus, Mu, div, toshow = strconv.Itoa(user.PlusTiming), strconv.Itoa(user.MinusTiming), strconv.Itoa(user.MultiplyTiming), strconv.Itoa(user.DivideTiming), strconv.Itoa(user.ToShowTiming)
			break
		}
	}
	return plus, minus, Mu, div, toshow
}

///////////////////////////////////////////
//REGISTRATION & LOGIN
///////////////////////////////////////////

func LoginHandler(w http.ResponseWriter, r *http.Request) { // /login/ отрисовка страницы с логином
	tmpl := template.Must(template.ParseFiles("html/login.html"))
	tmpl.Execute(w, nil)

}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) { // /registration/ отрисовка страницы с регистрацией
	tmpl := template.Must(template.ParseFiles("html/registration.html"))
	tmpl.Execute(w, nil)
}

func (sd *SharedData) RegisterUser(w http.ResponseWriter, r *http.Request) { //регистрация пользователя, проверяется, ненулевые ли поля и есть ли такой юзер, если всё нормально - создаёт нового пользователя
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		doneedtoadd := true

		if username == "" || password == "" {
			doneedtoadd = false
			http.Redirect(w, r, "/register/", http.StatusSeeOther)
			return
		}

		for _, user := range sd.UserList {
			if user.UserName == username {
				doneedtoadd = false
				http.Redirect(w, r, "/register/", http.StatusSeeOther)
				return
			}
		}
		if doneedtoadd {
			sd.UserList = append(sd.UserList, User{len(sd.UserList), username, password, 10, 10, 10, 10, 10})
		}
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	}
}

func (sd *SharedData) LoginUser(w http.ResponseWriter, r *http.Request) { //логин пользователя, проверяет, есть ли такой пользователь, если да - даёт ему куки с jwt токеном на час
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		for _, user := range sd.UserList {
			if user.UserName == username && user.Password == password {
				sd.SetCookieMiddleware(w, username, password)
				http.Redirect(w, r, "/calculator/", http.StatusSeeOther)
				return
			}
		}

		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	}
}

func (sd *SharedData) SetCookieMiddleware(w http.ResponseWriter, username, password string) { //создаёт jwt токен ввышеописанной функцией и добавляет его в куки пользователю
	jwtToken, _ := generateJWTToken(username, password)
	sd.ValidCookies = append(sd.ValidCookies, jwtToken)

	// Создаем cookie для jwt_token
	jwtCookie := &http.Cookie{
		Name:   "jwt_token",
		Value:  jwtToken,
		Path:   "/",
		Domain: "localhost",
	}
	http.SetCookie(w, jwtCookie)

}

func (sd *SharedData) CheckCookieMiddleware(next http.HandlerFunc) http.HandlerFunc { // middleware, которое проверяет, есть ли у пользователя jwt, проверяет его на правильность и кладёт структуру с данными о юзере в контекст
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil || !slices.Contains(sd.ValidCookies, cookie.Value) {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		username, password, err := extractDataFromCookie(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		userData := User{}
		for _, user := range sd.UserList {
			if user.UserName == username && user.Password == password {
				userData = user
				break
			}
		}

		ctx := context.WithValue(r.Context(), "user", userData)
		next(w, r.WithContext(ctx))
	}
}

///////////////////////////////////////////
//CALCULATOR
///////////////////////////////////////////

func (sd *SharedData) ReceiveResult(w http.ResponseWriter, r *http.Request) { //получение результата от агента
	result := r.URL.Query().Get("Result")
	id := r.URL.Query().Get("Id")
	port := r.URL.Query().Get("AgentPort")
	intid, _ := strconv.Atoi(id)
	fmt.Println(result, intid)

	for i := 0; i < len(sd.ExpressionList); i++ {
		if sd.ExpressionList[i].ExpressionID == intid {
			if sd.ExpressionList[i].Status == "solving" {
				sd.ExpressionList[i].ExpressionResult = result
				sd.ExpressionList[i].Status = "solved"
				break
			}

		}

	}

	for i, agent := range sd.AgentList {
		if agent.Port == port {
			sd.AgentList[i].Status = "online"
			break
		}

	}
}

func (sd *SharedData) AddExpression(w http.ResponseWriter, r *http.Request) { //добавление введённого юзером выражения, выражения могут повторяться, но только у разных юзеров
	user := r.Context().Value("user").(User)
	txt := r.FormValue("item")
	needtoadd := true
	needtoaddsameforanotheruser := false
	thisexpression := Expression{}
	username := user.UserName
	for i := range sd.ExpressionList {
		if sd.ExpressionList[i].ExpressionText == txt {
			if sd.ExpressionList[i].UserName == username {
				needtoadd = false
			} else {
				needtoaddsameforanotheruser = true
				thisexpression = sd.ExpressionList[i]
			}
			break
		}
	}
	if needtoadd {
		if needtoaddsameforanotheruser {
			sd.ExpressionList = append(sd.ExpressionList, Expression{ExpressionText: thisexpression.ExpressionText, ExpressionID: len(sd.ExpressionList), ExpressionResult: thisexpression.ExpressionResult, Status: thisexpression.Status, UserName: username, BeingSolvedByPort: ""})
		} else if isValidExpression(txt) {
			sd.ExpressionList = append(sd.ExpressionList, Expression{ExpressionText: txt, ExpressionID: len(sd.ExpressionList), ExpressionResult: "0", Status: "unsolved", UserName: username, BeingSolvedByPort: ""})
		} else {
			sd.ExpressionList = append(sd.ExpressionList, Expression{ExpressionText: txt, ExpressionID: len(sd.ExpressionList), ExpressionResult: "0", Status: "invalid", UserName: username, BeingSolvedByPort: ""})
		}
	}
	http.Redirect(w, r, "/calculator/", http.StatusSeeOther)
}

func (sd *SharedData) CalculatorPage(w http.ResponseWriter, r *http.Request) { // /calculator/ отрисовка страницы калькулятор, в темплейт передаётся список выражений и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/calculator.html"))
	user := r.Context().Value("user").(User)
	data := TemplateExpressionsData{
		List:     sd.ExpressionList,
		Username: user.UserName,
	}
	tmpl.Execute(w, data)
}

func (sd *SharedData) ChangeTimings(w http.ResponseWriter, r *http.Request) { //меняет тайминги у юзера
	user := r.Context().Value("user").(User)
	username := user.UserName
	plus, err1 := strconv.Atoi(r.FormValue("plu"))
	minus, err2 := strconv.Atoi(r.FormValue("min"))
	multiply, err3 := strconv.Atoi(r.FormValue("mul"))
	divide, err4 := strconv.Atoi(r.FormValue("div"))
	toshow, err5 := strconv.Atoi(r.FormValue("whb"))
	for i, user := range sd.UserList {
		if user.UserName == username {
			if err1 == nil {
				sd.UserList[i].PlusTiming = plus
			}
			if err2 == nil {
				sd.UserList[i].MinusTiming = minus
			}
			if err3 == nil {
				sd.UserList[i].MultiplyTiming = multiply
			}
			if err4 == nil {
				sd.UserList[i].DivideTiming = divide
			}
			if err5 == nil {
				sd.UserList[i].ToShowTiming = toshow
			}
			break
		}
	}

	http.Redirect(w, r, "/timings/", http.StatusSeeOther)
}

func (sd *SharedData) TimingsPage(w http.ResponseWriter, r *http.Request) { // /timings/ отрисовка страницы с таймингами, в темплейт передаётся список юзеров и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/timings.html"))
	user := r.Context().Value("user").(User)
	data := TemplateUserData{
		List:     sd.UserList,
		Username: user.UserName,
	}
	tmpl.Execute(w, data)
}

func (sd *SharedData) AddAgent(w http.ResponseWriter, r *http.Request) { //добавление нового агента пользователем
	port := r.FormValue("agentport")
	doneedtoadd := true
	_, err := strconv.Atoi(port)
	for i, agent := range sd.AgentList {
		if agent.Port == port {
			doneedtoadd = false
			if agent.Status == "dead" {
				sd.AgentList[i].Status = "online"
				sd.AgentList[i].NotRespondedFor = 0
			}
			break
		}
	}
	if err != nil || !doneedtoadd {
		fmt.Println(err)
		http.Redirect(w, r, "/agents/", http.StatusSeeOther)
	} else {
		addr := fmt.Sprintf("http://localhost%s/connect/?HostPort=%s", port, OrchestraPort)
		_, _ = http.Get(addr)

		sd.AgentList = append(sd.AgentList, Agent{Port: port, Status: "online", NotRespondedFor: 0, AgentID: len(sd.AgentList)})

		http.Redirect(w, r, "/agents/", http.StatusSeeOther)
	}
}

func (sd *SharedData) AgentsPage(w http.ResponseWriter, r *http.Request) { // /agents/ отрисовка страницы с агентами, в темплейт передаётся список агентов и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/agents.html"))
	user := r.Context().Value("user").(User)
	data := TemplateAgentData{
		List:     sd.AgentList,
		Username: user.UserName,
		ShowFor:  user.ToShowTiming,
	}
	tmpl.Execute(w, data)
}

func heartbeat(sd *SharedData) { //всем подключенным агентам отправляется хартбит через цикл фор, те, кто не принял - not responding
	for {
		if len(sd.AgentList) != 0 {
			for i, agent := range sd.AgentList {
				if sd.AgentList[i].NotRespondedFor >= 1 {
					sd.AgentList[i].Status = "notresponding"
				}
				if sd.AgentList[i].NotRespondedFor >= 30 {
					sd.AgentList[i].Status = "dead"
				}
				if sd.AgentList[i].Status != "dead" {
					heartbeataddr := fmt.Sprintf("http://localhost:%s/heartbeat/?HostPort=%s", agent.Port, OrchestraPort)
					_, err := http.Get(heartbeataddr)
					if err != nil {
						sd.AgentList[i].NotRespondedFor++
						continue
					} else {
						if sd.AgentList[i].Status != "busy" {
							sd.AgentList[i].NotRespondedFor = 0
							sd.AgentList[i].Status = "online"
						}
					}
				}
			}
			time.Sleep(time.Second)
		}
	}

}

func solver(sd *SharedData) { //пробегается по агентам и выражениям, если есть свободные и нерешённые - отправляет агентам выражения
	for {
		time.Sleep(time.Second)
		if len(sd.ExpressionList) != 0 && len(sd.AgentList) != 0 {
			for i := 0; i < len(sd.ExpressionList); i++ {
				if sd.ExpressionList[i].Status == "unsolved" {
					for j := range sd.AgentList {
						if sd.AgentList[j].Status == "online" && sd.ExpressionList[i].Status == "unsolved" {
							textwithreplacements := sd.ExpressionList[i].ExpressionText
							textwithreplacements = strings.ReplaceAll(textwithreplacements, "+", "%2B")
							textwithreplacements = strings.ReplaceAll(textwithreplacements, "/", "%2F")
							stringid := strconv.Itoa(sd.ExpressionList[i].ExpressionID)
							plus, minus, Mul, div, _ := sd.getTimingsByExpression(sd.ExpressionList[i])
							addr := fmt.Sprintf("http://localhost:%s/solve/?Expression=%s&Id=%s&ExecutionTimings=%s!%s!%s!%s", sd.AgentList[j].Port, textwithreplacements, stringid, plus, minus, Mul, div)
							fmt.Println(addr)
							_, err := http.Get(addr)
							if err != nil {
								fmt.Println(err)
							} else {
								sd.ExpressionList[i].Status = "solving"
								sd.AgentList[j].Status = "busy"
								sd.ExpressionList[i].BeingSolvedByPort = sd.AgentList[j].Port
							}

						}
					}
				}
			}
		}
	}
}
func agentChecker(sd *SharedData) { //проверяет, есть ли выражения, которые числятся решающимися, но решающий их агент - оффлайн
	for {
		for i := range sd.ExpressionList {
			for j := range sd.AgentList {
				if sd.ExpressionList[i].Status == "solving" {
					if sd.ExpressionList[i].BeingSolvedByPort == sd.AgentList[j].Port && sd.AgentList[j].Status == "notresponding" {
						sd.ExpressionList[i].Status = "unsolved"
						sd.ExpressionList[i].BeingSolvedByPort = ""
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
}

func initAgentsAndExpressions(sd *SharedData) { // при запуске программы приводит всех агентов и выражения в начальные состояния
	for i := range sd.AgentList {
		if sd.AgentList[i].Status != "dead" {
			sd.AgentList[i].Status = "online"
		}
	}
	for i := range sd.ExpressionList {
		if sd.ExpressionList[i].Status == "solving" {
			sd.ExpressionList[i].Status = "unsolved"
			sd.ExpressionList[i].BeingSolvedByPort = ""
		}
	}
}

func handleSignal(c chan os.Signal, sd *SharedData) { // при нажатии ctrl+c сохраняет структуру SharedData в файл
	for {
		<-c
		fmt.Println("SIGINT received, saving data...")
		sd.saveToFile()
		os.Exit(0)
	}
}

func main() {
	OrchestraPort = ":" + os.Args[1] // через os.args задаётся порт, на котором будет работать оркестратор
	fmt.Println(OrchestraPort)
	if OrchestraPort == "" {
		log.Fatal("PORT not set")
	}

	err := createJSONFileIfNotExist(datapath) // создание файла, если его нет
	if err != nil {
		panic(err)
	}

	sd, err := NewSharedData(datapath) // запись файла в структуру SharedData
	if err != nil {
		panic(err)
	}
	initAgentsAndExpressions(sd)

	c := make(chan os.Signal, 1) // обработка ctrl+C
	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go handleSignal(c, sd)
	go heartbeat(sd)
	go solver(sd)
	go agentChecker(sd) //логика программы

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	})
	http.HandleFunc("/registration/", RegistrationHandler)
	http.HandleFunc("/login/", LoginHandler)

	http.HandleFunc("/adduser/", sd.RegisterUser)
	http.HandleFunc("/submit/", sd.LoginUser)

	http.HandleFunc("/receiveresult/", sd.ReceiveResult)
	http.HandleFunc("/add/", sd.CheckCookieMiddleware(sd.AddExpression))
	http.HandleFunc("/changetimings/", sd.CheckCookieMiddleware(sd.ChangeTimings))
	http.HandleFunc("/addagent/", sd.CheckCookieMiddleware(sd.AddAgent))

	http.HandleFunc("/agents/", sd.CheckCookieMiddleware(sd.AgentsPage))
	http.HandleFunc("/calculator/", sd.CheckCookieMiddleware(sd.CalculatorPage))
	http.HandleFunc("/timings/", sd.CheckCookieMiddleware(sd.TimingsPage))
	http.ListenAndServe(OrchestraPort, nil)
	//обработка эндпоинтов
}
