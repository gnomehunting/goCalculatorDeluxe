
## Contact me https://t.me/xdd42

### Реализован многопользовательский режим, персистентность с помощью json файла, grpc - не использовано, тесты неполные

#### Схема работы

чтобы запустить оркестратор, вам нужно выполнить эту команду: go run .\orchestra\orchestra.go <любой порт>, после запуска оркестра создастя json файл в папке data, персистентность реализована с его помощью. Для сброса программы к начальному состоянию, удалите файл shared_data.json

чтобы запустить агента, вам нужно выполнить эту команду: go run .\agent\agent.go <любой порт>

агентов можно подключить сколько угодно, для этого нужно ввести порт агента на странице Agents, подключать их надо самостоятельно(агент появятся на веб странице через секунду после ввода порта в поле)

## Можно запустить оркестратор на порте 8080 и 5 агентов(8081-8085) скриптом RUN_ME.bat

1) чтобы начать работу вам нужно перейти на страницу [localhost:<вашпорт>](http://localhost:8080)
#### ВАЖНО! именно localhost, не 127.0.0.1

2) вы попадёте на страницу [login](http://localhost:8080/login/), но сначала нужно [зарегистрироваться](http://localhost:8080/registration/), после чего вы сможете зайти в приложение под введёнными данными

3) на странице [калькулятор](http://localhost:8080/calculator/) вы можете ввести выражения, которые можно решить, каждый пользователь видит только введённые им выражения

4) [на странице таймингов](http://localhost:8080/timings/) вы можете поменять тайминги для операций и для вывода неактивного агента на странице [агенты](http://localhost:8080/agents/) (значения по умолчанию - 10 секунд), тайминги привязаны к пользователю

5) на странице [агенты](http://localhost:8080/agents/) вы можете добавить новых агентов введя порт, на котором агент запущен, и увидеть, какие агенты подлючены и их статус, агенты общие между всеми пользователями, более подробные комментарии по работе программы находятся в коде.

#### Вы можете отключить любого агента или оркестр, и программа продолжит работать, но если агент был отключен более чем на 30 секунд при работающем оркестре, его порт снова нужно ввести на странице с агентами.