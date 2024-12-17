module github.com/go-bumbu/userauth

go 1.23

toolchain go1.23.1

replace github.com/go-bumbu/http => ../http

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/google/go-cmp v0.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/securecookie v1.1.2
	github.com/gorilla/sessions v1.4.0
	golang.org/x/crypto v0.27.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/sqlite v1.5.6
	gorm.io/gorm v1.25.11
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
