module github.com/go-bumbu/userauth

go 1.23

toolchain go1.23.1

replace github.com/go-bumbu/http => ../http

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/go-bumbu/http v0.2.0
	github.com/google/go-cmp v0.6.0
	github.com/gorilla/securecookie v1.1.2
	github.com/gorilla/sessions v1.4.0
	golang.org/x/crypto v0.27.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/sqlite v1.5.6
	gorm.io/gorm v1.25.11
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
