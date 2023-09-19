module main

go 1.21

replace local/ExampleRouter => ./src

replace local/BerdyshFrameworkGoLang => ../..

require local/ExampleRouter v0.0.0-00010101000000-000000000000

require (
	github.com/fatih/color v1.10.0 // indirect
	github.com/go-chi/chi v1.5.5 // indirect
	github.com/goccy/go-yaml v1.11.2 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	local/BerdyshFrameworkGoLang v0.0.0-00010101000000-000000000000 // indirect
)
