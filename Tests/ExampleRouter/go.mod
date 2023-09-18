module main

go 1.21

replace local/ExampleRouter => ./src

replace local/BerdyshFrameworkGoLang => ../..

require local/ExampleRouter v0.0.0-00010101000000-000000000000

require (
	github.com/go-chi/chi v1.5.5 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	local/BerdyshFrameworkGoLang v0.0.0-00010101000000-000000000000 // indirect
)
