module main

go 1.21

replace local/ExampleRouter => ./src

replace local/BerdyshFrameworkGoLang => ../..

require local/ExampleRouter v0.0.0-00010101000000-000000000000

require local/BerdyshFrameworkGoLang v0.0.0-00010101000000-000000000000 // indirect
