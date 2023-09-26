package BerdyshFrameworkGoLang

import (
)

type TypeFuncPlugin func(opts ... interface{}) (any)

type TypePlugin struct {
    Name    string ;
    Params  []string ;
    Entry   TypeFuncPlugin ;
}

