package ExampleClient

import (
_   "fmt"
)

import X "local/BerdyshFrameworkGoLang"

func    Entry() {
    cli := X.NewClient(&X.TypeClient{}) ;

    cli.Base = "https://petstore3.swagger.io/api/v3" ;
    cli.Base = "https://petstore.swagger.io/v2" ;
    cli.Base = "https://berdysh.net" ;

    cli.SelfTest() ;
}

















