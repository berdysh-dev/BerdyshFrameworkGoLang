package ExampleRouter

import (
_   "io"
    "net/http"
)

import X "local/BerdyshFrameworkGoLang"

type HandlerA struct{
    operationId     string
}

func (this *HandlerA) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("A") ; }
func (this *HandlerA) OperationId() (string){ return this.operationId ; }

type HandlerB struct {
    operationId     string
}

func (this *HandlerB) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("B") ; }
func (this *HandlerB) OperationId() (string){ return this.operationId ; }

type HandlerC struct {
    operationId     string
}

func (this *HandlerC) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("C") ; }
func (this *HandlerC) OperationId() (string){ return this.operationId ; }

func    Entry() {

    http.ListenAndServe(
        ":9005",
        X.NewRouter().
        LoaderOpenAPI("./swagger.json").
        AddOperationId("Op1",&HandlerA{}).
        AddOperationId("Op2",&HandlerA{}).
        LoaderConfig(),
    ) ;
}

















