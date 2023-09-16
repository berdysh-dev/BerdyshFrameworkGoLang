package ExampleRouter

import (
_   "io"
    "log/syslog"
    "net/http"
)

import X "local/BerdyshFrameworkGoLang"

type HandlerA struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

type HandlerB struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

type HandlerC struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

func (this *HandlerA) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("A") ; }
func (this *HandlerB) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("B") ; }
func (this *HandlerC) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("C") ; }

func    Entry() {

    X.Syslog(&X.TypeSyslogConfig{Facility: syslog.LOG_LOCAL7});

    toolBox := X.NewToolBox() ;

    http.ListenAndServe(
        ":9005",
        X.NewRouter().
        LoaderOpenAPI("./swagger.json").
        AddHandlerByOperationId("Op1",&HandlerA{ ToolBox: toolBox,OperationId:"Op1" }).
        AddHandlerByOperationId("Op2",&HandlerA{ ToolBox: toolBox,OperationId:"Op2" }).
        AddHandlerByOperationId("Op3",&HandlerB{ ToolBox: toolBox,OperationId:"Op3" }).
        LoaderConfig(),
    ) ;
}

















