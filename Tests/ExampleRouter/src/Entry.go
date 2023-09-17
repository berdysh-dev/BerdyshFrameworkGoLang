package ExampleRouter

import (
_   "io"
    "log/syslog"
    "net/http"
)

import X "local/BerdyshFrameworkGoLang"

type HandlerGET struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

type HandlerPOST struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

type HandlerPUT struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

type HandlerDELETE struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
}

func (this *HandlerGET)     ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("GET[%s]"      ,this.OperationId) ; }
func (this *HandlerPOST)    ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("POST[%s]"     ,this.OperationId) ; }
func (this *HandlerPUT)     ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("PUT[%s]"      ,this.OperationId) ; }
func (this *HandlerDELETE)  ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("DELETE[%s]"   ,this.OperationId) ; }

func    Entry() {

    X.Syslog(&X.TypeSyslogConfig{SockAddr:"unix:///dev/log", Facility: syslog.LOG_LOCAL7}) ;

    toolBox := X.NewToolBox() ;
    router := X.NewRouter() ;

    openAPI,err := X.LoaderOpenAPI(&X.TypeConfigOpenAPI{PathJson: "./swagger.json"}) ;

    if(err != nil){
        X.Debugf("err[%s]",err) ;
    }else{
        for _,paths := range openAPI.Paths(){

            // X.Debugf("[%04d][%s][%s][%s]",idx,paths.Method,paths.Path,paths.OperationId) ;

            switch(paths.Method){
                case "GET":{
                    router.Handle(paths.Path,&HandlerGET{ ToolBox: toolBox,OperationId: paths.OperationId}).Methods(paths.Method) ;
                }
                case "POST":{
                    router.Handle(paths.Path,&HandlerPOST{ ToolBox: toolBox,OperationId: paths.OperationId}).Methods(paths.Method) ;
                }
                case "PUT":{
                    router.Handle(paths.Path,&HandlerPUT{ ToolBox: toolBox,OperationId: paths.OperationId}).Methods(paths.Method) ;
                }
                case "DELETE":{
                    router.Handle(paths.Path,&HandlerDELETE{ ToolBox: toolBox,OperationId: paths.OperationId}).Methods(paths.Method) ;
                }
            }
        }
    }

    http.ListenAndServe(":9005",router) ;
}

















