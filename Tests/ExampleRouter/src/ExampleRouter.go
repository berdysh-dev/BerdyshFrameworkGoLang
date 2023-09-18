package ExampleRouter

import (
_   "io"
_   "fmt"
    "log/syslog"
    "net/http"
    "github.com/gorilla/mux"
_   "github.com/go-chi/chi"
)

import X "local/BerdyshFrameworkGoLang"

type HandlerPet struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
    OpenApi         *X.TypeRcLoaderOpenAPI ;
}

type HandlerUser struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
    OpenApi         *X.TypeRcLoaderOpenAPI ;
}

type HandlerStore struct {
    OperationId     string ;
    ToolBox         *X.TypeToolBox ;
    OpenApi         *X.TypeRcLoaderOpenAPI ;
}

func (this *HandlerPet)     ServeHTTP(w http.ResponseWriter, r *http.Request) {
    X.Debugf("Pet[%s]"      ,this.OperationId) ;
    req := X.Req(&w,r,this.OperationId,this.ToolBox,this.OpenApi) ;
    req.Dump() ;
}

func (this *HandlerUser)    ServeHTTP(w http.ResponseWriter, r *http.Request) {

    req := X.Req(&w,r,this.OperationId,this.ToolBox,this.OpenApi) ;

    switch(this.OperationId){
        case "loginUser"                :{ this.loginUser                   (req) ; }
        case "logoutUser"               :{ this.logoutUser                  (req) ; }
        case "getUserByName"            :{ this.getUserByName               (req) ; }
        case "updateUser"               :{ this.updateUser                  (req) ; }
        case "deleteUser"               :{ this.deleteUser                  (req) ; }
        case "createUsersWithListInput" :{ this.createUsersWithListInput    (req) ; }
        case "createUser"               :{ this.createUser                  (req) ; }
        default:{
            // X.Debugf("User-Miss[%p][%s]" ,this,this.OperationId) ;
            this.loginUser(req) ;
        }
    }
}

///////////////////////////

func (this *HandlerUser) loginUser(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) logoutUser(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) getUserByName(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) updateUser(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) deleteUser(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) createUsersWithListInput(req *X.TypeReqRc){
    req.Dump() ;
}

func (this *HandlerUser) createUser(req *X.TypeReqRc){
    req.Dump() ;
}

///////////////////////////

func (this *HandlerStore)   ServeHTTP(w http.ResponseWriter, r *http.Request) {
    X.Debugf("Store[%s]"    ,this.OperationId) ;
    req := X.Req(&w,r,this.OperationId,this.ToolBox,this.OpenApi) ;
    req.Dump() ;
}

func    Entry() {

    X.Syslog(&X.TypeSyslogConfig{SockAddr:"unix:///dev/log", Facility: syslog.LOG_LOCAL7}) ;

    assoc := X.NewAssoc() ;
    i := assoc.IteratorKeys() ;

    for i.HasNext(){
        v,err := i.Next() ; _ = v ;
        if(err != nil){
            break ;
        }
    }

    toolBox := X.NewToolBox() ;

    router := mux.NewRouter() ;
    // router := X.NewRouter() ;
    // router := chi.NewRouter() ;

    openAPI,err := X.LoaderOpenAPI(&X.TypeConfigOpenAPI{PathJson: "./swagger.json"}) ;

    pets    := make(map[string]HandlerPet)      ; _ = pets ;
    users   := make(map[string]HandlerUser)     ; _ = users ;
    stores  := make(map[string]HandlerStore)    ; _ = stores ;

    if(err != nil){
        X.Debugf("err[%s]",err) ;
    }else{
        for _,paths := range openAPI.Paths(){
            switch(paths.Tag){
                case "pet":{
                    handler := &HandlerUser{ OpenApi: openAPI,ToolBox: toolBox,OperationId: paths.OperationId} ;
                    router.Handle(paths.Path,handler).Methods(paths.Method) ;
                }
                case "user":{
                    handler := &HandlerUser{ OpenApi: openAPI,ToolBox: toolBox,OperationId: paths.OperationId} ;
                    router.Handle(paths.Path,handler).Methods(paths.Method) ;
                }
                case "store":{
                    handler := &HandlerUser{ OpenApi: openAPI,ToolBox: toolBox,OperationId: paths.OperationId} ;
                    router.Handle(paths.Path,handler).Methods(paths.Method) ;
                }
            }
        }
    }

    http.ListenAndServe(":9005",router) ;
}

















