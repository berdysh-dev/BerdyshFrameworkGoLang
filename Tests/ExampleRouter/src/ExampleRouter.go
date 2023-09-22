package ExampleRouter

import (
_   "io"
    "fmt"
    "log/syslog"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/gin-gonic/gin"
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

func    Entry2() {
    X.SlogInit() ;
    X.Syslog(&X.TypeSyslogConfig{SockAddr:"unix:///dev/log", Facility: syslog.LOG_LOCAL7}) ;

    if(false){
        A := X.NewAssoc().Append("a").Append("b").Append("c") ;
        B := X.NewAssoc().Append("x").Append("y").Append("z") ;

        J := X.NewAssoc().SetKV("A",A).SetKV("B",B).SetKV("C","C").SetKV("D",123).SetKV("E",true) ;

        X.Debugf("Ans[%s]",J.String()) ;
    }
    if(false){

        optA1 := X.NewAssoc().Append(3,1,4) ;
        optB1 := X.NewAssoc().Append(9).Append(8).Append(7) ;
        optA2 := X.NewAssoc().Append("A").Append("B","C")
        optB2 := X.NewAssoc().Append("X","Y","Z")

        A := X.NewAssoc().SetKV("Name","AAA").SetKV("Age",17).SetKV("Opt1",optA1).SetKV("Opt2",optA2) ;
        B := X.NewAssoc().SetKV("Name","BBB").SetKV("Age",50).SetKV("Opt1",optB1).SetKV("Opt2",optB2) ;

        J := X.NewAssoc().Append(A,B) ;

        fmt.Printf("%s\n",J.ToLower().ToUpper().String()) ;
    }

    if(true){
        assoc := X.NewAssoc() ;
//      path := "/usr/local/GIT/BerdyshFrameworkGoLang/Tests/ExampleRouter/swagger.json" ;
        path := "/usr/local/GIT/BerdyshFrameworkGoLang/Tests/ExampleRouter/openapi.yaml" ;

        assoc.LoadFile(path) ;

        fmt.Printf("%s\n",assoc.String()) ;

        if(false){
            i := assoc.Iterator() ;
            for i.HasNext(){
                key,err := i.Next() ;
                if(err != nil){
                    X.Debugf("err[%s]",err);
                    break ;
                }

                X.Debugf("[%s]",key) ;
                as := assoc.GetAssoc(key) ;
                X.Debugf("[%V]",as.Type()) ;
            }
        }
    }
    X.Debugf("Fin") ;
}

func    Entry3() {

    X.SlogInit() ;
    X.Syslog(&X.TypeSyslogConfig{SockAddr:"unix:///dev/log", Facility: syslog.LOG_LOCAL7}) ;

    toolBox := X.NewToolBox() ; _ = toolBox ;

    router := mux.NewRouter() ;
    // router := X.NewRouter() ;
    // router := chi.NewRouter() ;

//  path := "/usr/local/GIT/BerdyshFrameworkGoLang/Tests/ExampleRouter/swagger.json" ;
    path := "/usr/local/GIT/BerdyshFrameworkGoLang/Tests/ExampleRouter/openapi.yaml" ;

    openAPI,err := X.LoaderOpenAPI(&X.TypeConfigOpenAPI{PathJson: path}) ; _ = openAPI ; _ = err ;

/*

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
*/

    fmt.Printf("Listn") ;

    http.ListenAndServe(":9005",router) ;
}

func    Entry() {

    router := gin.Default()

    cb_ping := func(ctx *gin.Context){

        for k,v := range ctx.Keys {
            X.Debugf("[%s][%T]",k,v);
        }

        for _,param := range ctx.Params {
            X.Debugf("[%s][%s]",param.Key,param.Value) ;
        }

        res := gin.H{ "message": "Pong", }

        ctx.JSON(200,res)
    } ;

    router.GET("/:id",cb_ping) ;

    // router.Run("localhost:9005")
    http.ListenAndServe(":9005",router) ;
}
















