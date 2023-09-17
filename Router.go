package BerdyshFrameworkGoLang

import (
    "log/syslog"
    "net/http"
    "strings"
    "encoding/json"
)

type ExHandlerRPC interface {
    ServeHTTP(http.ResponseWriter, *http.Request)
    OperationId() (string)
}

type TypeRouterItem struct {
    MethodsMap  map[string]bool ;

    OperationId string  ;
    Path        string  ;
    Name        string  ;
    Handler     any     ;
    Cb          any     ;
    XXX         any     ;

    Args        []interface{} ;

    HandlerORG  http.Handler  ;
    HandlerRPC  ExHandlerRPC  ;
}

func (this *TypeRouterItem) Init() (*TypeRouterItem){
    this.MethodsMap = make(map[string]bool) ;
    return this ;
}

type TypeRouter struct {
    Items []*TypeRouterItem ;
    StrictSlashFlag     bool ;

    IsMatchItemByhttpRequest    TypeFuncIsMatchItemByhttpRequest ;
}

type TypeRouterRequest struct {
    Croak   map[string]interface{}
}

type TypeFuncIsMatchItemByhttpRequest func (router *TypeRouter,Q *TypeRouterRequest,item *TypeRouterItem,r *http.Request) (bool) ;

func DefaultIsMatchItemByhttpRequest(router *TypeRouter,Q *TypeRouterRequest,item *TypeRouterItem,r *http.Request) (bool){
    var isOkMethod = false ; _ = isOkMethod ;
    if(len(item.MethodsMap) == 0){
        isOkMethod = true ;
    }else{
        method,ok := item.MethodsMap[r.Method] ;
        if(ok){
            isOkMethod = method ;
        }
    }
    return false ;
}

func (this *TypeRouter) Init() (*TypeRouter){
    this.Items = make([]*TypeRouterItem,0) ;
    this.IsMatchItemByhttpRequest = DefaultIsMatchItemByhttpRequest ;
    return this ;
}

func (router *TypeRouter) ServeHTTP(w http.ResponseWriter,r *http.Request){
    Q := TypeRouterRequest{} ;
    Q.Croak = make(map[string]interface{}) ;

    for _,item := range router.Items{
        if(item.HandlerRPC != nil){
            item.HandlerRPC.ServeHTTP(w,r)
        }else{
            item.HandlerORG.ServeHTTP(w,r)
        }
        break ;
    }
}

func (this *TypeRouter) SetFuncIsMatchItemByhttpRequest(cb TypeFuncIsMatchItemByhttpRequest) (*TypeRouter){
    this.IsMatchItemByhttpRequest = cb ;
    return this ;
}

func (this *TypeRouter) StrictSlash(b bool) (*TypeRouter){
    this.StrictSlashFlag = b ;
    return this ;
}

func (this *TypeRouter) LoaderConfig(args ... any) (*TypeRouter){
    return this ;
}

func (router *TypeRouter) LoaderRPC(handlerRPCs ... ExHandlerRPC) (*TypeRouter){
    for _,h := range handlerRPCs{
        routerItem := TypeRouterItem{}
        routerItem.Init();
        routerItem.HandlerRPC   = h ;
        routerItem.OperationId  = h.OperationId()
        router.Items = append(router.Items,&routerItem) ;
    }
    return router ;
}

func (this *TypeRouter) AddOperationId(operationId string,handlerORG http.Handler) (*TypeRouter){
    routerItem := TypeRouterItem{}
    routerItem.Init();
    routerItem.OperationId = operationId ;
    routerItem.HandlerORG = handlerORG ;
    return this ;
}

func (routerItem *TypeRouterItem) Methods(args ... any) (*TypeRouterItem){
    for _,method := range args{
        routerItem.MethodsMap[method.(string)] = true ;
    }
    return routerItem ;
}

func (this *TypeRouter) Handle(args ... interface{}) (*TypeRouterItem){
    routerItem := TypeRouterItem{}
    routerItem.Init();
    routerItem.Args = args ;
    this.Items = append(this.Items,&routerItem) ;
    return &routerItem ;
}

func (this *TypeRouter) HandleFunc(args ... interface{}) (*TypeRouterItem){
    routerItem := TypeRouterItem{}
    routerItem.Init();
    routerItem.Args = args ;
    this.Items = append(this.Items,&routerItem) ;
    return &routerItem ;
}

func (this *TypeRouter) FuncGet(args ... interface{}) (*TypeRouter){
    return this ;
}

func (this *TypeRouter) FuncPost(args ... interface{}) (*TypeRouter){
    return this ;
}

func (this *TypeRouter) AddHandlerByOperationId(args ... interface{}) (*TypeRouter){
    return this ;
}


func NewRouter() (*TypeRouter){
    ret := TypeRouter{}
    return ret.Init() ;
}

type TypeToolBox struct {}

func (this *TypeToolBox) Init() (*TypeToolBox){
    return this ;
}

func NewToolBox() (*TypeToolBox){
    ret := TypeToolBox{}
    return ret.Init() ;
}

type TypeSyslogConfig struct {
    SockAddr    string
    Facility    syslog.Priority
}

func Syslog(conf *TypeSyslogConfig){
}

type TypeConfigOpenAPI struct {
    PathJson    string ;
    PathYaml    string ;
}

type TypeInfoOpenAPI struct {
    Title               string ;
    Version             string ;
    TermsOfService      string ;
    Description         string ;
}

func OpenAPI_Decode_info(m map[string]interface{}) (TypeInfoOpenAPI){
    ret := TypeInfoOpenAPI{} ;

    for K,v := range m{
        k := strings.ToLower(K) ;
        switch(k){
            case "title":{
                ret.Title = v.(string) ;
            }
            case "termsofservice":{
                ret.TermsOfService = v.(string) ;
            }
            case "contact":{}
            case "license":{}
            case "description":{
                ret.Description = v.(string) ;
            }
            case "version":{
                ret.Version = v.(string) ;
            }
        }
    }

    return ret ;
}

type TypeDefinitionsOpenAPI struct {
}

func OpenAPI_Decode_definitions(m map[string]interface{}) (TypeDefinitionsOpenAPI){

    ret := TypeDefinitionsOpenAPI{} ;

    for name,xx := range m{
        vmap := xx.(map[string]interface{}) ;
        t := "" ;
        var properties any ;
        for k,v := range vmap{
            switch(k){
                case "type":{
                    t = v.(string) ;
                }
                case "properties":{
                    properties = v ;
                }
            }
        }
        for x,v := range properties.(map[string]interface{}){
            vmap := v.(map[string]interface{}) ;
            for k,v := range vmap{
                switch(k){
                    case "xml":{}
                    case "type":{ Debugf_("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "format":{ Debugf_("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "description":{ Debugf_("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "enum":{
                        for _,e := range v.([]any){
                            Debugf_("[%s][%s][%s][%s][%s]",name,t,x,k,e.(string)) ;
                        }
                    }
                    case "example":{
                        Debugf_("!!!!!!!!!![%s][%V]",k,v) ;
                    }
                    case "items":{
                        Debugf_("!!!!!!!!!![%s][%V]",k,v) ;
                    }
                    case "$ref":{
                        Debugf_("[%s][%s][%s][%s][%s]",name,t,x,k,v.(string)) ;
                    }
                    default:{
                        Debugf_("!!!!!!!!!![%s][%V]",k,v) ;
                    }
                }
            }
        }
    }

    return ret ;
}

type TypePathsOpenAPI struct {
    OperationId     string ;
    Path            string ;
    Method          string ;
}

func OpenAPI_Decode_paths(m map[string]interface{}) ([]TypePathsOpenAPI){
    ret := make([]TypePathsOpenAPI,0)
    for path,pathDef := range m{
        for method,methodDef := range pathDef.(map[string]interface{}){
            operationId := "" ;
            for k,v := range methodDef.(map[string]interface{}){
                switch(strings.ToLower(k)){
                    case "operationid":{
                        operationId = v.(string) ;
                    }
                }
            }
            x := TypePathsOpenAPI{} ;

            x.OperationId = operationId ;
            x.Method = strings.ToUpper(method) ;
            x.Path = path ;
            ret = append(ret,x) ;
        }
    }
    return ret ;
}

type TypeRcLoaderOpenAPI struct {
    defs map[string]interface{} ;
}

func (this *TypeRcLoaderOpenAPI) Paths() ([]TypePathsOpenAPI){
    return this.defs["paths"].([]TypePathsOpenAPI) ;
}

func LoaderOpenAPI(conf *TypeConfigOpenAPI) (TypeRcLoaderOpenAPI,error){

    ret := TypeRcLoaderOpenAPI{} ;

    defs := make(map[string]interface{}) ;

    if(conf.PathJson != ""){
        if text , err := File_get_contents(conf.PathJson) ; (err != nil){
            Debugf("err[%s]",err);
        }else{
            m := make(map[string]interface{}) ;
            json.Unmarshal([]byte(text),&m) ;
            for K,v := range m{
                k := strings.ToLower(K) ;
                switch(k){
                    case "paths"                :{ defs[k] = OpenAPI_Decode_paths(v.(map[string]interface{})) ; }
                    case "definitions"          :{ defs[k] = OpenAPI_Decode_definitions(v.(map[string]interface{})) ; }
                    case "info"                 :{ defs[k] = OpenAPI_Decode_info(v.(map[string]interface{})) ; }
                    case "tags"                 :{}
                    case "schemes"              :{}
                    case "securitydefinitions"  :{}
                    case "externaldocs"         :{}
                    case "swagger"              :{ defs[k] = v.(string) ; }
                    case "host"                 :{}
                    case "basepath"             :{}
                }
            }
        }
    }

    ret.defs = defs ;

    return ret,nil ;
}

func (this *TypeRouter) LoaderOpenAPI (conf *TypeConfigOpenAPI) (*TypeRouter){
    defs,err := LoaderOpenAPI(conf) ;
    _ = defs ;
    _ = err ;
    return this ;
}






