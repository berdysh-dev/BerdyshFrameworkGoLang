package BerdyshFrameworkGoLang

import (
_   "errors"
    "fmt"
    "flag"
    "log/syslog"
    "net/http"
    "net/url"
    "sync"
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

type Router struct {
    Items []*TypeRouterItem ;
    StrictSlashFlag     bool ;

    IsMatchItemByhttpRequest    TypeFuncIsMatchItemByhttpRequest ;
}

type TypeRouterRequest struct {
    Croak   map[string]interface{}
}

type Param struct {
    Key     string
    Value   string
}

type Params []Param

type Context struct {
//  writermem       responseWriter
    Request         *http.Request
//  Writer          ResponseWriter
    Params          Params
//  handlers        HandlersChain
    index           int8
    fullPath        string
//  engine          *Engine
    params          *Params
//  skippedNodes    *[]skippedNode

    mu              sync.RWMutex
    Keys            map[string]any
//  Errors          errorMsgs
    Accepted        []string
    queryCache      url.Values
    formCache       url.Values
    sameSite        http.SameSite
}

type routeNode struct {
}

type Parameter struct {
    *routeNode
    path       string
    wildcard   int
}

func (this *Router) AddRoute(args ... any){} ;

func (this *Context) JSON(code int,obj any){}
func (this *Context) String(args ... any) (error){ return nil ; }

type TypeFuncGinLike func (ctx *Context) ;
type TypeFuncChiLike func (w http.ResponseWriter,r *http.Request) (error) ;
type TypeFuncChiRouteLike func (r Router) ;

func (this *Router) GET(args ... any){} ;
func (this *Router) PUT(args ... any){} ;
func (this *Router) POST(args ... any){} ;
func (this *Router) DELETE(args ... any){} ;

func (this *Router) Get(args ... any){} ;
func (this *Router) Post(args ... any){ } ;

func (this *Router) Put(args ... any){} ;
func (this *Router) Delete(args ... any){} ;

func (this *Router) Route(args ... any){} ;

func (this *Router) Use(args ... any){} ;

func Logger() (int){ return 0 ; }

func Recover() (int){ return 0 ; }

type H map[string]string ;

// goji.web
type C struct {
    URLParams   map[string]string ;
} ;

func Get(args ... any){
}

var bind string ;

func init() {
  flag.StringVar(&bind, "s", "", "文字列の場合の例")
}

func Serve(){
    flag.Parse() ;

    Debugf("できたかな？[%s]",bind) ;

}

type TypeFuncIsMatchItemByhttpRequest func (router *Router,Q *TypeRouterRequest,item *TypeRouterItem,r *http.Request) (bool) ;

func DefaultIsMatchItemByhttpRequest(router *Router,Q *TypeRouterRequest,item *TypeRouterItem,r *http.Request) (bool){
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

func (this *Router) Init() (*Router){
    this.Items = make([]*TypeRouterItem,0) ;
    this.IsMatchItemByhttpRequest = DefaultIsMatchItemByhttpRequest ;
    return this ;
}

func (router *Router) ServeHTTP(w http.ResponseWriter,r *http.Request){
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

func (this *Router) SetFuncIsMatchItemByhttpRequest(cb TypeFuncIsMatchItemByhttpRequest) (*Router){
    this.IsMatchItemByhttpRequest = cb ;
    return this ;
}

func (this *Router) StrictSlash(b bool) (*Router){
    this.StrictSlashFlag = b ;
    return this ;
}

func (this *Router) LoaderConfig(args ... any) (*Router){
    return this ;
}

func (router *Router) LoaderRPC(handlerRPCs ... ExHandlerRPC) (*Router){
    for _,h := range handlerRPCs{
        routerItem := TypeRouterItem{}
        routerItem.Init();
        routerItem.HandlerRPC   = h ;
        routerItem.OperationId  = h.OperationId()
        router.Items = append(router.Items,&routerItem) ;
    }
    return router ;
}

func (this *Router) AddOperationId(operationId string,handlerORG http.Handler) (*Router){
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

func (this *Router) Handle(args ... interface{}) (*TypeRouterItem){
    routerItem := TypeRouterItem{}
    routerItem.Init();
    routerItem.Args = args ;
    this.Items = append(this.Items,&routerItem) ;
    return &routerItem ;
}

func (this *Router) HandleFunc(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Queries(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Name(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) FuncGet(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) FuncPost(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) AddHandlerByOperationId(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Host(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) PathPrefix(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Methods(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Schemes(args ... interface{}) (*Router){
    return this ;
}

func (this *Router) Headers(args ... interface{}) (*Router){
    return this ;
}

func Default() (*Router){
    ret := Router{}
    return ret.Init() ;
}

func New() (*Router){
    return NewRouter() ;
}

func NewRouter() (*Router){
    ret := Router{}
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

type TypeVersionOpenAPI struct {
    Version string
}

type TypeServersEntryOpenAPI struct {
    Url string ;
}

type TypeServersOpenAPI struct {
    defs []TypeServersEntryOpenAPI ;
}

func OpenAPI_Decode_servers(ch *TypeAssoc) (TypeServersOpenAPI){

    ret := TypeServersOpenAPI{} ;

    defs := make([]TypeServersEntryOpenAPI,0) ;

    Debugf_("Type[%s]",ch.Type()) ;
    if(ch.IsArray()){
        i := ch.Iterator() ;
        for i.HasNext(){
            Key,_ := i.Next() ;
            v := ch.GetAssoc(Key) ;
            if(v.IsStandardMap()){
                def := TypeServersEntryOpenAPI{} ;
                ii := v.Iterator() ;
                for ii.HasNext(){
                    K2,_ := ii.Next() ;
                    vv := v.GetAssoc(K2) ;

                    switch(K2){
                        case "url":{
                            def.Url = vv.String() ;
                        }
                        default:{
                            Debugf("K2[%s][%s]",K2,vv.String()) ;
                        }
                    }

                }
                defs = append(defs,def) ;
            }
        }
    }

    ret.defs = defs ;

    return ret ;
}

func OpenAPI_Decode_tags(ch *TypeAssoc) (error){ return nil ; }
func OpenAPI_Decode_externaldocs(ch *TypeAssoc) (error){ return nil ; }

func OpenAPI_Decode_components(ch *TypeAssoc) (error){
    // Debugf("Type[%s]",ch.Type()) ;
    // Debugf("String[%s]",ch.String()) ;
    return nil ;
}

func OpenAPI_Decode_openapi(ch *TypeAssoc) (TypeVersionOpenAPI){

    ret := TypeVersionOpenAPI{} ;

    if ok,str := IsString(ch) ; (ok == true){
        ret.Version = str ;
    }else{
        Debugf("String変換不可") ;

        Debugf("Type[%s]",ch.Type()) ;
        Debugf("String[%s]",ch.String()) ;
    }

    return ret ;
}

func OpenAPI_Decode_info(ch *TypeAssoc) (TypeInfoOpenAPI){
    ret := TypeInfoOpenAPI{} ;

    i := ch.Iterator() ;
    for i.HasNext(){
        Key,_ := i.Next() ;
        key := Strtolower(Key) ;
        v := ch.GetAssoc(Key) ;
        switch(key){
            case "title":{
                ret.Title = v.String() ;
            }
            case "termsofservice":{
                ret.TermsOfService = v.String() ;
            }
            case "contact":{
                ii := v.Iterator() ;
                for ii.HasNext(){
                    K2,_ := ii.Next() ;
                    vv := v.GetAssoc(K2) ;
                    Debugf_("[%s][%s][%s]",key,K2,vv.String()) ;
                }
            }
            case "license":{
                ii := v.Iterator() ;
                for ii.HasNext(){
                    K2,_ := ii.Next() ;
                    vv := v.GetAssoc(K2) ;
                    Debugf_("[%s][%s][%s]",key,K2,vv.String()) ;
                }
            }
            case "description":{
                ret.Description = v.String() ;
            }
            case "version":{
                ret.Version = v.String() ;
            }
            default:{
                Debugf("[%s][%s]",key,v.Type()) ;
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
                    case "type":{ Debugf("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "format":{ Debugf("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "description":{ Debugf("[%s][%s][%s][%s][%s]",name,t,x,k,v) ; }
                    case "enum":{
                        for _,e := range v.([]any){
                            Debugf("[%s][%s][%s][%s][%s]",name,t,x,k,e.(string)) ;
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

type TypeParameterOpenAPI struct {
    Name        string ;
    Required    bool ;
    In          string ;
    Type        string ;
    Format      string ;
    Description string ;
}

type TypePathsOpenAPI struct {
    Tag             string ;
    OperationId     string ;
    Path            string ;
    Method          string ;
    Parameters      map[string]TypeParameterOpenAPI ;
}


func OpenAPI_Decode_paths(ch *TypeAssoc) ([]TypePathsOpenAPI){
    ret := make([]TypePathsOpenAPI,0)

    if(ch.IsStandardMap()){
        var kv TypeKV ;
        for i := ch.Iterator() ; i.HasNext(&kv) ;i.Next(){
            Path ,v := kv.GetStringAssoc() ;
            Debugf_("[%s][%T]",Path,v);
            if(v.IsStandardMap()){
                for ii := v.Iterator() ; ii.HasNext(&kv) ;ii.Next(){
                    method ,vv := kv.GetStringAssoc() ;
                    Debugf_("[%s]",method) ;
                    if(vv.IsStandardMap()){
                        for iii := vv.Iterator() ; iii.HasNext(&kv) ;iii.Next(){
                            k ,def := kv.GetStringAssoc() ;
                            Debugf_("[%s]",k);
                            switch(k){
                                case "tags":{
                                    if(def.IsArray()){
                                        for ix := def.Iterator() ; ix.HasNext(&kv) ; ix.Next() {
                                        }
                                    }
                                }
                                case "summary":{}
                                case "x-swagger-router-controller":{}
                                case "description":{}
                                case "operationId":{}
                                case "parameters":{
                                    if(def.IsArray()){
                                        for ix := def.Iterator() ; ix.HasNext(&kv) ; ix.Next() {
                                            _,v3 := kv.GetIntAssoc() ;
                                            if(v3.IsStandardMap()){
                                                for iz := v3.Iterator() ; iz.HasNext(&kv) ; iz.Next() {
                                                    kk ,_ := kv.GetStringAssoc() ;
                                                    Debugf("[%s]",kk);
                                                }
                                            }
                                        }
                                    }
                                }
                                case "responses":{}
                                case "security":{}
                                case "requestBody":{}
                                default:{
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    

/*

            Debugf("[%V]",v);

    for path,pathDef := range m{
        for method,methodDef := range pathDef.(map[string]interface{}){
            operationId := "" ;
            var tags any = nil ;
            parameters := make(map[string]TypeParameterOpenAPI) ;
            for k,v := range methodDef.(map[string]interface{}){
                switch(strings.ToLower(k)){
                    case "operationid":{ operationId = v.(string) ; }
                    case "tags":{ tags = v ; }
                    case "parameters":{
                        for _,vv := range v.([]interface{}){
                            parameter := TypeParameterOpenAPI{} ;
                            name := "" ;
                            Debugf_("-------------------------------------------------") ;
                            for kkk,vvv := range vv.(map[string]interface{}){
                                switch(kkk){
                                    case "name":{
                                        name = vvv.(string) ;
                                        parameter.Name = name ;
                                    }
                                    case "in":{ parameter.In = vvv.(string) ; }
                                    case "description":{ parameter.Description = vvv.(string) ; }
                                    case "required":{ parameter.Required = vvv.(bool) ; }
                                    case "schema":{
                                        for kkkk,vvvv := range vvv.(map[string]interface{}){
                                            switch(kkkk){
                                                case "type":{ parameter.Type = vvvv.(string) ; }
                                                case "format":{ parameter.Format = vvvv.(string) ; }
                                                case "items":{ Debugf_("[%s][%V]",kkkk,vvvv) ; }
                                                case "enum":{ Debugf_("[%s][%V]",kkkk,vvvv) ; }
                                                case "default":{ Debugf_("[%s][%V]",kkkk,vvvv) ; }
                                                default:{ Debugf_("[%s][%V]",kkkk,vvvv) ; }
                                            }
                                        }
                                    }
                                }
                            }
                            if(name != ""){
                                parameters[name] = parameter ;
                            }
                        }
                    }
                    case "requestbody":{
                        for kk,vv := range v.(map[string]interface{}){
                            switch(kk){
                                case "content":{
                                    for kkk,vvv := range vv.(map[string]interface{}){
                                        switch(kkk){
                                            case "application/json":{
                                                for k3,v3 := range vvv.(map[string]interface{}){
                                                    switch(k3){
                                                        case "schema":{
                                                            for k4,v4 := range v3.(map[string]interface{}){
                                                                switch(k4){
                                                                    case "$ref":{
                                                                        Debugf_("!!![%s][%s]",k4,v4.(string)) ;
                                                                    }
                                                                    case "type":{
                                                                        Debugf_("!!![%s][%s]",k4,v4.(string)) ;
                                                                    }
                                                                    case "items":{
                                                                        for k5,v5 := range v4.(map[string]interface{}){
                                                                            Debugf_("!!![%s][%V]",k5,v5) ;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    default:{
                        Debugf_("!!![%s]",k) ;
                    }
                }
            }
            x := TypePathsOpenAPI{} ;
            x.OperationId   = operationId ;
            x.Method        = strings.ToUpper(method) ;
            x.Path          = path ;
            x.Parameters    = parameters ;

            if(tags != nil){
                t := tags.([]interface{}) ;
                x.Tag = t[0].(string) ;
            }

            ret = append(ret,x) ;
        }
    }
*/
    return ret ;
}

type TypeRcLoaderOpenAPI struct {
    defs *TypeAssoc ;
}

/*
func (this *TypeRcLoaderOpenAPI) Paths() ([]TypePathsOpenAPI){
    return this.defs["paths"].([]TypePathsOpenAPI) ;
}
*/

func LoaderOpenAPI(conf *TypeConfigOpenAPI) (*TypeRcLoaderOpenAPI,error){

    ret := TypeRcLoaderOpenAPI{} ;
    ret.defs = NewAssoc() ;

    if(conf.PathJson != ""){

        swagger := NewAssoc().LoadFile(conf.PathJson) ;

        i := swagger.Iterator() ;
        for i.HasNext(){
            Key,err := i.Next() ;
            if(err != nil){
                Debugf("err[%s]",err) ;
                break ;
            }
            key := Strtolower(Key) ;
            ch := swagger.GetAssoc(Key) ;
            switch(key){
                case "servers"      :{ ret.defs.SetKV(key,OpenAPI_Decode_servers        (ch)) ; }
                case "info"         :{ ret.defs.SetKV(key,OpenAPI_Decode_info           (ch)) ; }
                case "tags"         :{ ret.defs.SetKV(key,OpenAPI_Decode_tags           (ch)) ; }
                case "paths"        :{ ret.defs.SetKV(key,OpenAPI_Decode_paths          (ch)) ; }
                case "externaldocs" :{ ret.defs.SetKV(key,OpenAPI_Decode_externaldocs   (ch)) ; }
                case "components"   :{ ret.defs.SetKV(key,OpenAPI_Decode_components     (ch)) ; }
                case "openapi"      :{ ret.defs.SetKV(key,OpenAPI_Decode_openapi        (ch)) ; }
            }
        }

        fmt.Printf("%s\n",ret.defs.String()) ;
    }

    return &ret,nil ;
}

func (this *Router) LoaderOpenAPI (conf *TypeConfigOpenAPI) (*Router){
    defs,err := LoaderOpenAPI(conf) ;
    _ = defs ;
    _ = err ;
    return this ;
}

func (this *Router) Start(opts ... any){
    addr := ":8080" ;
    if(len(opts) >= 1){
        addr = opts[0].(string) ;
    }
    http.ListenAndServe(addr,this) ;
}

func (this *Router) Run(opts ... any){
    addr := ":8080" ;
    if(len(opts) >= 1){
        addr = opts[0].(string) ;
    }
    http.ListenAndServe(addr,this) ;
}

type TypeReqRc struct {
    w               *http.ResponseWriter ;
    r               *http.Request ;
    OperationId     string ;
    ToolBox         *TypeToolBox ;
    OpenApi         *TypeRcLoaderOpenAPI ;
}

func Req(w *http.ResponseWriter, r *http.Request,OperationId string,toolBox *TypeToolBox,openApi *TypeRcLoaderOpenAPI) (*TypeReqRc){
    ret := TypeReqRc{}

    ret.w = w ;
    ret.r = r ;
    ret.OperationId = OperationId ;
    ret.ToolBox = toolBox ;
    ret.OpenApi = openApi ;

    return &ret ;
}

func (this *TypeReqRc) Dump(){
    Debugf("Dump[%s][%s]----------------------",this.r.Method,this.OperationId) ;
/*

    var paths TypePathsOpenAPI ; _ = paths ;

    flagPaths := false ;

    for _,v := range this.OpenApi.defs["paths"].([]TypePathsOpenAPI){
        if((v.OperationId != "") && (v.OperationId == this.OperationId)){
            paths = v ;
            flagPaths = true ;
        }
    }

    if(flagPaths){
        for _,param := range paths.Parameters{
            Debugf("%V",param) ;
        }
    }

    if(this.r.ContentLength > 0){
        contentTypePostFull := this.r.Header.Get("content-type") ;
        // Debugf("ContentLength[%d]",this.r.ContentLength) ;
        // Debugf("contentTypePostFull[%s]",contentTypePostFull) ;
        post_bytes := make([]byte,this.r.ContentLength) ;
        this.r.Body.Read(post_bytes) ;
        assoc := NewAssoc() ;
        assoc.LoadContents(contentTypePostFull,post_bytes) ;

        Debugf("%s",assoc.String()) ;

    }
*/

}

















