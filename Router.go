package BerdyshFrameworkGoLang

import (
    "net/http"
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

func (this *TypeRouter) LoaderOpenAPI(args ... any) (*TypeRouter){
    return this ;
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

func (this *TypeRouter) OperationId(args ... interface{}) (*TypeRouter){
    return this ;
}


func NewRouter() (*TypeRouter){
    ret := TypeRouter{}
    ret.Init() ;
    return &ret ;
}













