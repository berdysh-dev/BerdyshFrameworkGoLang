package BerdyshFrameworkGoLang

import (
    "net/http"
)

type TypeRouterItem struct {
    path        string ;
    handler     http.Handler ;
    methods     map[string]bool ;
}

func (this *TypeRouterItem) Init() (*TypeRouterItem){
    this.methods = make(map[string]bool) ;
    return this ;
}

type TypeRouter struct {
    items []*TypeRouterItem ;
    strictSlash bool ;
}

func (this *TypeRouter) Init() (*TypeRouter){
    this.items = make([]*TypeRouterItem,0) ;
    return this ;
}

func (item *TypeRouterItem) isMatch(r *http.Request) (bool){

    var isOkMethod = false ;

    if(len(item.methods) == 0){
        isOkMethod = true ;
    }else{
        method,ok := item.methods[r.Method] ;
        if(ok){
            isOkMethod = method ;
        }
    }

    Debugf("[%s][%v][%s][%s]",r.Method,isOkMethod,r.RequestURI,item.path) ;

    return false ;
}

func (this *TypeRouter) ServeHTTP(w http.ResponseWriter,r *http.Request){


    for _,item := range this.items{
        if(item.isMatch(r) == true){
            item.handler.ServeHTTP(w,r)
            break ;
        }
    }
}

func (this *TypeRouter) StrictSlash(b bool) (*TypeRouter){
    this.strictSlash = b ;
    return this ;
}

func (this *TypeRouter) Handle(path string,handler http.Handler) (*TypeRouterItem){

    routerItem := TypeRouterItem{}
    routerItem.Init();
    routerItem.path = path ;
    routerItem.handler = handler ;
    this.items = append(this.items,&routerItem) ;
    return &routerItem ;
}

func (routerItem *TypeRouterItem) Methods(args ... any) (*TypeRouterItem){
    for _,method := range args{
        routerItem.methods[method.(string)] = true ;
    }
    return routerItem ;
}

func NewRouter() (*TypeRouter){
    ret := TypeRouter{}
    ret.Init() ;
    return &ret ;
}













