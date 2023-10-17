package BerdyshFrameworkGoLang

import (
    "bytes"
    "net/http"
    "net/url"
    "io"
    "fmt"
    "context"
    "strconv"
    "strings"
    "sync"
    "mime/multipart"
)

type TypeContentTypeParser struct {
    contentTypeFull string
    contentType     string
    contentTypeMime string
}

type TypeNoBody struct{}

func (*TypeNoBody) Read(p []byte) (n int, err error){
    return 0,io.EOF ;
}

type TypeBody struct{
    String string ;
}

func (this *TypeBody) Set(str string){
    this.String = str ;
}

func (this *TypeBody) Read(p []byte) (n int, err error){
    if(this.String == ""){
        return 0,io.EOF ;
    }else{
        src := []byte(this.String) ;
        n := len(src) ;
        for ii:=0;ii<n ; ii++ { p[ii] = src[ii] ; }
        this.String = "" ;
        return n,nil ;
    }
}

func ContentTypeParser(contentTypePostFull string) (TypeContentTypeParser,error){
    this := TypeContentTypeParser{} ;

    this.contentTypeFull = contentTypePostFull ;

    ar := strings.Split(contentTypePostFull,";")
    if(len(ar) >= 1){ this.contentType      = strings.TrimSpace(ar[0]) ; }
    if(len(ar) >= 2){ this.contentTypeMime  = strings.TrimSpace(ar[1]) ; }

    return this,nil ;
}

func    IsMatchContentType(a string,b string) (bool){
    aa,_ := ContentTypeParser(a)
    bb,_ := ContentTypeParser(b)

    if(aa.contentType == bb.contentType){
        return true ;
    }else{
        return false ;
    }
}

type TypeClient struct {
    Base    string ;

    Hnd     http.Client ;
}

type TypeClientRes struct {
    Cli *TypeClient ;
    Err error ;
}

func (rc *TypeClientRes) Init(cli *TypeClient) (*TypeClientRes){
    rc.Cli = cli ;
    rc.Err = errorf("TypeClientRes Not Init.") ;
    return rc ;
}

func(this *TypeClientRes) Error(opts ... interface{}) (error){
    if(len(opts) != 0){
        this.Err = nil ;
    }
    return this.Err ;
}

func (cli *TypeClient) NewRes() (*TypeClientRes){
    ret := &TypeClientRes{} ;
    return ret.Init(cli) ;
}

func (this *TypeClient) SelfTest_0001() (error){

    params := NewAssoc() ;
    params.SetKV("username","uuu") ;
    params.SetKV("password","ppp") ;

//  url := this.Base + "/user/login" + "?" + params.EncodeCGI() ;
    url := this.Base + "/user/login" + "?" + params.EncodeCGI() ;

    printf("URL[%s]\n", url)

    r, err := http.Get(url) ;

    if(err != nil){
        Debugf("err[%s]",err) ;
        return err ;
    }

    ContentType := "" ; _ = ContentType ;

    Debugf("OK[%d][%s]",r.StatusCode,r.Proto) ;
    for k,v := range r.Header{
        switch(k){
            case "Content-Type":{
                ContentType = v[0] ;
            }
        }
    }

    body, err := io.ReadAll(r.Body)
    r.Body.Close()

    if((r.ContentLength != -1) && (r.ContentLength != (int64)(len(body)))){ Debugf("ContentLength[%d:%d]",r.ContentLength,len(body)) ; }

    Debugf("BODY[%s]", body)
    Debugf("ContentType[%s]", ContentType)

    kv := NewKV() ;

    if(IsMatchContentType("application/json",ContentType)){
        reqJson := NewAssoc().DecodeJson(body) ;
        for i := reqJson.Iterator() ; i.HasNext(kv) ;i.Next(){
            k,t,v := kv.KTV() ;
            Debugf("[%v][%s][%v]",k,t,v) ;
        }
    }

    return nil ;
}

func (this *TypeClient) SelfTest_0002() (error){

    cli := NewClient() ;

    if(true){
        params := NewAssoc().SetKV("json_param","漢字").SetKV("json_hoge","   ") ; _ = params ;
        upstream := params ;
//      upstream := "HOHOHO" ;

        _ = upstream ;

//      url := this.Base + "/user/login" + "?" + params.EncodeCGI() ;
//      url := this.Base + "/user/hoge" ;
//      url := this.Base + "/Echo/" + "?" + params.EncodeCGI() ;
        url := this.Base + "/Echo/" ;

        Debugf_("!!URL[%s]\n", url) ;

        headers := NewAssoc().SetKV("X-Test-Hoge","hoge") ; _ = headers ;
        auth := NewAssoc().SetKV("KIND","Basic").SetKV("USER","user").SetKV("PASS","pass") ; _ = auth ;

//      Q := NewAssoc().SetKV("URL",url).SetKV("FORM",upstream).SetKV("HEADERS",headers) ;

        Q := NewAssoc().SetKVx(KV{K:METHOD,V:POST},KV{K:URL,V:url}) ;

        res := cli.NewRes() ;

        cli.Do(Q,res) ;
    }

    return nil ;
}

func (this *TypeClient) SelfTest(){
    this.SelfTest_0002() ;
}

func (this *TypeClient) Do(opts ... interface{}){

    Q   := NewAssoc() ;
    var rc  *TypeClientRes = nil ;

    var err         error           ; _ = err ;
    var req         *http.Request   ; _ = req ;
    var res         *http.Response  ; _ = res ;

    var bodyPost    = &TypeBody{} ;
    var post_str    string          ; _ = post_str ;

    url := ""                       ; _ = url ;
    method := ""                    ; _ = method ;

    KIND_UPSTREAM := ""             ; _ = KIND_UPSTREAM ;
    content_typeUPSTREAM := ""      ; _ = content_typeUPSTREAM ;
    var upstream any                ; _ = upstream ;            

    for _,opt := range opts{
        t := GetTypeParse(opt) ;

        Debugf("[%s][%s]",t.Name,t.Kind) ;

        if(t.Kind == "map"){
            if(t.IsMapStandard){
                Q.SetMapStandard(opt.(map[string]interface {})) ;
            }
        }else{
            switch(t.Name){
                case "TypeClientRes":{
                    switch(t.Kind){
                        case "ptr":{
                            rc = opt.(*TypeClientRes) ;
                        }
                    }
                }
                case "KV":{
                    switch(t.Kind){
                        case "slice":{
                            for _,kv := range opt.([]KV){
                                Q.SetKV(kv.K,kv.V) ;
                            }
                        }
                    }
                }
                case "TypeAssoc":{
                    switch(t.Kind){
                        case "ptr":{
                            Q.Clone(opt.(*TypeAssoc)) ;
                        }
                    }
                }
                default:{
                    Debugf("Unknown[%s][%s]",t.Name,t.Kind) ;
                }
            }
        }
    }

    if(rc == nil){
        return ;
    }else{
        rc.Err = nil ;
    }

    kv := NewKV() ;
    for i := Q.Iterator() ; i.HasNext(kv) ;i.Next(){
        k,_,v := kv.KTV() ;
        switch(k){
            case URL:{ url = v.String() ; }
            case METHOD:{ method = v.String() ; }
            case HEADERS:{
                for ii := v.Iterator() ; ii.HasNext(kv) ;ii.Next(){
                    K,_,v := kv.KTV() ;
                    k = Strtolower(K) ;
                    if(k == "content-type"){
                        Debugf("[%s][%s]\n",k,v.String()) ;
                        content_typeUPSTREAM = v.String() ;
                    }
                }
            }
            case "UPSTREAM","JSON","FORM","MULTIPART":{
                KIND_UPSTREAM = k.(string) ;
            }
        }
    }

    if(url == ""){
        rc.Err = errorf("URL is nil") ;
        return ;
    }

    if(method == ""){
        if(KIND_UPSTREAM != ""){
            method = "POST" ;
        }else{
            method = "GET" ;
        }
    }

    for i := Q.Iterator() ; i.HasNext(kv) ;i.Next(){
        k,_,v := kv.KTV() ;
        switch(k){
            case "UPSTREAM","JSON","FORM","MULTIPART":{
                if(v.Type() == "string"){
                    upstream = v.String() ;
                }else{
                    upstream = v ;
                }
                KIND_UPSTREAM = k.(string) ;
            }
        }
    }

    if(KIND_UPSTREAM != ""){
        if(IsType(upstream,&TypeAssoc{})){

            if(content_typeUPSTREAM != ""){
                switch(content_typeUPSTREAM){
                    case "application/x-www-form-urlencoded":{
                        post_str = upstream.(*TypeAssoc).EncodeCGI() ;
                    }
                    case "application/json":{
                        post_str = upstream.(*TypeAssoc).EncodeJson() ;
                    }
                }
            }else{
                switch(KIND_UPSTREAM){
                    case "FORM":{
                        post_str = upstream.(*TypeAssoc).EncodeCGI() ;
                    }
                    case "JSON":{
                        post_str = upstream.(*TypeAssoc).EncodeJson() ;
                    }
                    default:{
                        Debugf("KIND_UPSTREAM[%s]",KIND_UPSTREAM) ;
                    }
                }
            }
        }
        if(IsType(upstream,"")){
            post_str = upstream.(string) ;
        }

        bodyPost.Set(post_str) ;
    }

    Debugf("[%s][%s]\n",method,url) ;
    ctx := context.Background() ; _ = ctx ;

//    req,err = http.NewRequest(method,url,bodyPost) ;
    req,err = http.NewRequest(method,url,bytes.NewBuffer([]byte(post_str))) ;

    for i := Q.Iterator() ; i.HasNext(kv) ;i.Next(){
        k,_,v := kv.KTV() ;
        switch(k){
            case "HEADERS":{
                for ii := v.Iterator() ; ii.HasNext(kv) ;ii.Next(){
                    K,_,v := kv.KTV() ;
                    k = Strtolower(K) ;
                    Debugf("[%s][%s]\n",k,v.String()) ;
                    if(k == "content-type"){
                        req.Header.Set(k.(string),v.String()) ;
                    }else{
                        req.Header.Set(k.(string),v.String()) ;
                    }
                }
            }

            case "AUTH":{
                for ii := v.Iterator() ; ii.HasNext(kv) ;ii.Next(){
                    k,_,v := kv.KTV() ;
                    Debugf_("[%s][%s]\n",k,v.String()) ;
                }
            }
        }
    }

    if(KIND_UPSTREAM != ""){
        if(content_typeUPSTREAM == ""){
            switch(KIND_UPSTREAM){
                case POST_JSON:{
                    content_typeUPSTREAM = "application/json" ;
                }
                case POST_FORM:{
                    content_typeUPSTREAM = "application/x-www-form-urlencoded" ;
                }
                case POST_MULTIPART:{
                    content_typeUPSTREAM = "multipart/form-data" ;
                }
                default:{
                    content_typeUPSTREAM = "application/octet-stream" ;
                }
            }
            req.Header.Set("content-type",content_typeUPSTREAM) ;
        }

//      req.Header.Set("content-length",sprintf("%d",len(post_str))) ;

        Debugf("KIND[%s][%s][%s]",KIND_UPSTREAM,content_typeUPSTREAM,post_str) ;
    }

    res, err = this.Hnd.Do(req) ;

    if(err != nil){
        rc.Err = err ;
        return ;
    }
        
    Debugf("StatusCode[%d]\n",res.StatusCode) ;
//  Debugf("ContentLength[%d]\n",res.ContentLength ) ;
    header := NewAssoc() ;
    for k,v := range res.Header{
        header.SetKV(k,v[0])
    }

    Debugf_("[%s]",header.String()) ;

    defer res.Body.Close() ;

    if(false){
        bbb := make([]byte,4096) ;
        n,err := res.Body.Read(bbb) ;

        if(err != nil){
            Debugf("err[%s]",err) ;
        }else{
            Debugf("n[%d]",n) ;
            Debugf("[%str]",string(bbb)) ;
        }
    }else{
        payload, e := io.ReadAll(res.Body) ;
        if(e != nil){
            Debugf("err[%s]\n",e) ;
        }else{
            s := Strval(payload) ;
            Debugf("Len[%d]\n",len(s)) ;
            Debugf("BODY[%s]\n",s) ;
        }
    }

    return ;
}

func (cli *TypeClient) Init() (*TypeClient){

    cli.Hnd = http.Client{}

    return cli ;
}


func NewClient(opts ... interface{}) (*TypeClient){
    var ret *TypeClient ;
    ret = &TypeClient{} ;
    return ret.Init() ;
}

type HttpServerOption struct {
    Addr    string ;
}

type Cookie struct {
    Name    string ;
    Value   string ;
}

type ReqHttp struct {
    Method      string ;
    Path        string ;
    QueryString string ;
    RemoteAddr  string ;
    Host        string ;

    ContentLength   int64 ;
    ContentType     string ;
    Charset         string ;
    Boundary        string ;

    PostRaw         string ;

    Cookies         map[string]Cookie ;
    Headers         map[string]string ;
    HeadersMulti    map[string][]string ;
}

type EzHeader struct {
    P   *ResHttp ;
}

func (this *EzHeader) Set(K string,v string) (*EzHeader){

    k := ToLower(K) ;

    this.P.Headers[k] = v ;

    return this ;
}

type EzCookie struct {
}

func (this *EzCookie) Set(opts ... any){
}

type ResHttp struct {
    Status          int ;
    ContentType     string ;
    Charset         string ;
    fifo            string ;
    ezHeader        EzHeader ;
    Headers         map[string]string ;
    InitHeaders     bool ;

    Cookie          EzCookie ;
}

type multipartReader struct {
    PostRaw string ;
    Reader  io.Reader ;
}

func (this *multipartReader) Read(p []byte) (n int, err error){
    max := len(p) ;

    if(this.Reader != nil){
        return this.Reader.Read(p) ;
    }

    if(this.PostRaw != ""){

        b := []byte(this.PostRaw) ;

        L := len(b) ;

        if(max >= L){
            for idx,x := range b {
                p[idx] = x ;
            }
            return L,nil ;
        }
    }

    return 0,Errorf("MEM") ;
}

func NewReqHttp(req *http.Request) (ReqHttp){
    Q := ReqHttp{} ;

    Q.Method        = req.Method ;
    Q.Path          = req.URL.Path ;
    Q.QueryString   = req.URL.RawQuery ;
    Q.RemoteAddr    = req.RemoteAddr ;
    Q.Host          = req.Host ;

    Q.Headers       = make(map[string]string) ;
    Q.HeadersMulti  = make(map[string][]string) ;

    for K,vs := range req.Header{
        k := ToLower(K) ;
        switch(k){
            case "content-type":{
                printf("TTTTTTTTTTTTTTTTTT[%s]\n",vs[0]) ;
                tokens := strings.Split(vs[0], ";") ;

                Q.ContentType   = "" ;
                Q.Charset       = "" ;
                Q.Boundary      = "" ;

                for idx,token := range tokens{
                    token = Trim(token) ;
                    if(idx == 0){
                        Q.ContentType = token ;
                    }else{
                        xx := strings.Split(token,"=") ;
                        if(len(xx) == 2){
                            k := ToLower(Trim(xx[0])) ;
                            v := Trim(xx[1]) ;
                            switch(k){
                                case "boundary":{
                                    Q.Boundary = v ;
                                }
                                case "charset":{
                                    Q.Charset = v ;
                                }
                            }
                        }
                    }
                }
            }
            case "content-length":{
                if i64,err := strconv.ParseInt(vs[0],10,64) ; (err != nil){
                    printf("err[%s][%s][%s]\n",k,err,vs[0]) ;
                }else{
                    Q.ContentLength = i64 ;
                }
            }
            default:{
                if(len(vs) == 1){
                    Q.Headers[k] = vs[0] ;
                }else{
                    Q.HeadersMulti[k] = vs ;
                }
            }
        }
    }

    if(Q.ContentLength > 0){
        Printf("[%s]/PostData[%s][%d]\n",Q.ContentType,Q.ContentType,Q.ContentLength) ;

        switch(Q.ContentType){
            case "application/x-www-form-urlencoded":{
                if err := req.ParseForm() ; (err != nil) {
                    printf("err[%s]\n",err) ;
                }else{
                    printf("OK[%T]\n",req.Form) ;
                    for k, vs := range req.Form {
                        for idx,v := range vs {
                            printf("%d[%s][%T][%s]\n",idx,k,v,v) ;
                        }
                    }
                }
            }
            case "multipart/form-data":{
                mpr := multipart.NewReader(&multipartReader{Reader: req.Body},Q.Boundary) ;
                if multipartForm,err := mpr.ReadForm(Q.ContentLength) ; (err != nil){
                    printf("err[%s]\n",err) ;
                }else{
                    for k,vs := range multipartForm.Value{
                        for idx,v := range vs {
                            printf("%d[%s][%T][%s]\n",idx,k,v,v) ;
                        }
                    }
                }
            }
            default:{
                buf := make([]byte, Q.ContentLength) ;

                //  req.Body io.ReadCloser = io.Reader + io.Close 

                if rcSz , err := req.Body.Read(buf) ; (err != nil){
                    if(err == io.EOF){
                        Q.PostRaw = (string)(buf[:rcSz]) ;
                    }else{
                        printf("err[%s]\n",err) ;
                    }
                }else{
                    Q.PostRaw = (string)(buf[:rcSz]) ;
                }
                switch(Q.ContentType){
                    default:{
                    }
                }
            }
        }

    }

    return Q ;
}

type ResponseWriter interface {
    Header()                        http.Header ;
    Write([]byte)                   (int, error) ;
    WriteHeader(statusCode int) ;
}

func NewResHttp() (ResHttp){
    A := ResHttp{} ;
    A.Status = 200 ;
    A.ContentType = "text/html" ;
    A.Charset = "utf-8" ;

    A.ezHeader.P = &A ;
    A.Headers   = make(map[string]string) ;
    A.InitHeaders = true ;

    return A ;
}

func (this *ResHttp) Write(p []byte) (n int, err error){
    this.fifo += string(p) ;
    return n,nil ;
}

func (this *ResHttp) Printf(format string,args ... any){
    str := fmt.Sprintf(format,args ...) ;
    this.fifo += str ;
}

func (this *ResHttp) Echo(opts ... any){
    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "string":{
                this.fifo += opt.(string) ;
            }
            case "[]uint8":{
                this.fifo += string(opt.([]uint8)) ;
            }
            case "[]int32":{
                this.fifo += string(opt.([]int32)) ;
            }
            case "int":{
                this.fifo += sprintf("%d",opt.(int)) ;
            }
            case "int32":{
                this.fifo += sprintf("%c",opt.(int32)) ;
            }
            default:{
                this.fifo += sprintf("Unknown[%s]",t) ;
            }
        }
    }
}

func (this *ResHttp) Header() (*EzHeader){
    return &(this.ezHeader) ;
}

func (this *ResHttp) WriteHeader(status int){
    this.Status = status ;
}

type EzRouterEntryInterface interface {
    Init() ;
    EvReqHttp(A *ResHttp,Q *ReqHttp) ;
    GetId() (string) ;
}

type EzHandler struct {
    Path    string ;
    Methods []string ;
    Handle  EzRouterEntryInterface ;
}

type EzRouter struct {
    server  *HttpServer ;

    Handlers    []EzHandler ;
} ;

type HttpServer struct {
    wait    sync.WaitGroup ;
    Addr    string ;
    Router  EzRouter ;
}

func (this *EzRouter) ServeHTTP(wrReal http.ResponseWriter,req *http.Request){

    var entry *EzHandler = nil ;

    for _,e := range this.Handlers {
        for _,m := range e.Methods{
            if(req.Method == m){
                entry = &e ;
            }
        }
    }

    if(entry != nil){

        Q := NewReqHttp(req) ;
        A := NewResHttp() ;

        entry.Handle.EvReqHttp(&A,&Q) ;

        for K,v := range A.Headers{
            k := ToLower(K) ;
            wrReal.Header().Set(k,v) ;
        }

        wrReal.WriteHeader(A.Status) ;

        if _,err := wrReal.Write([]byte(A.fifo)) ; (err != nil){
            Printf("err[%s]\n",err) ;
        }
    }
}

func NewHttpServer(opts ... any) (*HttpServer,error){
    server := HttpServer{} ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "*BerdyshFrameworkGoLang.HttpServerOption":{
                x := opt.(*HttpServerOption) ;
                server.Addr = x.Addr ;
            }
            case "BerdyshFrameworkGoLang.HttpServerOption":{
                x := opt.(HttpServerOption) ;
                server.Addr = x.Addr ;
            }
            default:{
                printf("Unknown[%s]\n",t) ;
            }
        }
    }

    return &server,nil ;
}

func (server *HttpServer) Method(opts ... any) (*HttpServer){
    idx := len(server.Router.Handlers) - 1 ;
    if(idx >= 0){
        e := &(server.Router.Handlers[idx]) ;
        for _,opt := range opts{
            t := sprintf("%T",opt) ;
            switch(t){
                case "string":{
                    m := ToUpper(opt.(string)) ;
                    switch(m){
                        case "GET","PUT","POST","DELETE","HEAD":{
                            e.Methods = append(e.Methods,m) ;
                        }
                        default:{
                            printf("Unknown[%s]\n",m) ;
                        }
                    }
                }
            }
        }
    }
    return server ;
}

func (server *HttpServer) EzHandle(path string,handle  EzRouterEntryInterface) (*HttpServer){

    handle.Init() ;

    h := EzHandler{} ;

    h.Path  = path ;
    h.Handle = handle ;

    server.Router.Handlers = append(server.Router.Handlers,h) ;

    return server ;
}

func (this *HttpServer) DoProc(){
    this.wait.Add(1) ;

    go func(server *HttpServer){

        addr := ":8080" ;

        if ui , err := url.Parse(server.Addr) ; (err != nil){
            printf("err[%s].\n",err) ;
        }else{
            addr = ui.Host ;
        }

        this.wait.Done() ;

        server.Router.server = server ;
        http.ListenAndServe(addr,&(server.Router)) ;
    }(this) ;

    this.wait.Wait() ;
}














































