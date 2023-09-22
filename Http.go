package BerdyshFrameworkGoLang

import (
    "bytes"
    "net/http"
    "io"
    "fmt"
    "context"
_   "strconv"
    "strings"
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
    rc.Err = fmt.Errorf("TypeClientRes Not Init.") ;
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

    fmt.Printf("URL[%s]\n", url)

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
        rc.Err = fmt.Errorf("URL is nil") ;
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

//      req.Header.Set("content-length",fmt.Sprintf("%d",len(post_str))) ;

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


















































