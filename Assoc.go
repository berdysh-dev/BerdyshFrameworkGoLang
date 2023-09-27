package BerdyshFrameworkGoLang

import (
    "reflect"
    "strings"
    "bytes"
    "net/url"
    "encoding/json"
    "github.com/goccy/go-yaml"
)

type TypeAssocRaw map[string]interface{}

type TypeAssoc struct {
    Raw interface{}
    xtype string ;

    inited  bool ;
    isMap   bool ;
    isArray bool ;
}

func (this *TypeAssoc) Init() (*TypeAssoc){
    return this ;
}

type TypeParse struct {
    Pkg             string
    Name            string
    Kind            string
    Ptr             bool
    IsMapStandard   bool ;
}

type Map map[string]interface{} ;

func GetTypeParse(x any) (TypeParse){
    ret := TypeParse{} ;
    tmp := "" ; _ = tmp ;

    t := GetType(x) ;
    rt := reflect.TypeOf(x) ;

    Debugf_("RT:Kind[%v]",rt.Kind()) ;
    Debugf_("RT:Name[%s]",rt.Name()) ;
    Debugf_("RT:PkgPath[%s]",rt.PkgPath()) ;

    ret.Kind = rt.Kind().String() ;

    if((t == "map[string]interface {}") || (t == "map[string]interface{}") || (t == "map[string]any")){
        ret.IsMapStandard = true ;
    }else{
        if(t[:1] == "*"){
            ret.Ptr = true ;
            tmp = t[1:] ;
        }else{
            ret.Ptr = false ;
            tmp = t ;
        }

        ar := strings.Split(tmp,".") ;

        if(len(ar) == 2){
            ret.Pkg     = ar[0] ;
            ret.Name    = ar[1] ;
        }else{
            ret.Name    = tmp ;
        }
    }

    return ret ;
}

func IsType(opts ... interface{}) (bool){
    m := make([]TypeParse,0) ;
    for _,opt := range opts{
        x := GetTypeParse(opt) ;
        m = append(m,x) ;
    }

    if(len(m) == 2){
        if((m[0].Name == m[1].Name) && (m[0].Ptr == m[1].Ptr)){
            return true ;
        }
    }

    return false ;
}

func (this *TypeAssoc) GetType(opts ... interface{}) string {
    if(len(opts) == 1){
        return GetType(opts[0]) ;
    }else{
        return GetType(this.Raw) ;
    }
}

func (this *TypeAssoc) GetType2(t interface{}) (string,reflect.Kind) {
    return sprintf("%T",t),reflect.TypeOf(t).Kind() ;
}

func (this *TypeAssoc) conv_r (mode int,src interface{}) (interface{},error){

    tt := reflect.TypeOf(src).Kind() ;

    if((tt == reflect.Slice) || (tt == reflect.Array)){

        a,b := GetType2(src) ; _ = a ; _ = b ;

        if(a == "[]interface {}"){
            ret := make([]interface {},0) ;
            for _, v := range src.([]interface {}){
                x,_ := this.conv_r(mode,v) ;
                ret = append(ret,x) ;
            }
            return ret,nil ;
        }else{
            ret := make([]map[string]interface {},0) ;
            for _, v := range src.([]map[string]interface{}){
                x,_ := this.conv_r(mode,v) ;
                ret = append(ret,x.(map[string]interface {})) ;
            }
            return ret,nil ;
        }
    }else if(tt == reflect.Map){

        a,b := GetType2(src) ; _ = a ; _ = b ;

        if(a != "map[string]interface {}"){
            Debugf("!!![%s][%s][%s]",tt,a,b) ;
        }else{
            ret := make(map[string]interface{}) ;

            for k, v := range src.(map[string]interface{}) {
                var k2 string ;

                if(mode == 0){
                    k2 = k ;
                }else if(mode == 1){
                    k2 = UC(k) ;
                }else{
                    k2 = LC(k) ;
                }

                if(v == nil){
                    ret[k2] = nil ;
                    continue ;
                }

                t := reflect.TypeOf(v).Kind() ;

                switch(t){
                case reflect.Slice:
                    fallthrough
                case reflect.Array:{
                    var slice []interface{} ;
                    for _, vv := range v.([]interface{}) {
                        a,b := GetType2(vv) ; _ = a ; _ = b ;
                        // Debugf("[%s][%s]\n",a,b);
                        var x any ;
                        switch(a){
                            // case "string":{ x,_ = vv.(string) ; }
                            default:{
                            //  x,_ = this.conv_r(mode,vv.(map[string]interface{})) ;
                                x,_ = this.conv_r(mode,vv) ;
                            }
                        }
                        slice = append(slice,x) ;
                    }
                    ret[k2] = slice ;
                }
                case reflect.Map:{
                    x,_ := this.conv_r(mode,v.(map[string]interface{})) ;
                    ret[k2] = x ;
                }
                case reflect.Float32:
                    fallthrough
                case reflect.Float64:{
                    if(true){
                        ret[k2] = int64(v.(float64)) ;
                    }else{
                        ret[k2] = v ;
                    }
                }
                default:
                    ret[k2] = v ;
                }
            }
            return ret,nil ;
        }
    }else{
        // a,b := GetType2(src) ;
        // Debugf("!!![%s][%s][%s]",tt,a,b) ;
    }
    return src,nil ;
}

func (this *TypeAssoc) DecodeYaml(src any) (error){
    var text string ;

    switch(reflect.TypeOf(src).Kind()){
        case reflect.String:{
            text = src.(string) ;
        }
        default:{
            text = string(src.([]byte)) ;
        }
    }

    var m any ;
    if err := yaml.Unmarshal([]byte(text), &m) ; (err != nil){
        Debugf("err[%s]",err) ;
        return err ;
    }

    if tmp,err := this.conv_r(0,m) ; (err != nil){
        Debugf("err[%s]",err) ;
        return err ;
    }else{
        this.Raw = tmp ;
        return nil ;
    }
}

func (this *TypeAssoc) SetMapStandard(m map[string]interface {}) (*TypeAssoc){
    this.Raw = m ;

    return this ;
}

func (this *TypeAssoc) DecodeJson(src any) (*TypeAssoc){

    var text string ;

    switch(reflect.TypeOf(src).Kind()){
        case reflect.String:{
            text = src.(string) ;
        }
        default:{
            text = string(src.([]byte)) ;
        }
    }

    var m any ;
    if(text[0:1] == "["){
        m = make([]map[string]interface{},0) ;
    }else{
        m = make(map[string]interface{}) ;
    }

    if err := json.Unmarshal([]byte(text),&m) ; (err != nil){
        Debugf("err[%s]",err) ;
        Debugf("json[%s]",text) ;
    }else{
        if tmp,err := this.conv_r(0,m) ; (err != nil){
            Debugf("err[%s]",err) ;
        }else{
            this.Raw = tmp ;
        }
    }

    return this ;
}

func (this *TypeAssoc) IsArray() bool{
    if((this.isArray == true) || (this.xtype == "[]interface {}")){
        return true ;
    }
    return false ;
}

func (this *TypeAssoc) IsStandardMap(opts ... interface{}) bool{
    if(len(opts) == 0){
        t := GetType(this.Raw) ;
        if(t == "map[string]interface {}"){
            return true ;
        }
    }else{
        t := GetType(opts[0])
        if(t == "map[string]interface {}"){
            return true ;
        }
    }
    return false ;
}

func IsStandardMap(v any) bool{
    if(GetType(v) == "map[string]interface {}"){
        return true ;
    }else{
        return false ;
    }
}

func IsJson(src any) bool {
    if ok,text := IsString(src) ; (ok == true){
        c := Substr(text,0,1) ;
        if((c == "{") || (c == "[")){
            return true ;
        }
    }
    return false ;
}

func IsYaml(src any) bool {
    if ok,text := IsString(src) ; (ok == true){
        c := Substr(text,0,1) ;
        if((c != "{") && (c != "[")){
            return true ;
        }
    }
    return false ;
}

func (this *TypeAssoc) LoadFile(path string) (*TypeAssoc){
    text,_ := File_get_contents(path);

    if(IsJson(text)){
        this.LoadContents("application/json",text) ;
    }else if(IsYaml(text)){
        this.LoadContents("text/yaml",text) ;
    }

    return this ;
}

func (this *TypeAssoc) LoadContents(contentType string,src any) (*TypeAssoc){

    var text string ; _ = text ;

    switch(reflect.TypeOf(src).Kind()){
        case reflect.String:{
            text = src.(string) ;
        }
        default:{
            text = Strval(src) ;
        }
    }

    if rc,err := ContentTypeParser(contentType) ; (err != nil){
        Debugf("err[%s]",err) ;
    }else{
        switch(rc.contentType){
            case "application/x-www-form-urlencoded", "application/xml" :{
                Debugf("err[%s]",rc.contentType) ;
                Debugf("text[%s]",Strval(src)) ;
                Debugf("text[%s]","おかしい") ;
            }
            case "application/json":{
                if err := this.DecodeJson(src) ; (err != nil){
                }
            }
            case "text/yaml":{
                if err := this.DecodeYaml(src) ; (err != nil){
                }
            }
            default:{
                Debugf("err[%s]",rc.contentType) ;
            }
        }
    }
    return this ;
}

type TypeAssocIterator struct {
    Nkey    []interface{} ;
    Idx     int ;
    Max     int ;
    Opts    Opt
    Assoc *TypeAssoc ;
}

type KV struct {
    K   string ;
    V   any ;
}

type TypeKV struct {
    K   any ;
    V   *TypeAssoc ;
}

func NewKV() (*TypeKV){
    ret := TypeKV{} ;
    return &ret ;
}

func (this *TypeKV) KT() (any,string){
    return this.K,GetType(this.K) ;
}

func (this *TypeKV) KTV() (any,string,*TypeAssoc){
    return this.K,GetType(this.K),this.V ;
}

func (this *TypeKV) GetSS() (string,string){
    return this.K.(string),this.V.Raw.(string) ;
}

func (this *TypeKV) GetStringString() (string,string){
    return this.K.(string),this.V.Raw.(string) ;
}

func (this *TypeKV) GetStringAssoc() (string,*TypeAssoc){
    return this.K.(string),this.V ;
}

func (this *TypeKV) GetIntAssoc() (int,*TypeAssoc){
    return this.K.(int),this.V ;
}

func (this *TypeAssocIterator) HasNext(opts ... interface{}) bool{

    if(this.Idx < this.Max){
        if(len(opts) == 1){
            t := GetType(opts[0]);
            if(t == "*BerdyshFrameworkGoLang.TypeKV"){
                var kv *TypeKV = opts[0].(*TypeKV) ;
                kv.K = this.Nkey[this.Idx] ;
                kv.V = this.Assoc.GetAssoc(kv.K) ;
            }
        }
        return true ;
    }else{
        return false ;
    }
}

func (this *TypeAssocIterator) Rewind() {
    this.Max = len(this.Nkey) ;
    this.Idx = 0 ;
}

func (this *TypeAssocIterator) Next() (any, error){
    ret := this.Nkey[this.Idx] ;
    this.Idx += 1 ;
    return ret,nil ;
}

func (this *TypeAssocIterator) ReDo() (*TypeAssocIterator){
    this.Idx = 0 ;
    this.Max = 0 ;
    nkey := make([]interface{},0) ;
    t:= GetType(this.Assoc.Raw) ;

    if(t == "[]interface {}"){
        if(this.Assoc != nil){
            for key,_ := range this.Assoc.Raw.([] interface{}){
                nkey = append(nkey,key) ;
            }
        }
    }else if(t == "map[string]interface {}"){
        if(true){
            if((this.Assoc != nil) && IsStandardMap(this.Assoc.Raw)){
                for key,_ := range this.Assoc.Raw.(map[string] interface{}){
                    nkey = append(nkey,key) ;
                }
            }
        }else{
            Debugf("連想配列のキーだけじゃない") ;
        }
    }

    this.Nkey = nkey ;
    this.Max = len(this.Nkey) ;

    return this ;
}

func (this *TypeAssoc) GetAssoc(opts ... interface{}) (*TypeAssoc){

    opt := opts[0] ;

    t := GetType(opt) ;
    if(t == "string"){
        k := opt.(string) ;
        m := this.Raw.(map[string]interface{}) ;
        return NewAssoc().Clone(m[k]) ;
    }else{
        k := opt.(int) ;
        m := this.Raw.([]interface{}) ;
        return NewAssoc().Clone(m[k]) ;
    }
}

func (this *TypeAssoc) Get(opts ... interface{}) (any){
    RetIsAssoc := false ;
    if(len(opts) >= 2){
        RetIsAssoc = true ;
    }
    if(len(opts) >= 1){
        opt := opts[0] ;
        if(true){
            k := opt.(string) ;
            m := this.Raw.(map[string]interface{}) ;

            if(RetIsAssoc){
                return NewAssoc().Clone(m[k]) ;
            }else{
                return m[k] ;
            }
        }
    }
    return nil ;
}

func (this *TypeAssoc) InitMap() (*TypeAssoc){
    if(this.inited == false){
        this.inited = true ;
        this.isMap = true ;
        this.Raw = make(map[string]interface{}) ;
    }
    return this ;
}

func (this *TypeAssoc) IsMap() (bool){
    return this.isMap ;
}

func (this *TypeAssoc) SetKVx(opts ... interface{}) (*TypeAssoc){

    this.InitMap() ;
    if(this.isMap == true){
        for _,opt := range opts{
            t := GetTypeParse(opt) ; _ = t ;
            Debugf_("Name[%s][%v]",t.Name,t.Ptr);
            switch(t.Name){
                case "KV":{
                    if(! t.Ptr){
                        kv := opt.(KV) ;
                        this.Raw.(map[string]interface{})[kv.K] = kv.V ;
                    }else{
                        kv := opt.(*KV) ;
                        this.Raw.(map[string]interface{})[kv.K] = kv.V ;
                    }
                }
            }
        }
    }

    return this ;
}

func (this *TypeAssoc) SetKV(opts ... interface{}) (*TypeAssoc){
    this.InitMap() ;
    if(len(opts) == 2){
        if(this.isMap == true){
            v := opts[1] ;
            t := GetType(v) ;

            switch(t){
                case "*BerdyshFrameworkGoLang.TypeAssoc":{
                    vv := v.(*TypeAssoc).Raw ;
                    this.Raw.(map[string]interface{})[opts[0].(string)] = vv ;
                }
                case "string":{
                    this.Raw.(map[string]interface{})[opts[0].(string)] = v.(string) ;
                }
                case "int":{
                    this.Raw.(map[string]interface{})[opts[0].(string)] = v.(int) ;
                }
                case "bool":{
                    this.Raw.(map[string]interface{})[opts[0].(string)] = v.(bool) ;
                }
                default:{
                    this.Raw.(map[string]interface{})[opts[0].(string)] = v ;
                }
            }
        }
    }

    return this ;
}

func (this *TypeAssoc) Append(opts ... interface{}) (*TypeAssoc){

    if(this.inited == false){
        this.inited = true ;
        this.isArray = true ;
        this.Raw = make([] interface{},0) ;
    }

    if(this.isArray == true){
        for _,v := range opts{
            t := GetType(v) ;
            Debugf_("[%s]",t);
            switch(t){
                case "*BerdyshFrameworkGoLang.TypeAssoc":{
                    vv := v.(*TypeAssoc).Raw ;
                    this.Raw = append(this.Raw.([] interface{}),vv) ;
                }
                default:{
                    this.Raw = append(this.Raw.([] interface{}),v) ;
                }
            }
        }
    }
    return this ;
}

func (this *TypeAssoc) IteratorKeys(opts ... interface{}) (*TypeAssocIterator){
    ret := this.Iterator() ;
    ret.Opts.Keys = true ;
    return ret.ReDo() ;
}

func (this *TypeAssoc) Iterator(opts ... interface{}) (*TypeAssocIterator){

    ret := TypeAssocIterator{} ;
    ret.Assoc = this ;
    ret.Idx = 0 ;
    ret.Max = 0 ;

    for _,opt := range opts{
        t := GetType(opt) ;
        switch(t){
            case "BerdyshFrameworkGoLang.Opt":{
                if(opt.(Opt).Keys       ){ ret.Opts.Keys         = true ; }
                if(opt.(Opt).SortByKey  ){ ret.Opts.SortByKey    = true ; }
                if(opt.(Opt).SortByValue){ ret.Opts.SortByValue  = true ; }
                if(opt.(Opt).OrderByDesc){ ret.Opts.OrderByDesc  = true ; }
                if(opt.(Opt).OrderByAsc ){ ret.Opts.OrderByAsc   = true ; }
            }
        }
    }

    ret.ReDo() ;
    return &ret ;
}

func (this *TypeAssoc) EncodeJson() (string){
    if bin, err := json.Marshal(this.Raw) ; (err == nil){
        return string(bin) ;
    }else{
        Debugf("err[%s]",err) ;
        return "" ;
    }
    return "" ;
}

func (this *TypeAssoc) String() (string){
    var buf bytes.Buffer ; _ = buf ;

    t := GetType(this.Raw)

    Debugf_("!!!!!!!!!!!!!!!!!![%s]",t);

    if(t == "string"){
        return this.Raw.(string) ;
    }else if bin, err := json.Marshal(this.Raw) ; (err != nil){
        return "" ;
    }else{
        if err := json.Indent(&buf,bin, "", "  ") ; (err != nil){
            return "" ;
        }else{
            return buf.String() ;
        }
    }
}

func (this *TypeAssoc) Strval() (string){ return this.Raw.(string) ; }
func (this *TypeAssoc) Intval() (int){ return this.Raw.(int) ; }

func (this *TypeAssoc) Type() (string){
    return this.xtype ;
}

func (this *TypeAssoc) EncodeCGI() (string){

    ret := "" ;

    kv := TypeKV{} ;

    for i := this.Iterator() ; i.HasNext(&kv) ;i.Next(){
        k ,v := kv.GetStringString() ;
        if(ret != ""){ ret += "&" ; }
        ret += url.QueryEscape(k) + "=" + url.QueryEscape(v) ;
    }

    return ret ;
}

func (this *TypeAssoc) Encode(opts ... interface{}) (string){
    for _,opt := range opts {
        t := GetType(opt) ;
        switch(t){
            case "string":{
                if(opt.(string) == "application/x-www-form-urlencoded"){
                    return  this.EncodeCGI() ;
                }
            }
        }
    }

    return "" ;
}

func (this *TypeAssoc) Clone(v any) (*TypeAssoc){

    t := GetTypeParse(v) ;

    // Debugf("[%s][%s]",t.Name,t.Kind) ;

    switch(t.Name){
        case "TypeAssoc":{
            if(t.Ptr){
                this.Raw = v.(*TypeAssoc).Raw ;
            }else{
                this.Raw = v.(TypeAssoc).Raw ;
            }
        }
        default:{
            this.Raw = v ;
        }
    }

    this.xtype = GetType(this.Raw) ;
    return this ;
}

func (this *TypeAssoc) ToLower() (*TypeAssoc){
    return this ;
}

func (this *TypeAssoc) ToUpper() (*TypeAssoc){
    return this ;
}

func NewAssoc() (*TypeAssoc){
    ret := TypeAssoc{} ;
    ret.Init() ;
    return &ret ;
}

























