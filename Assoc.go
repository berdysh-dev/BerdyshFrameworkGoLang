package BerdyshFrameworkGoLang

import (
    "fmt"
    "reflect"
    "bytes"
    "encoding/json"
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

func (this *TypeAssoc) GetType(opts ... interface{}) string {
    if(len(opts) == 1){
        return GetType(opts[0]) ;
    }else{
        return GetType(this.Raw) ;
    }
}

func (this *TypeAssoc) GetType2(t interface{}) (string,reflect.Kind) {
    return fmt.Sprintf("%T",t),reflect.TypeOf(t).Kind() ;
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

                if(mode == 1){
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

func (this *TypeAssoc) DecodeJson(src any) (error){

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
        return err ;
    }

    if tmp,err := this.conv_r(1,m) ; (err != nil){
        Debugf("err[%s]",err) ;
        return err ;
    }else{
        this.Raw = tmp ;
        return nil ;
    }
}

func IsStandardMap(v any) bool{
    if(GetType(v) == "map[string]interface {}"){
        return true ;
    }else{
        return false ;
    }
}

func (this *TypeAssoc) LoadFile(path string) (error){
    text,_ := File_get_contents(path);

    this.DecodeJson(text);

    return nil ;
}

func (this *TypeAssoc) LoadContents(contentType string,src any) (error){

    var text string ; _ = text ;

    switch(reflect.TypeOf(src).Kind()){
        case reflect.String:{
            Debugf("string") ;
            text = src.(string) ;
        }
        default:{
            text = Strval(src) ;
        }
    }

    if rc,err := ContentTypeParser(contentType) ; (err != nil){
        Debugf("err[%s]",err) ;
        return err ;
    }else{
        switch(rc.contentType){
            case "application/x-www-form-urlencoded", "application/xml" :{
                Debugf("err[%s]",rc.contentType) ;
                Debugf("text[%s]",Strval(src)) ;
                Debugf("text[%s]","おかしい") ;
            }
            case "application/json":{
                if err := this.DecodeJson(src) ; (err != nil){
                    return err ;
                }
            }
            default:{
                Debugf("err[%s]",rc.contentType) ;
            }
        }
    }

    return nil ;
}

type TypeAssocIterator struct {
    Skey    []string ;
    Idx     int ;
    Max     int ;
    Opts    Opt
    Assoc *TypeAssoc ;
}

func (this *TypeAssocIterator) HasNext() bool{
    return (this.Idx < this.Max) ;
}

func (this *TypeAssocIterator) Rewind() {
    this.Max = len(this.Skey) ;
    this.Idx = 0 ;
}

func (this *TypeAssocIterator) Next() (any, error){
    ret := this.Skey[this.Idx] ;
    this.Idx += 1 ;
    return ret,nil ;
}

func (this *TypeAssocIterator) ReDo() (*TypeAssocIterator){
    this.Idx = 0 ;
    this.Max = 0 ;

    if(this.Opts.Keys){
        if((this.Assoc != nil) && IsStandardMap(this.Assoc.Raw)){
            skey := make([]string,0) ;
            for key,_ := range this.Assoc.Raw.(map[string] interface{}){
                skey = append(skey,key) ;
            }
            this.Skey = skey ;
            this.Max = len(this.Skey) ;
        }
    }

    return this ;
}

func (this *TypeAssoc) GetAssoc(opts ... interface{}) (*TypeAssoc){
    k := opts[0].(string) ;
    m := this.Raw.(map[string]interface{}) ;
    return NewAssoc().Clone(m[k]) ;
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

func (this *TypeAssoc) SetKV(opts ... interface{}) (*TypeAssoc){
    if(len(opts) == 2){
        if(this.inited == false){
            this.inited = true ;
            this.isMap = true ;
            this.Raw = make(map[string]interface{}) ;
        }

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
                    Debugf("[%s][%V]",t,v);
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
    ret.Skey = make([]string,0) ;

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


func (this *TypeAssoc) String() (string){
    var buf bytes.Buffer ; _ = buf ;

    if bin, err := json.Marshal(this.Raw) ; (err != nil){
        return "" ;
    }else{
        if err := json.Indent(&buf,bin, "", "  ") ; (err != nil){
            return "" ;
        }else{
            return buf.String() ;
        }
    }
}

func (this *TypeAssoc) Type() (string){
    return this.xtype ;
}

func (this *TypeAssoc) Clone(v any) (*TypeAssoc){
    this.Raw = v ;
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

























