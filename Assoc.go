package BerdyshFrameworkGoLang

import (
    "strings"
    "reflect"
    "bytes"
    "encoding/json"
)

type TypeAssocRaw map[string]interface{}

type TypeAssoc struct {
    Raw interface{}
}

func (this *TypeAssoc) Init() (*TypeAssoc){
    return this ;
}

func LC(src string) (string){ return strings.ToLower(src[0:1]) + src[1:] ; }
func UC(src string) (string){ return strings.ToUpper(src[0:1]) + src[1:] ; }

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
            Debugf("string") ;
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

func (this *TypeAssoc) LoadFile(path string) (error){
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

func NewAssoc() (TypeAssoc){
    ret := TypeAssoc{} ;
    ret.Init() ;
    return ret ;
}

