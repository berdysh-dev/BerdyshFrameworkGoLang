package BerdyshFrameworkGoLang

import (
    "strings"
    "strconv"
)

func Strtolower(src interface{}) (string){
    return strings.ToLower(src.(string)) ;
}

func LC(src string) (string){ return strings.ToLower(src[0:1]) + src[1:] ; }
func UC(src string) (string){ return strings.ToUpper(src[0:1]) + src[1:] ; }

func ToLower(s string) (string){ return strings.ToLower(s) ; }
func ToUpper(s string) (string){ return strings.ToUpper(s) ; }

func Strval(org interface{}) string{

    t := GetType(org) ;

    if(t == "[]uint8"){
        return string(org.([]uint8)) ;
    }else if(t != "string"){
        printf("TYPE[%s]\n",t) ;
    }

    return org.(string) ;
}

func Intval(org interface{}) int{
    return org.(int) ;
}

func Chr(c interface{}) string {

    r := make([]rune,1) ;

    switch(sprintf("%T",c)){
        case "int":{
            r[0] = (rune)(c.(int)) ;
            return string(r) ;
        }
        case "int32":{
            r[0] = (rune)(c.(int32)) ;
            return string(r) ;
        }
        case "uint8":{
            r[0] = (rune)(c.(uint8)) ;
            return string(r) ;
        }
        case "byte":{
            return string(c.(byte)) ;
        }
        default:{
            printf("!!![%T]\n",c) ;
        }
    }

    return "" ;
}

func Ord(c interface{}) rune {
    if(sprintf("%T",c) == "string"){
        r := []rune(c.(string))
        return r[0] ;
    }
    return 0 ;
}

func Atoi(org interface{}) int{
    i, _ := strconv.Atoi(Strval(org)) ;
    return i ;
}

func Atoi64(org interface{}) uint64{
    convertedStrUint64, _ := strconv.ParseUint(Strval(org), 10, 64) ;
    return convertedStrUint64 ;
}

func Trim(src interface{}) string{
    return strings.Trim(Strval(src)," \t\r\n\f\v") ;
}

func Ltrim(src interface{}) string{
    return strings.TrimLeft(Strval(src)," \t\r\n\f\v") ;
}

func Rtrim(src interface{}) string{
    return strings.TrimRight(Strval(src)," \t\r\n\f\v") ;
}

func IsString(src any) (bool,string) {

    t := GetType(src)

    switch(t){
        case "string":{
            return true,src.(string) ;
        }
        case "*BerdyshFrameworkGoLang.TypeAssoc":{
            if t2 := src.(*TypeAssoc).Type() ; (t2 == "string"){
                return true , src.(*TypeAssoc).String() ;
            }
        }
        default:{
            Debugf("!!!!!!![きた][%s]",t);
        }
    }
    return false , "" ;
}

func Substr(args ... interface{}) string{
    ret := "" ; _ = ret ;
    str := "" ; _ = str ;
    st := 0 ; _ = st ;
    offset := 0 ; _ = offset ;
    length := 0 ; _ = length ;

    is_length := false ; _ = is_length ;

    num_args := len(args) ; _ = num_args ;

    if(num_args < 1){ return "" ; }

    str = Strval(args[0]) ;
    r := []rune(str) ; _ = r ;
    max := len(r) ; _ = max ;

    switch(num_args){
    case 2:{
            offset = Intval(args[1]) ;
        }
    case 3:{
            offset = Intval(args[1]) ;
            length = Intval(args[2]) ;
            is_length = true ;
        }
    }

    if(offset < 0){
        length = 0 - offset ;
        offset = max - length ;
        return string(r[offset:(offset+length)]) ;
    }else{
        st = offset ;
    }

    if(is_length){
        return string(r[offset:(offset+length)]) ;
    }else{
        return string(r[offset:]) ;
    }
}







