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
    return string(c.(byte)) ;
}

func Ord(c interface{}) byte {
    return Strval(c)[0] ;
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
    ret := "" ;
    str := "" ;
    st := 0 ;
    offset := 0 ;
    length := 0 ;

    is_length := 0 ;

    num_args := len(args) ;

    if(num_args < 1){ return "" ; }

    str = Strval(args[0]) ;
    str_len := len(str) ;
    bin := []byte(str)

    switch(num_args){
    case 2:{
            str = Strval(args[0]) ;
            offset = Intval(args[1]) ;
        }
    case 3:{
            str = Strval(args[0]) ;
            offset = Intval(args[1]) ;
            length = Intval(args[2]) ;
            is_length = 1 ;
        }
    }

    if(offset < 0){
        offset = 0 - offset ;
        st = str_len - offset ;
    }else{
        st = offset ;
    }

    idx := st ;
    cnt := 0 ;
    for(idx < str_len){
        ret += Chr(bin[idx]) ;
        idx += 1 ;
        cnt += 1 ;
        if(is_length != 0){
            if(cnt >= length){ break ; }
        }
    }

    _ = str ; _ = offset ; _ = length ; _ = is_length ;

    return ret ;
}

