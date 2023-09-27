package BerdyshFrameworkGoLang

import (
_   "errors"
    "os"
    "reflect"
    "time"
    "encoding/base64"
    "github.com/google/uuid"
)

func GetType(t interface{}) string {
    return sprintf("%s",reflect.TypeOf(t)) ;
}

func GetType2(t interface{}) (string,string) {
    return sprintf("%s",reflect.TypeOf(t)), sprintf("%T",t) ;
}

func Getmypid() int{
    return  os.Getpid() ;
}

func TimeNow() int64 {
    return time.Now().Unix() ;
}

func UUIDv4() string {

    u, err := uuid.NewRandom()
    if err != nil {
        return "" ;
    }
    uu := u.String()
    return uu ;
}

func File_exists(path interface{}) int{
    _, err := os.Stat(Strval(path)) ;
    if(err == nil){
        return 1 ;
    }else{
        return 0 ;
    }
}

func Base64_decode(src string) (string,error){
    dec, err := base64.StdEncoding.DecodeString(src) ;

    if(err != nil){
        return "",err ;
    }else{
        return string(dec),nil ;
    }
}




















