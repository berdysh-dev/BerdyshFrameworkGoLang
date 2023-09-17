package BerdyshFrameworkGoLang

import (
    "log"
    "fmt"
    "errors"
    "os"
    "strings"
    "strconv"
    "runtime"
    "reflect"
    "time"
    "net"
    "log/syslog"
    "encoding/base64"
_   "encoding/json"
_    "io/ioutil"
_    "io/fs"
    "github.com/google/uuid"
)

func Gettype(t interface{}) string {
    return fmt.Sprintf("%s",reflect.TypeOf(t)) ;
}

func Gettype2(t interface{}) (string,string) {
    return fmt.Sprintf("%s",reflect.TypeOf(t)), fmt.Sprintf("%T",t) ;
}

func Debugf_(args ... interface{}){
}

func Debugf(args ... interface{}){
    pc, file, line, ok := runtime.Caller(1) ;
    _ = pc ; _ = file ; _ = ok ;
    _ = line ;

    // fmt.Printf("要素数[%v]\n",len(args)) ;

    paths := strings.Split(file, "/") ;

    basename := paths[len(paths)-1] ;

    var f[99] string ;

    for iii := 0; iii < len(args); iii++ {
        switch(Gettype(args[iii])){
        case "string":
            f[iii] = fmt.Sprintf("%s",args[iii]) ;
            break ;
        case "int":
            f[iii] = fmt.Sprintf("%d",args[iii]) ;
            break ;
        }
    }

    fff := fmt.Sprintf("%s",args[0]) ;

    var out string ;

    if(len(args) == 1){ out = fmt.Sprintf("%v",fff) ; }
    if(len(args) == 2){ out = fmt.Sprintf(fff,args[1]) ; }
    if(len(args) == 3){ out = fmt.Sprintf(fff,args[1],args[2]) ; }
    if(len(args) == 4){ out = fmt.Sprintf(fff,args[1],args[2],args[3]) ; }
    if(len(args) == 5){ out = fmt.Sprintf(fff,args[1],args[2],args[3],args[4]) ; }
    if(len(args) == 6){ out = fmt.Sprintf(fff,args[1],args[2],args[3],args[4],args[5]) ; }
    if(len(args) == 7){ out = fmt.Sprintf(fff,args[1],args[2],args[3],args[4],args[5],args[6]) ; }
    if(len(args) == 8){ out = fmt.Sprintf(fff,args[1],args[2],args[3],args[4],args[5],args[6],args[7]) ; }
    if(len(args) == 9){ out = fmt.Sprintf(fff,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8]) ; }

    message := fmt.Sprintf("%04d:%v:%v\n",line,basename,out) ;

    if(true){
        conn, err := net.Dial("unix","/dev/log") ;
        if(err != nil){
            // fmt.Printf("err[%s]\n",err) ;
        }else{
            facility    := syslog.LOG_LOCAL7 ;
            syslog_lv   := syslog.LOG_DEBUG ;
            ar := strings.Split(message,"\n") ;
            for idx,line := range ar {
                if((idx > 0) && (line == "")){ continue ; }
                packet := fmt.Sprintf("<%d>Sep  4 09:09:02 : ",(facility + syslog_lv)) ;
                packet = packet + line ;
                rc , _ := conn.Write([]byte(packet)) ; _ = rc ;
            }
            conn.Close() ;
        }
    }
    

    return ;
}

func GetSourceCodeLine(args ... interface{}) string {
    pc, file, line, ok := runtime.Caller(1) ;
    _ = pc ; _ = file ; _ = ok ;
    paths := strings.Split(file, "/") ;
    basename := paths[len(paths)-1] ;

    return fmt.Sprintf("%s:%d",basename,line) ;
}

func GetSourceCodeFile(args ... interface{}) string {
    pc, file, line, ok := runtime.Caller(1) ;
    _ = pc ; _ = line ; _ = ok ;

    paths := strings.Split(file, "/") ;
    basename := paths[len(paths)-1] ;

    return basename ;
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

func Strval(org interface{}) string{

    t := Gettype(org) ;

    if(t == "[]uint8"){
        return string(org.([]uint8)) ;
    }else if(t == "string"){
        ;
    }else{
        fmt.Printf("TYPE[%s]\n",t) ;
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

func File_exists(path interface{}) int{
    _, err := os.Stat(Strval(path)) ;
    if(err == nil){
        return 1 ;
    }else{
        return 0 ;
    }
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

func local_dummy_KonaPayUtil(){

    err := errors.New("NULL") ;

    _ = err ;

    fmt.Print("") ;
    log.Print("") ;
}

func Base64_decode(src string) (string,error){
    dec, err := base64.StdEncoding.DecodeString(src) ;

    if(err != nil){
        return "",err ;
    }else{
        return string(dec),nil ;
    }
}




















