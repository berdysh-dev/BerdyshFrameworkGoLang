package BerdyshFrameworkGoLang

import (
    "fmt"
_   "errors"
    "os"
    "strings"
    "runtime"
    "reflect"
    "time"
    "net"
    "log/syslog"
    "encoding/base64"
    "github.com/google/uuid"
)

func GetType(t interface{}) string {
    return fmt.Sprintf("%s",reflect.TypeOf(t)) ;
}

func GetType2(t interface{}) (string,string) {
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
        switch(GetType(args[iii])){
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

            day := time.Now()
            const layout = "Jan _2 15:04:05"
            date := fmt.Sprint(day.Format(layout)) 
            head := fmt.Sprintf("<%d>%s : ",(facility + syslog_lv),date) ;

            ar := strings.Split(message,"\n") ;
            for idx,line := range ar {
                if((idx > 0) && (line == "")){ continue ; }
                packet := head + line ;
                conn.Write([]byte(packet)) ;
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




















