package BerdyshFrameworkGoLang

import (
    "os"
    "net"
    "time"
    "regexp"
    "strconv"
)

const (
    SOCKET_LOG  = "/dev/log"
)

func Tick(){
    for lp:=1;;lp+=1 {
        time.Sleep(1 * time.Second) ;
        Debugf("Syslogd[%06d].",lp) ;
    }
}

func EvRecvSyslog(s string){
    var Facility string ; _ = Facility ;
    var Priority string ; _ = Priority ;

    r := regexp.MustCompile(`^\<(\d+)\>(.* \d\d:\d\d:\d\d)\s*:\s+(.*)$`)
    tmp := r.FindAllStringSubmatch(s,-1)
    if(len(tmp) == 1){
        matches := tmp[0] ;
        pri,_  := strconv.Atoi(matches[1]) ;  _ = pri ;
        date := matches[2] ; _ = date ;
        mess := matches[3] ; _ = mess ;

        facilityN := pri / 8 ; _ = Facility ;
        priorityN := pri % 8 ; _ = Priority ;

        switch(facilityN){
            case 0: Facility = "LOG_KERN" ;
            case 1: Facility = "LOG_USER" ;
            case 2: Facility = "LOG_MAIL" ;
            case 3: Facility = "LOG_DAEMON" ;
            case 4: Facility = "LOG_AUTH" ;
            case 5: Facility = "LOG_SYSLOG" ;
            case 6: Facility = "LOG_LPR" ;
            case 7: Facility = "LOG_NEWS" ;
            case 8: Facility = "LOG_UUCP" ;
            case 9: Facility = "LOG_CRON" ;
            case 10: Facility = "LOG_AUTHPRIV" ;
            case 11: Facility = "LOG_FTP" ;
            case 16: Facility = "LOG_LOCAL0" ;
            case 17: Facility = "LOG_LOCAL1" ;
            case 18: Facility = "LOG_LOCAL2" ;
            case 19: Facility = "LOG_LOCAL3" ;
            case 20: Facility = "LOG_LOCAL4" ;
            case 21: Facility = "LOG_LOCAL5" ;
            case 22: Facility = "LOG_LOCAL6" ;
            case 23: Facility = "LOG_LOCAL7" ;
        }

        switch(priorityN){
            case 0: Priority = "LOG_EMERG" ;
            case 1: Priority = "LOG_ALERT" ;
            case 2: Priority = "LOG_CRIT" ;
            case 3: Priority = "LOG_ERR" ;
            case 4: Priority = "LOG_WARNING" ;
            case 5: Priority = "LOG_NOTICE" ;
            case 6: Priority = "LOG_INFO" ;
            case 7: Priority = "LOG_DEBUG" ;
        }

        printf("[%s][%s][%s][%s]\n",Facility,Priority,date,mess) ;
    }
}

func Syslogd(){
    var err error ; _ = err ;
    var st os.FileInfo ; _ = st ;

    st , err = os.Stat(SOCKET_LOG) ;

    if(err == nil){ os.Remove(SOCKET_LOG) ; }

    unixAddr, err := net.ResolveUnixAddr("unix",SOCKET_LOG) ;

    if(err != nil){
        printf("err[%s]\n",err) ;
    }else{
        sockListen, err := net.ListenUnix("unix",unixAddr) ; _ = sockListen ;
        if(err != nil){
            printf("err[%s]\n",err) ;
        }else{
            for {
                unixConn, err := sockListen.Accept() ;
                if(err != nil){
                    printf("err[%s]\n",err) ;
                }else{
                    buf := make([]byte,4096) ;
                    var szRc int ; _ = szRc ;
                    szRc,err = unixConn.Read(buf) ;
                    if(err != nil){
                        printf("err[%s]\n",err) ;
                    }else{
                        EvRecvSyslog(string(buf)) ;
                    }
                }
            }
        }
    }
}

















