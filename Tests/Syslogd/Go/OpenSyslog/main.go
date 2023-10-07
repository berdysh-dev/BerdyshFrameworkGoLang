package main

import X "local/BerdyshFrameworkGoLang"

func main(){
    option := X.NewOpenSyslogOption() ;
    option.Addr = "udp://:514" ;
    _ = option ;

    if logger,err := X.OpenSyslog("prefix",0,X.LOG_LOCAL2,option) ; (err != nil){
        X.Printf("err[%s]\n",err);
    }else{
        defer logger.Close() ;
        if err := logger.Debugf("あああ[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
        if err := logger.Debugf("いいい[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
        if err := logger.Debugf("ううう[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
    }
}

