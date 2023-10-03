package main

import(
    "fmt"
    "log/syslog"
    "github.com/NextronSystems/simplesyslog"
)


func dial(schema string) {
    sysLog, err := syslog.Dial(schema,"localhost:514", syslog.LOG_WARNING|syslog.LOG_LOCAL7, "TAG")
    if(err != nil){
        fmt.Printf("err[%s]\n",err)
    }else{
        fmt.Fprintf(sysLog,schema)
        // sysLog.Emerg("BBB")
    }
}

func unix(){
    if w,err := syslog.New(syslog.LOG_WARNING|syslog.LOG_LOCAL7,"TAG") ; (err != nil){
        fmt.Printf("err[%s]\n",err)
    }else{
        fmt.Fprintf(w,"unix")
    }
}

func simple(){
    if client, err := simplesyslog.NewClient(simplesyslog.ConnectionUDP,"127.0.0.1:514",nil) ; (err != nil){
        fmt.Printf("err[%s]\n",err) ;
    }else{
        defer client.Close() ;
        if err := client.Send("foo bar baz", simplesyslog.LOG_LOCAL7|simplesyslog.LOG_NOTICE) ; err != nil {
            fmt.Printf("err[%s]\n",err)
        }
    }
}

func main(){
    fmt.Printf("St.\n")
    if(false){
        simple() ;
    }else{
        // unix() ;
        // dial("tcp") ;
        dial("udp") ;
    }
    fmt.Printf("Fin.\n")
}
