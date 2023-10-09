package main

import(
    "os"
    "time"
    "sync"
)

import X "local/BerdyshFrameworkGoLang" ;

import M "local/BerdyshFrameworkGoLang" ;
// import M "gopkg.in/mcuadros/go-syslog.v2" ;

type Test struct {
    wait    sync.WaitGroup ;
}

type TypeChanString chan string ;

func (this *Test) Ch(){
    ch := make(TypeChanString) ;

    go func(ch TypeChanString){
        loop := 0 ;
        for{
            str := X.Sprintf("%06d",loop) ;
            X.Printf("Loop[%s].\n",str) ;

            ch <- str ;

            X.Sleep(1) ;
            loop++ ;
        }
    }(ch) ;

    X.Printf("待受\n") ;

    xxx := 0 ;
    for x := range ch{
        X.Printf("受信[%d][%s]\n",xxx,x) ;
        xxx ++ ;
    }
}

func (this *Test) Cli(){

    optTCP := X.NewSyslogOption() ;
    optUDP := X.NewSyslogOption() ;

    optTCP.Addr = "tcp://:514" ;
    optUDP.Addr = "udp://:514" ;

    go func(){
        if loggerTCP,err := X.NewSyslogClient("tcp",0,X.LOG_LOCAL2,optTCP) ; (err != nil){
            X.Printf("err[%s]\n",err);
        }else{
            defer loggerTCP.Close() ;
            for {
                if err := loggerTCP.Debug("TCP-1[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
                X.Sleep(1) ;
            }
        }
    }();

    go func(){
        if loggerUDP,err := X.NewSyslogClient("udp",0,X.LOG_LOCAL2,optUDP) ; (err != nil){
            X.Printf("err[%s]\n",err);
        }else{
            defer loggerUDP.Close() ;
            for {
                if err := loggerUDP.Debug("UDP-1[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
                X.Sleep(1) ;
            }
        }
    }();

    go func(){
        if loggerUNIX,err := X.NewSyslogClient("unix",0,X.LOG_LOCAL2) ; (err != nil){
            X.Printf("err[%s]\n",err);
        }else{
            defer loggerUNIX.Close() ;
            for {
                if err := loggerUNIX.Debug("UNIX-1[%d][%d][%d]",1,2,3) ; (err != nil){ X.Printf("err[%s]\n",err); }
                X.Sleep(1) ;
            }
        }
    }();

}

type MyHandler struct {
    Id  string ;
    inited bool ;
    mu sync.Mutex ;
} ;

func (this *MyHandler) GetId() (string){ return this.Id ; }

func (this *MyHandler) Init(){
    this.inited = true ;
}

func (this *MyHandler) IsInited() (bool){
    return this.inited ;
}

func (this *MyHandler) EvRecv(rc *X.SyslogEntry){
    X.Printf("%s.%s:%s:\n",X.SyslogFacility2str(rc.Facility),X.SyslogSeverity2str(rc.Severity),rc.Message) ;
}

func (this *Test) Serv(){

    X.Printf("Begin-main.\n") ;

    this.wait.Add(1) ;

    go func() {

        // time.Sleep(3 * time.Second) ;

        router := X.NewSyslogRouter() ;
        entry := X.NewSyslogEntry() ;
        handler := MyHandler{Id: "All"} ;
        router.Handle(entry,&handler) ;

        addrs := make([]string,0) ;
        addrs = append(addrs,"unix:///dev/log") ;
        addrs = append(addrs,"tcp://:514") ;
        addrs = append(addrs,"udp://:514") ;

        if err := X.SyslogDaemon(addrs,router) ; (err != nil){
            X.Printf("err[%s].\n",err) ;
        }else{
            X.Printf("OK[].\n") ;
        }
        this.wait.Done() ;
    }() ;

    X.Printf("Start-main.\n") ;
    this.wait.Wait() ;
    X.Printf("Ready-main.\n") ;
}

func (this *Test) Serv2(){

    X.Printf("Begin.\n") ;

    this.wait.Add(1) ;

    go func() {

        time.Sleep(3 * time.Second) ;

        channel := make(M.LogPartsChannel) ;

        server := M.NewServer()
        server.SetFormat(M.RFC3164) ;
        server.SetFormat(M.RFC5424) ;
        server.SetFormat(M.RFC6587) ;
        server.SetFormat(M.Automatic) ;
        server.SetHandler(M.NewChannelHandler(channel)) ;

        sock := "/dev/log"

        if _ , err := os.Stat(sock) ; (err == nil){ os.Remove(sock) ; }

        if err := server.ListenUnixgram(sock) ; (err != nil){
            X.Printf("err[%s]\n",err) ;
        }else{
            if err := server.ListenUDP(":514") ; (err != nil){
                X.Printf("err[%s]\n",err) ;
            }else{
                if err := server.ListenTCP(":514") ; (err != nil){
                    X.Printf("err[%s]\n",err) ;
                }else{
                    if err := server.Boot() ; (err != nil){
                        X.Printf("err[%s]\n",err) ;
                    }else{
                        go func(channel M.LogPartsChannel) {

                            X.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!![%T]\n",channel) ;

                            idx := 0 ;
                            for logParts := range channel {
                                // X.Printf("!!![%d]\n",idx) ;
                                for k,v := range logParts {
                                    _ = v ;
                                    switch(k){
                                        case "content":{
                                            X.Printf("[%s][%V]\n",k,v) ;
                                        }
                                    }
                                }
                                idx ++ ;
                            }
                        }(channel) ;
                        this.wait.Done() ;
                        server.Wait() ;
                    }
                }
            }
        }
    }() ;
    X.Printf("Start.\n") ;
    this.wait.Wait() ;
    X.Printf("Ready.\n") ;
}

func main(){
    test := &Test{} ;

    test.Serv2() ;
//  test.Serv() ;
    test.Cli() ;
//  test.Ch() ;

    X.Tick() ;
}













