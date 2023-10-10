package BerdyshFrameworkGoLang

import(
    "sync"
    "net"
    "net/url"
)

type RedisServer struct {
    Addr    string ;
    wait    sync.WaitGroup ;
}

type RedisPacket struct {
}

func (server *RedisServer) DecodeRESP3(bin []byte,idx int) (int,any,error){
    var x any ;
    L := len(bin) ; _ = L ;

    kind := bin[idx] ;

    switch(kind){
        case '+':{
        }
        case '-':{
        }
        case ':':{
            idx += 1 ;
            num := 0;
            for {
                if((bin[idx] >= '0') && (bin[idx] <= '9')){
                    num = (num * 10) + ((int)(bin[idx]) - '0') ;
                    idx += 1 ;
                }else if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                    idx += 2 ;
                    return idx,num,nil ;
                }else{
                    return idx,nil,Errorf("Broken") ;
                }
            }
        }
        case '$':{
            idx += 1 ;
            if((bin[idx+0] == '-') && (bin[idx+1] == '1') && (bin[idx+2] == 0x0d) && (bin[idx+3] == 0x0a)){
                idx += 4 ;
                return idx,nil,nil ;
            }else{
                num := 0;
                for{
                    if((bin[idx] >= '0') && (bin[idx] <= '9')){
                        num = (num * 10) + ((int)(bin[idx]) - '0') ;
                        idx += 1 ;
                    }else if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                        idx += 2 ;
                        str := "" ;
                        for jjj:=0 ; jjj<num;jjj++ {
                            str += Chr(bin[idx+jjj]) ;
                        }
                        // printf("$:Num[%d][%s]\n",num,str) ;
                        idx += num ;

                        if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                            idx += 2 ;
                            return idx,str,nil ;
                        }else{
                            return idx,nil,Errorf("Broken") ;
                        }
                    }else{
                        printf("NotCR[0x%x][0x%x]\n",bin[idx],bin[idx+1]) ;
                        break ;
                    }
                }
            }
        }
        case '*','%':{
            idx += 1 ;
            num := 0;
            for{
                if((bin[idx] >= '0') && (bin[idx] <= '9')){
                    num = (num * 10) + ((int)(bin[idx]) - '0') ;
                    idx += 1 ;
                }else if((bin[idx+0] == 0x0d) && (bin[idx+1] == 0x0a)){
                    idx += 2 ;
                    if(kind == '*'){
                        ret := make([]any,0) ;
                        for iii := 0 ; iii<num ; iii++ {
                            idx,x,_ = server.DecodeRESP3(bin,idx) ;
                            ret = append(ret,x) ;
                        }
                        return idx,ret,nil ;
                    }else{
                        ret := make(map[string]any) ;
                        for iii := 0 ; iii<num ; iii++ {
                            var k any ;
                            var v any ;
                            idx,k,_ = server.DecodeRESP3(bin,idx) ;
                            idx,v,_ = server.DecodeRESP3(bin,idx) ;
                            ret[k.(string)] = v ;
                        }
                        return idx,ret,nil ;
                    }
                }else{
                    printf("NotCR[0x%x][0x%x]\n",bin[idx],bin[idx+1]) ;
                    break ;
                }
            }
        }
    }
    return idx,nil,nil ;
}

func (server *RedisServer) DecodeProtocol(fifo string) (string,any,error){
    printf("%s\n\n",Hexdump(fifo)) ;

    packet := RedisPacket{} ; _ = packet ;
    bin := []byte(fifo) ; _ = bin ;

    idx,x,err := server.DecodeRESP3(bin,0) ; _ = idx ; _ = err ;

    printf("[%T]\n",x) ;
    printf("[%V]\n",x) ;

    printf("LEN[%d/%d]\n",idx,len(bin)) ;

    if(sprintf("%T",x) == "[]interface {}"){
        for idx,v := range x.([]interface {}){
            printf("%03d:[%T][%V]\n",idx,v,v) ;
            idx += 1 ;
        }
    }

    if(sprintf("%T",x) == "map[string]interface {}"){
        idx := 0 ;
        for k,v := range x.(map[string]interface {}){
            printf("%03d:[%s][%T][%V]\n",idx,k,v,v) ;
            idx += 1 ;
        }
    }

    return "",x,ErrNotEnough;
}

func (server *RedisServer) DoTcp(tcpConn *net.TCPConn){
    var err error ; _ = err ;
    var packet any ;
    var szRc int ; _ = szRc ;

    printf("TCP-Accept.\n") ;
    buf := make([]byte,0x1000) ;
    fifo := "" ;

    for{
        if szRc,err = tcpConn.Read(buf) ; (err != nil){
            printf("Read.err[%s]\n",err) ;
            break ;
        }else{
            if(szRc > 0){
                fifo += string(buf[:szRc]) ;
                for{
                    if fifo,packet,err = server.DecodeProtocol(fifo) ; (err != nil){
                        break ;
                    }else{
                        _ = packet ;
                    }
                }
            }
        }
    }

    tcpConn.Close() ;
}

func NewRedisServer(addr string)(error){

    server := &RedisServer{} ;

    server.Addr = addr ;
    server.wait.Add(1) ;

    go func(server *RedisServer){
        if ui , err := url.Parse(server.Addr) ; (err != nil){
            Printf("err[%s]/addr[%s]\n",err,addr) ;
        }else{
            switch(ui.Scheme){
                case "tcp":{
                    if tcpAddr, err := net.ResolveTCPAddr("tcp", ui.Host) ; (err != nil) {
                        Printf("err[%s]/addr[%s]\n",err,ui.Host) ;
                    }else{
                        if tcpListener, err := net.ListenTCP("tcp", tcpAddr) ; (err != nil) {
                            Printf("err[%s]/addr[%s]\n",err,ui.Host) ;
                        }else{
                            Printf("TCP-Listen-OK[]/addr[%s]\n",ui.Host) ;
                            server.wait.Done() ;
                            for{
                                chanTcpConn := make(chan *net.TCPConn) ;
                                chanTcpErr := make(chan error) ;

                                go func() {
                                    tcpConn, err := tcpListener.AcceptTCP() ;
                                    if (err != nil) {
                                        chanTcpErr <- err ;
                                        return
                                    }
                                    chanTcpConn <- tcpConn
                                }() ;

                                select {
                                    case tcpConn := <-chanTcpConn:{
                                        go server.DoTcp(tcpConn) ;
                                    }
                                    case err := <-chanTcpErr:{
                                        printf("Accept.err[%s]\n",err) ;
                                    }
                                }

                            }
                        }
                    }
                }
            }
        }

        server.wait.Done() ;
    }(server) ;

    server.wait.Wait() ;

    return nil ;
}

func TestRedis(addr string,opts ... any){

    server := &RedisServer{} ;

    packet := "*2\r\n$5\r\nhello\r\n$1\r\n3\r\n" ;

    printf("%s\n",Hexdump(packet)) ;

    if ui , err := url.Parse(addr) ; (err != nil){
        printf("err[%s]/addr[%s]\n",err,addr) ;
    }else{
        switch(ui.Scheme){
            case "tcp":{
                if conn,err := net.Dial("tcp", ui.Host) ; (err != nil){
                    printf("err[%s]/addr[%s]\n",err,addr) ;
                }else{
                    defer conn.Close()
                    if len,err := conn.Write(getBytes(packet)) ; (err != nil){
                        printf("err[%s]/addr[%s]\n",err,addr) ;
                    }else{
                        printf("Send(%d)\n",len) ;
                        buf := make([]byte,0x1000) ;
                        if szRc,err := conn.Read(buf) ; (err != nil){
                            printf("err[%s]/addr[%s]\n",err,addr) ;
                        }else{
                            // printf("Recv(%d)\n",szRc) ;
                            // printf("%s\n",Hexdump(string(buf[:szRc]))) ;

                            _,x,_ := server.DecodeProtocol(string(buf[:szRc])) ;

                            if(sprintf("%T",x) == "map[string]interface {}"){
                                for k,v := range x.(map[string]interface {}){
                                    printf("[%s][%T][%V]\n",k,v,v) ;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}














































