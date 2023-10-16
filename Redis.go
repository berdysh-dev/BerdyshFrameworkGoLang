package BerdyshFrameworkGoLang

import(
    "sync"
    "os"
    "io"
    "net"
    "net/url"
    "math/big"
)

const (
    RedisClientSetinfoLibName       = "LIB-NAME"
    RedisClientSetinfoLibVer        = "LIB-VER"
) ;

const (
    RedisHelloServer        = "server"
    RedisHelloRedis         = "redis"
    RedisHelloVersion       = "version"
    RedisHelloProto         = "proto"
    RedisHelloId            = "id"
    RedisHelloMode          = "mode"
    RedisHelloStandalone    = "standalone"
    RedisHelloRole          = "role"
    RedisHelloMaster        = "master"
    RedisHelloModules       = "modules"
) ;

func BuildHelloReqponse() (string){

    m := make(map[string]interface {}) ; _ = m ;

    m[RedisHelloServer]     = RedisHelloRedis ;
    m[RedisHelloVersion]    = "7.0.13" ;
    m[RedisHelloProto]      = 3 ;
    m[RedisHelloId]         = 29 ;
    m[RedisHelloMode]       = RedisHelloStandalone ;
    m[RedisHelloRole]       = RedisHelloMaster ;
    m[RedisHelloModules]    = make([]interface{},0) ;

    return EncodeRESP3(m) ;
}

func BuildClientSetinfoRequest() (string){
    m := make([]interface{} ,0) ; _ = m ;
    m = append(m,"CLIENT","SETINFO","LIB-NAME","go-redis(,go1.21.0)") ;

    return EncodeRESP3(m) ;
}

type RedisServer struct {
    Entrys  []RedisEvalEntry ;
    Addr    any ;
    wait    sync.WaitGroup ;
}

type RedisPacket struct {
}

func EncodeRESP3_string(s string) (string){
    return sprintf("$%d\r\n%s\r\n",len(s),s) ;
}

func EncodeRESP3_int(i int) (string){
    return sprintf(":%d\r\n",i) ;
}

func EncodeRESP3_bool_old(b bool) (string){
    var s string ;
    if(b == true){
        s = "1" ;
    }else{
        s = "0" ;
    }
    return EncodeRESP3_string(s) ;
}

func EncodeRESP3_bool_new(b bool) (string){
    if(b == true){
        return "#t\r\n" ;
    }else{
        return "#f\r\n" ;
    }
}

func EncodeRESP3(src any) (string){
    ret := "" ;
    t := sprintf("%T",src) ;
    switch t {
        case "[]interface{}","[]interface {}":{
            m := src.([]interface{}) ;
            ret += sprintf("*%d\r\n",len(m)) ;
            for _,v := range m{
                ret += EncodeRESP3(v) ;
            }
        }
        case "map[string]interface{}","map[string]interface {}":{
            m := src.(map[string]interface {}) ; _ = m ;
            ret += sprintf("%%%d\r\n",len(m)) ;
            for k,v := range m{
                ret += EncodeRESP3_string(k) ;
                ret += EncodeRESP3(v) ;
            }
        }
        case "bool":{
            if(true){
                ret += EncodeRESP3_bool_old(src.(bool)) ;
            }else{
                ret += EncodeRESP3_bool_new(src.(bool)) ;
            }
        }
        case "nil":{
            ret += "$-1\r\n" ;
        }
        case "int":{
            ret += EncodeRESP3_int(src.(int)) ;
        }
        case "string":{
            ret += EncodeRESP3_string(src.(string)) ;
        }
        default:{
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-Unknown[%s]\n",t) ;
        }
    }
    return ret ;
}

/*
    https://github.com/antirez/RESP3/blob/master/spec.md
*/

func DecodeRESP3(bin []byte,idx int) (int,any,error){
    var x any ;
    L := len(bin) ; _ = L ;

    var kind byte ;

    if(L >= 1){
        kind = bin[idx] ;
    }else{
        return idx,nil,ErrNotEnough ;
    }

    b := make([]byte,0) ;

    switch(kind){
        case '+','-','_':{
            idx += 1 ;
            b = append(b,kind) ;
            for {
                if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                    idx += 2 ;
                    if(kind == '_'){
                        return idx,nil,nil ;
                    }else{
                        return idx,string(b),nil ;
                    }
                }else{
                    b = append(b,bin[idx]) ;
                    idx += 1 ;
                }
            }
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
        case ',':{ // Double
            idx += 1 ;
            for {
                if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                    idx += 2 ;
                    var d float64 = 0 ;  // ToDo: b -> d double.
                                        // ToDp: "inf" , "-inf"
                                        // +Int -Int

                    str := string(b)
                    switch(str){
                        case "inf":{
                        }
                        case "-inf":{
                        }
                        default:{
                        }
                    }

                    return idx,d,nil ;
                }else{
                    b = append(b,bin[idx]) ;
                    idx += 1 ;
                }
            }
        }
        case '(':{ // Big number
            idx += 1 ;
            for {
                if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                    idx += 2 ;

                    r := new(big.Rat)
                    r.SetString(string(b)) ;

                    return idx,r,nil ;
                }else{
                    b = append(b,bin[idx]) ;
                    idx += 1 ;
                }
            }
        }
        case '#':{ // Boolean
            if((bin[idx+0] == '#') && (bin[idx+1] == 't') && (bin[idx+2] == 0x0d) && (bin[idx+3] == 0x0a)){
                idx += 4 ;
                return idx,true,nil ;
            }else if((bin[idx+0] == '#') && (bin[idx+1] == 'f') && (bin[idx+2] == 0x0d) && (bin[idx+3] == 0x0a)){
                return idx,false,nil ;
            }else{
                return idx,nil,Errorf("Broken") ;
            }
        }
        case '=','!':{ // !:blob error  , =:Verbatim string
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
                        for jjj:=0 ; jjj<num;jjj++ {
                            b = append(b,bin[idx+jjj]) ;
                        }
                        printf("=:Num[%d][%s]\n",num,string(b)) ;
                        idx += num ;
                        if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                            idx += 2 ;
                            return idx,string(b),nil ;
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
                        for jjj:=0 ; jjj<num;jjj++ {
                            b = append(b,bin[idx+jjj]) ;
                        }
                        // printf("$:Num[%d][%s]\n",num,string(b)) ;
                        idx += num ;
                        if((bin[idx+0] == CR) && (bin[idx+1] == LF)){
                            idx += 2 ;
                            return idx,string(b),nil ;
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
        case '*','%','~':{
            idx += 1 ;

            if((bin[idx + 0] == '-') && (bin[idx + 1] == '1') && (bin[idx + 2] == 0x0d) && (bin[idx + 3] == 0x0a)){
                idx += 4 ;
                return idx,nil,nil ;
            }

            num := 0;
            for{
                if((bin[idx] >= '0') && (bin[idx] <= '9')){
                    num = (num * 10) + ((int)(bin[idx]) - '0') ;
                    idx += 1 ;
                }else if((bin[idx+0] == 0x0d) && (bin[idx+1] == 0x0a)){
                    idx += 2 ;
                    if((kind == '*') || (kind == '~')){
                        ret := make([]any,0) ;
                        for iii := 0 ; iii<num ; iii++ {
                            idx,x,_ = DecodeRESP3(bin,idx) ;
                            ret = append(ret,x) ;
                        }
                        return idx,ret,nil ;
                    }else if(kind == '%'){
                        ret := make(map[string]any) ;
                        for iii := 0 ; iii<num ; iii++ {
                            var k any ;
                            var v any ;
                            idx,k,_ = DecodeRESP3(bin,idx) ;
                            idx,v,_ = DecodeRESP3(bin,idx) ;

                            if(sprintf("%T",k) == "string"){
                                ret[k.(string)] = v ;
                            }else{
                                printf("!!![%s][%V][%V]\n",Chr(kind),k,v) ;

                            }
                        }
                        return idx,ret,nil ;
                    }
                }else{
                    printf("NotCR[0x%x][0x%x]\n",bin[idx],bin[idx+1]) ;
                    break ;
                }
            }
        }
        default:{
            printf("なし[0x%02x]\n",kind) ;
        }
    }
    return idx,nil,nil ;
}

func DecodeProtocol(fifo string) (string,any,error){

    packet := RedisPacket{} ; _ = packet ;
    bin := []byte(fifo) ; _ = bin ;

    if(false){
        printf("Recv:\n%s\n",fifo) ;
        printf("%s\n\n",Hexdump(fifo)) ;
    }

    idx,x,err := DecodeRESP3(bin,0) ; _ = idx ; _ = err ;

    // printf("LEN[%d/%d]\n",idx,len(bin)) ;

    if(idx != len(bin)){
        printf("%s\n\n",Hexdump(fifo)) ;
        printf("%s\n\n",fifo) ;
    }

    return "",x,err ;
}

type ServerConn struct {
    tcpConn *net.TCPConn ;
}

func (conn *ServerConn) DoCmd(x any){

    printf("[%T]\n",x) ;
    printf("[%V]\n",x) ;

    if(sprintf("%T",x) == "[]interface {}"){
        m := x.([]interface {}) ;
        for idx,v := range m{
            printf("AR:%03d:[%T][%V]\n",idx,v,v) ;
            idx += 1 ;
        }

        if(len(m) >= 1){
            cmd := m[0].(string) ;
            switch(ToUpper(cmd)){
                case "HELLO":{
                    protover := "" ;
                    if(len(m) >= 2){ protover = m[1].(string) ; }
                    if(protover == "3"){
                        packet := BuildHelloReqponse() ;
                        if szRc,err := conn.tcpConn.Write(getBytes(packet)) ; (err != nil){
                            printf("Write.err[%s]\n",err) ;
                        }else{
                            printf("Write.OK[%d]\n",szRc) ;
                        }
                    }
                }
                case "CLIENT":{
                    if(len(m) >= 2){
                        cmdSub := ToUpper(m[1].(string)) ;
                        switch(cmdSub){
                            case "SETINFO":{
                                if(len(m) >= 3){
                                    opt := m[2].(string) ;
                                    switch(opt){
                                        case RedisClientSetinfoLibName:{
                                            printf("!![%s]\n",opt) ;
                                        }
                                        case RedisClientSetinfoLibVer:{
                                            printf("!![%s]\n",opt) ;
                                        }
                                        default:{
                                            printf("!![%s]\n",opt) ;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }else{
            printf("Assert[%d]\n",len(m)) ;
        }
    }
}

func (conn *ServerConn) EvAccept(){
    var err error ; _ = err ;
    var packet any ;
    var szRc int ; _ = szRc ;

    printf("TCP-Accept.\n") ;
    buf := make([]byte,0x1000) ;
    fifo := "" ;

    for{
        if szRc,err = conn.tcpConn.Read(buf) ; (err != nil){
            printf("Read.err[%s]\n",err) ;
            break ;
        }else{
            if(szRc > 0){
                fifo += string(buf[:szRc]) ;
                for{
                    if fifo,packet,err = DecodeProtocol(fifo) ; (err != nil){
                        printf("err[%s]\n",err) ;
                        break ;
                    }else{
                        printf("OK[]\n") ;
                        conn.DoCmd(packet) ;
                    }
                }
            }
        }
    }
    conn.tcpConn.Close() ;
}

func (server *RedisServer) NewServerConn(con any) (*ServerConn){
    ret := ServerConn{} ;

    t := sprintf("%T",con) ;

    switch(t){
        case "*net.TCPConn":{
            ret.tcpConn = con.(*net.TCPConn) ;
        }
    }

    return &ret ;
}

type RedisServerOption struct {
    Addr    any ;
}

func NewRedisServer(opts ... any)(*RedisServer,error){
    server := &RedisServer{} ;

    server.Entrys = make([]RedisEvalEntry,0) ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "*BerdyshFrameworkGoLang.RedisServerOption":{
                x := opt.(*RedisServerOption) ;
                server.Addr = x.Addr ;
            }
            default:{
                printf("!!![%s]\n",t) ;
            }
        }
    }

    // server.Addr = addr ;

    return server,nil ;
}

type RedisClient struct {
    lastErr     error ;
    Addr        string ;
    Network     string ;
    Host        string ;
    Path        string ;

    conn        net.Conn ;

    protoversion    int ;
    serverversion   string ;
}

func (cli *RedisClient) Call(opts ... any) (any,error){

    var err error ; _ = err ;
    var x any ; _ = x ;

    buf := make([]byte,0x1000) ;

    packet := EncodeRESP3(opts) ;

    printf("%s\n\n",Hexdump(packet)) ;

    if(cli.conn == nil){
        return nil,Errorf("Not connect [%s]",cli.Addr) ;
    }else if len,err := cli.conn.Write(getBytes(packet)) ; (err != nil){
        return nil,err ;
    }else{
        _ = len ;
        fifo := "" ;
        for{
            if szRc,err := cli.conn.Read(buf) ; (err != nil){
                return nil,err ;
            }else{
                fifo += string(buf[:szRc]) ;
                fifo,x,err = DecodeProtocol(fifo) ; _ = err ; _ = x ;

                if(err != nil){
                    return nil,err ;
                }else{
                    return x,nil ;
                }
                break ;
            }
        }
    }

    return nil,nil ;
}

func (cli *RedisClient) LastErr() (error){
    return cli.lastErr ;
}

func NewRedisClient(opts ... any) (*RedisClient){
    var cli *RedisClient = nil ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "BerdyshFrameworkGoLang.RedisClient":{
                tmp := opt.(RedisClient) ;
                cli = &tmp ;
            }
            case "*BerdyshFrameworkGoLang.RedisClient":{
                cli = opt.(*RedisClient) ;
            }
            default:{
                printf("!![%s]\n",t) ;
            }
        }
    }

    if(cli == nil){ cli = &RedisClient{} ; }

    if(cli.Addr == ""){ cli.Addr = "tcp://:6379" ; }

    if ui , err := url.Parse(cli.Addr) ; (err == nil){
        switch(ui.Scheme){
            case "tcp":{
                cli.Network = ui.Scheme ;
                cli.Host = ui.Host ;
            }
            case "unix":{
                cli.Network = ui.Scheme ;
                cli.Path = ui.Path ;
            }
        }
    }

    if(cli.Network == ""){
        cli.Network = "tcp" ;
        cli.Host = cli.Addr ;
    }

    switch(cli.Network){
        case "tcp":{
            if conn,err := net.Dial(cli.Network,cli.Host) ; (err != nil){
                cli.lastErr = err ;
            }else{
                cli.conn = conn ;
            }
        }
        case "unix":{
            if conn,err := net.Dial(cli.Network,cli.Path) ; (err != nil){
                cli.lastErr = err ;
            }else{
                cli.conn = conn ;
            }
        }
    }

    if(cli.conn != nil){
        if res,err := cli.Call("hello","3") ; (err != nil){
            cli.lastErr = err ;
        }else{
            if(sprintf("%T",res) == "map[string]interface {}"){
                m := res.(map[string]interface {}) ;
                for k,v := range m{
                    switch(k){
                        case "proto":{ cli.protoversion = v.(int) ; }
                        case "version":{ cli.serverversion = v.(string) ; }
                        default:{
                            // printf("[%s][%V]\n",k,v) ;
                        }
                    }
                }
            }
        }
        if(false && (cli.protoversion == 3)){
            if res,err := cli.Call("CLIENT","SETINFO","LIB-NAME","go-redis(,go1.21.0)") ; (err != nil){
                cli.lastErr = err ;
                // printf("err[%s]\n",err) ;
            }else{
                _ = res ;
            }
        }
    }

    return cli ;
}

func TestRedis(addr string,opts ... any){
}

type RedisEvalEntryInterface interface {
    Init() ;
    Do(f string,src string) (string) ;
}

type RedisEvalEntry struct {
    Function    any ;
    H           RedisEvalEntryInterface ;
}

func NewRedisEvalEntry(opts ... any) (RedisEvalEntry){
    ret := RedisEvalEntry{} ;
    return ret ;
}

func (this *RedisEvalEntry) SetFunction(opts ... any) (*RedisEvalEntry) {

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "string":{
                if(this.Function == nil){
                    this.Function = opt.(string) ;
                }else{
                    t2 := sprintf("%T",this.Function) ;
                    switch(t2){
                        case "string":{
                            x := make([]string,0) ;
                            x = append(x,this.Function.(string)) ;
                            x = append(x,opt.(string)) ;
                            this.Function = x ;
                        }
                        case "[]string":{
                            this.Function = append(this.Function.([]string),opt.(string)) ;
                        }
                        default:{
                            printf("!!!-t2[%s]\n",t2) ;
                        }
                    }
                }
            }
            default:{
                printf("!!!-t[%s]\n",t) ;
            }
        }
    }

    return this ;
}

func (server *RedisServer) DoProcUnix(ui *url.URL){
    netDial := ui.Scheme ; _ = netDial ;
    addrDial := ui.Path ; _ = addrDial ;

    var x any ; _ = x ;

    if _ , err := os.Stat(addrDial) ; (err == nil){
        if(addrDial == "/run/redis.sock"){
            os.Remove(addrDial) ;
        }
    }

    if unixAddr, err := net.ResolveUnixAddr(netDial,addrDial) ; (err != nil){
        Printf("err[%s]/path[%s]\n",err,addrDial) ;
    }else{
        if sockListen, err := net.ListenUnix(netDial,unixAddr) ; (err != nil){
            Printf("ListenUnix-err[%s]/path[%s]\n",err,addrDial) ;
        }else{
            Printf("UNIX-Listen-OK[]/addr[%s]\n",addrDial) ;
            server.wait.Done() ;
            for{
                if unixConn, err := sockListen.Accept() ; (err != nil){
                    Printf("err[%s]/addr[%s]\n",err,addrDial) ;
                }else{
                    go func(){
                        buf := make([]byte,0x1000) ;
                        var szRc int ;
                        fifo := "" ;
                        for {
                            if szRc,err = unixConn.Read(buf) ; (err == nil){

                                fifo += string(buf[:szRc]) ;
                                // printf("\n%s\n",Hexdump(fifo)) ;

                                fifo,x,err = DecodeProtocol(fifo) ; _ = err ; _ = x ;

                                Res := "" ;

                                if(sprintf("%T",x) == "[]interface {}"){
                                    Q := x.([]interface {}) ;

                                    for idx,v := range Q{
                                        printf("[%02d][%V]\n",idx,v) ;
                                    }

                                    switch(Q[0].(string)){
                                        case "EVAL":{
                                            script := Q[1].(string) ; _ = script ;
                                            numkeys := Q[2].(string) ; _ = numkeys ;
                                            arg := Q[3].(string) ; _ = arg ;

                                            for _,e := range server.Entrys{
                                                switch(sprintf("%T",e.Function)){
                                                    case "[]string":{
                                                        for _,f := range e.Function.([]string){
                                                            if(f == script){
                                                                Res = e.H.Do(script,arg) ;
                                                                goto brk ;
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                        }
                                    }
                                }
brk:
                                packet := sprintf("$%d\r\n%s\r\n",len(Res),Res) ;
                                unixConn.Write([]byte(packet)) ;

                            }else{
                                unixConn.Close() ;
                                if(err == io.EOF){
                                    // printf("unix-recv[%s]\n",err) ;
                                }else{
                                    printf("unix-recv[%s]\n",err) ;
                                }
                                break ;
                            }
                        }
                    }() ;
                }
            }
        }
    }
}

func (server *RedisServer) DoProcTcp(ui *url.URL){

    netDial := ui.Scheme ; _ = netDial ;
    addrDial := ui.Host ; _ = addrDial ;

    if tcpAddr, err := net.ResolveTCPAddr(netDial,addrDial) ; (err != nil) {
        Printf("err[%s]/addr[%s]\n",err,addrDial) ;
    }else{
        if tcpListener, err := net.ListenTCP(netDial,tcpAddr) ; (err != nil) {
            Printf("err[%s]/addr[%s]\n",err,addrDial) ;
        }else{
            Printf("TCP-Listen-OK[]/addr[%s]\n",addrDial) ;
            server.wait.Done() ;
            for{
                chanTcpConn := make(chan *net.TCPConn) ;
                chanTcpErr := make(chan error) ;
                go func(){
                    tcpConn, err := tcpListener.AcceptTCP() ;
                    if (err != nil) {
                        chanTcpErr <- err ;
                        return ;
                    }
                    chanTcpConn <- tcpConn ;
                }() ;
                select {
                    case tcpConn := <-chanTcpConn:{
                        conn := server.NewServerConn(tcpConn) ;
                        go conn.EvAccept() ;
                    }
                    case err := <-chanTcpErr:{
                        printf("Accept.err[%s]\n",err) ;
                    }
                }
            }
        }
    }
}

func (server *RedisServer) DoProc(opts ... any) (*RedisServer) {

    addrs := make([]string,0) ;

    t := sprintf("%T",server.Addr) ;
    switch(t){
        case "string":{
            addrs = append(addrs,server.Addr.(string)) ;
        }
    }

    for _,addr := range addrs{
        if ui , err := url.Parse(addr) ; (err != nil){
            Printf("err[%s]/addr[%s]\n",err,addr) ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    server.wait.Add(1) ;
                    go func(){
                        server.DoProcUnix(ui) ;
                    }() ;
                }
                case "tcp":{
                    server.wait.Add(1) ;
                    go func(){
                        server.DoProcTcp(ui) ;
                    }() ;
                }
            }
        }
    }

    printf("Wait-Start.\n") ;
    server.wait.Wait() ;
    printf("Wait-OK.\n") ;
    return server ;
}

func (server *RedisServer) Handle(entry RedisEvalEntry,h RedisEvalEntryInterface) (*RedisServer){
    h.Init() ;
    entry.H = h ;
    server.Entrys = append(server.Entrys,entry) ;
    return server ;
}












































