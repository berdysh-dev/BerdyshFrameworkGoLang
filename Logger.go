package BerdyshFrameworkGoLang

import (
    "io"
    "os"
    "log"
    "log/slog"
    "log/syslog"
    "net/url"
    "runtime"
    "strings"
    "context"
    "go.uber.org/zap"
    "net"
    "time"
    "regexp"
    "strconv"
_   "reflect"

)

type Level int ;

const (
    LevelDebug      slog.Level = slog.LevelDebug
    LevelInfo       slog.Level = slog.LevelInfo
    LevelWarn       slog.Level = slog.LevelWarn
    LevelError      slog.Level = slog.LevelError
    LevelNotice     slog.Level = 2
    LevelCritical   slog.Level = 12
    LevelAlert      slog.Level = 16
    LevelEmerg      slog.Level = 20
)

const (
    DEBUG       = "DEBUG"
    INFO        = "INFO"
    NOTICE      = "NOTICE"
    WARNING     = "WARNING"
    ERROR       = "ERROR"
    CRITICAL    = "CRITICAL"
    ALERT       = "ALERT"
    EMERGENCY   = "EMERGENCY"
)

type Value struct {
}

type JSONHandler struct {
    w       io.Writer ;
    opts    *HandlerOptions ;
}

type Logger struct {
    slogLogger      *slog.Logger ;
    Jh              JSONHandler ;
} ;

type LevelVar struct {
}

type Leveler interface {
    Level() Level
}

type HandlerOptions struct {
    AddSource bool ;
    Level Leveler ;
    ReplaceAttr func(groups []string, a slog.Attr) slog.Attr ;
} ;

var DefaultLogger   *Logger = &Logger{} ;

func SetDefault(logger *Logger){
    DefaultLogger = logger ;
    if(DefaultLogger.slogLogger != nil){
        slog.SetDefault(DefaultLogger.slogLogger) ;
    }
}

func (this *Logger) Log(level slog.Level,msg string,a ... any){
    this.slogLogger.Log(context.Background(),level,msg,a ...) ;
}

func IsPathGOROOT(path string) bool{
    p2,ok := os.LookupEnv("GOROOT") ;
    if(ok){
        a := strings.Split(p2,      "/") ;
        b := strings.Split(path,    "/") ;
        for idx,_ := range a{
            if(a[idx] != b[idx]){
                return false ;
            }
        }
        return true ;
    }else{
        return false ;
    }
}

func (this *Logger) Logf(level slog.Level,f string,a ... any){
    var msg string ;
    mode := XWriterEnumNull ;
    if(sprintf("%T",this.Jh.w) == "*BerdyshFrameworkGoLang.XWriter"){
        mode = this.Jh.w.(*XWriter).Mode ;
    }
    if(mode == XWriterEnumGoogleCloudLogging){
        msg = sprintf(f,a ...) ;
    }else{
        dept := 1 ;
        for {
            _, fileFull, line, ok := runtime.Caller(dept) ;
            if(ok){
                paths := strings.Split(fileFull, "/") ;
                file := paths[len(paths)-1] ;
                if((file == "WriteGoogleCloudLogging.go") || (file == "Logger.go") || IsPathGOROOT(fileFull)){
                    dept++ ; continue ;
                }
                msg = sprintf("%04d:%s:%s",line,file,sprintf(f,a ...)) ;
                break ;
            }else{
                break ;
            }
        }
    }
    this.Log(level,msg) ;
}

func (this *Logger) Debugf      (f string,a ... any){ this.Logf(LevelDebug      ,f,a ...) ; }
func (this *Logger) Infof       (f string,a ... any){ this.Logf(LevelInfo       ,f,a ...) ; }
func (this *Logger) Warnf       (f string,a ... any){ this.Logf(LevelWarn       ,f,a ...) ; }
func (this *Logger) Errorf      (f string,a ... any){ this.Logf(LevelError      ,f,a ...) ; }
func (this *Logger) Noticef     (f string,a ... any){ this.Logf(LevelNotice     ,f,a ...) ; }
func (this *Logger) Criticalf   (f string,a ... any){ this.Logf(LevelCritical   ,f,a ...) ; }
func (this *Logger) Alertf      (f string,a ... any){ this.Logf(LevelAlert      ,f,a ...) ; }
func (this *Logger) Emergf      (f string,a ... any){ this.Logf(LevelEmerg      ,f,a ...) ; }

func (this *Logger) Debugf_     (f string,a ... any){ ; }
func (this *Logger) Infof_      (f string,a ... any){ ; }
func (this *Logger) Warnf_      (f string,a ... any){ ; }
func (this *Logger) Errorf_     (f string,a ... any){ ; }
func (this *Logger) Noticef_    (f string,a ... any){ ; }
func (this *Logger) Criticalf_  (f string,a ... any){ ; }
func (this *Logger) Alertf_     (f string,a ... any){ ; }
func (this *Logger) Emergf_     (f string,a ... any){ ; }

func (this *Logger) Debug       (msg string, a ... any){ this.Log(LevelDebug        ,msg,a ...) ; }
func (this *Logger) Info        (msg string, a ... any){ this.Log(LevelInfo         ,msg,a ...) ; }
func (this *Logger) Warn        (msg string, a ... any){ this.Log(LevelWarn         ,msg,a ...) ; }
func (this *Logger) Error       (msg string, a ... any){ this.Log(LevelError        ,msg,a ...) ; }
func (this *Logger) Notice      (msg string, a ... any){ this.Log(LevelNotice       ,msg,a ...) ; }
func (this *Logger) Critical    (msg string, a ... any){ this.Log(LevelCritical     ,msg,a ...) ; }
func (this *Logger) Alert       (msg string, a ... any){ this.Log(LevelAlert        ,msg,a ...) ; }
func (this *Logger) Emerg       (msg string, a ... any){ this.Log(LevelEmerg        ,msg,a ...) ; }

func (this *Logger) Debug_      (msg string, a ... any){ ; }
func (this *Logger) Info_       (msg string, a ... any){ ; }
func (this *Logger) Warn_       (msg string, a ... any){ ; }
func (this *Logger) Error_      (msg string, a ... any){ ; }
func (this *Logger) Notice_     (msg string, a ... any){ ; }
func (this *Logger) Critical_   (msg string, a ... any){ ; }
func (this *Logger) Alert_      (msg string, a ... any){ ; }
func (this *Logger) Emerg_      (msg string, a ... any){ ; }

func Debugf     (f string,a ... any){ DefaultLogger.Debugf      (f,a ...) ; }
func Infof      (f string,a ... any){ DefaultLogger.Infof       (f,a ...) ; }
func Warnf      (f string,a ... any){ DefaultLogger.Warnf       (f,a ...) ; }
func Errorf     (f string,a ... any){ DefaultLogger.Errorf      (f,a ...) ; }
func Noticef    (f string,a ... any){ DefaultLogger.Noticef     (f,a ...) ; }
func Criticalf  (f string,a ... any){ DefaultLogger.Criticalf   (f,a ...) ; }
func Alertf     (f string,a ... any){ DefaultLogger.Alertf      (f,a ...) ; }
func Emergf     (f string,a ... any){ DefaultLogger.Emergf      (f,a ...) ; }

func Debugf_    (f string,a ... any){ ; }
func Infof_     (f string,a ... any){ ; }
func Warnf_     (f string,a ... any){ ; }
func Errorf_    (f string,a ... any){ ; }
func Noticef_   (f string,a ... any){ ; }
func Criticalf_ (f string,a ... any){ ; }
func Emergf_    (f string,a ... any){ ; }

func Debug      (msg string, args ...any){ DefaultLogger.Debug     (msg,args ...) ; }
func Info       (msg string, args ...any){ DefaultLogger.Info      (msg,args ...) ; }
func Warn       (msg string, args ...any){ DefaultLogger.Warn      (msg,args ...) ; }
func Error      (msg string, args ...any){ DefaultLogger.Error     (msg,args ...) ; }
func Notice     (msg string, args ...any){ DefaultLogger.Notice    (msg,args ...) ; }
func Critical   (msg string, args ...any){ DefaultLogger.Critical  (msg,args ...) ; }
func Alert      (msg string, args ...any){ DefaultLogger.Alert     (msg,args ...) ; }
func Emerg      (msg string, args ...any){ DefaultLogger.Emerg     (msg,args ...) ; }

func Debug_     (msg string, args ...any){ ; }
func Info_      (msg string, args ...any){ ; }
func Warn_      (msg string, args ...any){ ; }
func Error_     (msg string, args ...any){ ; }
func Notice_    (msg string, args ...any){ ; }
func Critical_  (msg string, args ...any){ ; }
func Alert_     (msg string, args ...any){ ; }
func Emerg_     (msg string, args ...any){ ; }

func NewJSONHandler(w io.Writer, opts *HandlerOptions) *JSONHandler{
    ret := JSONHandler{} ;
    ret.w = w ;
    ret.opts = opts ;
    return &ret ;
}

type    TypeFuncSLogJsonWriter  func(string,string) ;

type SLogJsonWriter struct {
    Hook        io.Writer ;
    Output      io.Writer ;
    CallBack    TypeFuncSLogJsonWriter ;
} ;

func (this *SLogJsonWriter) Write(p []byte) (n int, err error){

    var severity string ; _ = severity ;
    var message string ; _ = message ;
    var timestamp string ; _ = timestamp ;

    as := NewAssoc().DecodeJson(p) ;

    kv := TypeKV{} ;
    for i := as.Iterator() ; i.HasNext(&kv) ;i.Next(){

        switch(kv.K){
            case "timestamp":{
                timestamp = kv.V.Raw.(string) ;
            }
            case "severity":{
                severity = kv.V.Raw.(string) ;
            }
            case "message":{
                message = kv.V.Raw.(string) ;
            }
        }
    }

    if(this.Output != nil){
        return this.Output.Write(p) ;
    }else{
        if(this.CallBack != nil){
            this.CallBack(severity,message) ;
        }
    }

    return len(p) , nil ;
}

func NewSLogJsonWriter() (*SLogJsonWriter){
    ret := SLogJsonWriter{} ;
    ret.Hook  = &ret ;
    return &ret ;
}

func ReplaceAttrSlog(groups []string, attr slog.Attr) (slog.Attr){
    if(attr.Key == slog.LevelKey){
        level := attr.Value.Any().(slog.Level) ;
        switch(level){
        case LevelDebug     : attr.Value = slog.StringValue(DEBUG) ;
        case LevelInfo      : attr.Value = slog.StringValue(INFO) ;
        case LevelNotice    : attr.Value = slog.StringValue(NOTICE) ;
        case LevelWarn      : attr.Value = slog.StringValue(WARNING) ;
        case LevelError     : attr.Value = slog.StringValue(ERROR) ;
        case LevelCritical  : attr.Value = slog.StringValue(CRITICAL) ;
        case LevelAlert     : attr.Value = slog.StringValue(ALERT) ;
        case LevelEmerg     : attr.Value = slog.StringValue(EMERGENCY) ;
        }
    }
    return attr ;
}

func ReplaceAttrSlogGoogleCloudLogging(groups []string, attr slog.Attr) (slog.Attr){
    if(attr.Key == "time"){
        attr.Key = "timestamp" ;
    }
    if(attr.Key == "msg"){
        attr.Key = "message" ;
    }
    if(attr.Key == slog.LevelKey){
        attr.Key = "severity" ;
        level := attr.Value.Any().(slog.Level) ;
        switch(level){
        case LevelDebug     : attr.Value = slog.StringValue(DEBUG) ;
        case LevelInfo      : attr.Value = slog.StringValue(INFO) ;
        case LevelNotice    : attr.Value = slog.StringValue(NOTICE) ;
        case LevelWarn      : attr.Value = slog.StringValue(WARNING) ;
        case LevelError     : attr.Value = slog.StringValue(ERROR) ;
        case LevelCritical  : attr.Value = slog.StringValue(CRITICAL) ;
        case LevelAlert     : attr.Value = slog.StringValue(ALERT) ;
        case LevelEmerg     : attr.Value = slog.StringValue(EMERGENCY) ;
        }
    }
    return attr ;
}

type TypeXWriterFuncOutput  func(opts ... any) ;

type TypeXWriterFuncMiddleWareOutput    func(opts ... any)(any) ;

type XWriter struct {
    Mode int ;
    Disable             bool ;
    FuncOutput          TypeXWriterFuncOutput ;
    SyslogFacility      syslog.Priority ;
    SyslogLevel         syslog.Priority ;
    SyslogAddr          string ;

    MiddleWareOutput    TypeXWriterFuncMiddleWareOutput ;
    MiddleWareOutputs   []TypeXWriterFuncMiddleWareOutput ;

    GoogleCloudLogging  XWriterOptionGoogleCloudLogging ;
}

func (this *XWriter) GetMode() int{
    return this.Mode ;
}

func (this *XWriter) Setter(opts ... any) (*XWriter){

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "BerdyshFrameworkGoLang.XWriter":{
                def := opt.(XWriter) ;
                this.Disable = def.Disable ;
                if(def.FuncOutput != nil){
                    this.FuncOutput = def.FuncOutput
                }
                if(def.MiddleWareOutput != nil){
                    this.MiddleWareOutputs = append(this.MiddleWareOutputs,def.MiddleWareOutput) ;
                }

                if(def.SyslogAddr != ""){
                    this.SyslogAddr = def.SyslogAddr
                }

                this.SyslogFacility = def.SyslogFacility ;
                this.SyslogLevel = def.SyslogLevel ;

            }
            case "BerdyshFrameworkGoLang.XWriterOptionGoogleCloudLogging":{
                this.GoogleCloudLogging = opt.(XWriterOptionGoogleCloudLogging) ;
            }
            default:{
                printf("Unknowns[%s]\n",t) ;
            }
        }
    }
    return this ;
}

const (
    XWriterEnumNull     = iota
    XWriterEnumStdout
    XWriterEnumStderr
    XWriterEnumSyslog
    XWriterEnumStdLog
    XWriterEnumHook
    XWriterEnumGoogleCloudLogging
    XWriterEnumTest
    XWriterEnumTest2
    XWriterEnumTest3
)

type IF_XWriter interface {
    io.Writer
    Setter(opts ... any) (*XWriter)
    GetMode() int
}

func getBytes(str string) ([]byte){
    return []byte(str) ;
}

func (this *XWriter) lineSyslog(line string){

    network := "unix" ;
    addr := "/dev/log" ;

    if(this.SyslogAddr != ""){
        ui , err := url.Parse(this.SyslogAddr) ; _ = ui ;
        if(err != nil){
            printf("err-1[%s]\n",err) ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    network = "unix" ;
                    addr = ui.Path ;
                }
            }
        }
    }

    sysLog, err := syslog.Dial(network, addr,this.SyslogFacility|this.SyslogLevel,"") ;

    if(err != nil){
        printf("err-2[%s]\n",err) ;
    }else{
        defer sysLog.Close() ;
        sysLog.Write(getBytes(line)) ;
    }
}

func (this *XWriter) WriteSub(p []byte) (n int, err error){

    lines := strings.Split(string(p),"\n") ;

    for _,line := range lines{
        if(line != ""){
            this.lineSyslog(line) ;
        }
    }

    return n,nil ;
}

func (this *XWriter) Write(p []byte) (n int, err error){

    if(this.FuncOutput != nil){
        this.FuncOutput(Trim(string(p))) ;
    }else{
        switch(this.Mode){
            case XWriterEnumStdout:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumStderr:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumSyslog:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumStdLog:{
                return this.WriteSub(p) ;
            }
            case XWriterEnumHook:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumGoogleCloudLogging:{
                return this.WriteGoogleCloudLogging(p) ;
            }
            case XWriterEnumTest:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumTest2:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumTest3:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            default:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
        }
    }
    return n,nil ;
}

var XWriterStdout               IF_XWriter = &XWriter{Mode: XWriterEnumStdout} ;
var XWriterStderr               IF_XWriter = &XWriter{Mode: XWriterEnumStderr} ;
var XWriterSyslog               IF_XWriter = &XWriter{Mode: XWriterEnumSyslog} ;
var XWriterStdLog               IF_XWriter = &XWriter{Mode: XWriterEnumStdLog} ;
var XWriterHook                 IF_XWriter = &XWriter{Mode: XWriterEnumHook} ;
var XWriterGoogleCloudLogging   IF_XWriter = &XWriter{Mode: XWriterEnumGoogleCloudLogging} ;
var XWriterTest                 IF_XWriter = &XWriter{Mode: XWriterEnumTest} ;
var XWriterTest2                IF_XWriter = &XWriter{Mode: XWriterEnumTest2} ;
var XWriterTest3                IF_XWriter = &XWriter{Mode: XWriterEnumTest3} ;

func NewLogger(opts ... any) (*Logger){

    var ret *Logger ;
    ret = &Logger{} ;

    var jh *JSONHandler ;

    for _,opt := range opts{
        switch(sprintf("%T",opt)){
            case "*BerdyshFrameworkGoLang.JSONHandler":{
                jh = opt.(*JSONHandler) ;
                ret.Jh.w = jh.w ;
                ret.Jh.opts = jh.opts ;
            }
        }
    }

    logLevel := new(slog.LevelVar) ;
    logLevel.Set(slog.LevelDebug) ;
    op := slog.HandlerOptions{ Level: logLevel }
    
    if(ret.Jh.opts.ReplaceAttr != nil){
        op.ReplaceAttr = ret.Jh.opts.ReplaceAttr ;
    }else{
        op.ReplaceAttr = ReplaceAttrSlog ;
    }

    jsonWriter := NewSLogJsonWriter() ;

    jsonWriter.Output = ret.Jh.w ;

    if(true){
        jsonWriter.CallBack = func(severity string,message string){
            printf("severity[%s]/msg[%s]\n",severity,message) ;
        } ;
    }

    loggerHandler := slog.NewJSONHandler(jsonWriter.Hook,&op) ;

    ret.slogLogger = slog.New(loggerHandler) ;

    return ret ;
}

type MySlogHandler struct {
}

func (this *MySlogHandler) Enabled(context.Context, slog.Level) bool{

    printf("Enabled.\n") ;

    return false ;
}

func (this *MySlogHandler) Handle(context.Context, slog.Record) error{
    printf("Handle.\n") ;
    return nil ;
}

func (this *MySlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler{
    printf("WithAttrs.\n") ;
    return this ;
}

func (this *MySlogHandler) WithGroup(name string) slog.Handler{
    printf("WithGroup.\n") ;
    return this ;
}

func TestSlog(){

    var handler slog.Handler = &MySlogHandler{} ;
    var oldLogger *log.Logger ;

    oldLogger = slog.NewLogLogger(handler,slog.LevelInfo) ; _ = oldLogger ;

//    logger.Debug("XXX") ;

}

func TestLogStd(){
    var oldLogger *log.Logger ; _ = oldLogger ;

    if(true){
        oldLogger = log.Default() ;
    }else{
        oldLogger = log.New(XWriterTest,"prefix" ,0) ;
    }

    w := oldLogger.Writer() ;

    if(sprintf("%T",w) == "*os.File"){
    }

    oldLogger.SetOutput(XWriterStdLog) ;
    oldLogger.SetPrefix("") ;
    oldLogger.SetFlags(0) ;

    log.Printf("XXX\n") ;

}

func TestLogZap(){
    logger, err := zap.NewDevelopment()

    if(err != nil){
        printf("err-3[%s]\n",err) ;
    }else{
        defer logger.Sync() ;
        var cfg zap.Config ;
        printf("type[%T]\n",cfg) ;
    }

}

const (
    SOCKET_LOG  = "/dev/log"
)

type SyslogDaemonHandle interface {
    EvRecv() ;
}

type SyslogDaemonEntry struct {
    SyslogFacility      syslog.Priority ;
    SyslogLevel         syslog.Priority ;
    Handle              SyslogDaemonHandle ;
}


type SyslogDaemonRouter struct {
    Entrys []SyslogDaemonEntry ;
}

func (this *SyslogDaemonRouter) Init() (*SyslogDaemonRouter){

    this.Entrys = make([]SyslogDaemonEntry,0) ;

    return this ;
}

func (this *SyslogDaemonRouter) Handle(entry SyslogDaemonEntry,handle SyslogDaemonHandle) (*SyslogDaemonRouter){

    entry.Handle = handle ;
    this.Entrys = append(this.Entrys,entry) ;

    return this ;
}

func NewSyslogDaemonRouter() (*SyslogDaemonRouter){
    ret := SyslogDaemonRouter{} ;
    return ret.Init() ;
}

func Tick(){
    for lp:=1;;lp+=1 {
        time.Sleep(1 * time.Second) ;
        Debugf("Syslogd[%06d].",lp) ;
    }
}

func EvRecvSyslog(router *SyslogDaemonRouter,s string){

    var Facility string ; _ = Facility ;
    var Priority string ; _ = Priority ;

    var facility    syslog.Priority = -1 ; _ = facility ;
    var priority    syslog.Priority = -1 ; _ = priority ;

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
            case 0:{
                Facility = "LOG_KERN" ;
                facility = syslog.LOG_KERN ;
            }
            case 1:{
                Facility = "LOG_USER" ;
                facility = syslog.LOG_USER ;
            }
            case 2:{
                Facility = "LOG_MAIL" ;
                facility = syslog.LOG_MAIL ;
            }
            case 3:{
                Facility = "LOG_DAEMON" ;
                facility = syslog.LOG_DAEMON ;
            }
            case 4:{
                Facility = "LOG_AUTH" ;
                facility = syslog.LOG_AUTH ;
            }
            case 5:{
                Facility = "LOG_SYSLOG" ;
                facility = syslog.LOG_SYSLOG ;
            }
            case 6:{
                Facility = "LOG_LPR" ;
                facility = syslog.LOG_LPR ;
            }
            case 7:{
                Facility = "LOG_NEWS" ;
                facility = syslog.LOG_NEWS ;
            }
            case 8:{
                Facility = "LOG_UUCP" ;
                facility = syslog.LOG_UUCP ;
            }
            case 9:{
                Facility = "LOG_CRON" ;
                facility = syslog.LOG_CRON ;
            }
            case 10:{
                Facility = "LOG_AUTHPRIV" ;
                facility = syslog.LOG_AUTHPRIV ;
            }
            case 11:{
                Facility = "LOG_FTP" ;
                facility = syslog.LOG_FTP ;
            }
            case 16:{
                Facility = "LOG_LOCAL0" ;
                facility = syslog.LOG_LOCAL0 ;
            }
            case 17:{
                Facility = "LOG_LOCAL1" ;
                facility = syslog.LOG_LOCAL1 ;
            }
            case 18:{
                Facility = "LOG_LOCAL2" ;
                facility = syslog.LOG_LOCAL2 ;
            }
            case 19:{
                Facility = "LOG_LOCAL3" ;
                facility = syslog.LOG_LOCAL3 ;
            }
            case 20:{
                Facility = "LOG_LOCAL4" ;
                facility = syslog.LOG_LOCAL4 ;
            }
            case 21:{
                Facility = "LOG_LOCAL5" ;
                facility = syslog.LOG_LOCAL5 ;
            }
            case 22:{
                Facility = "LOG_LOCAL6" ;
                facility = syslog.LOG_LOCAL6 ;
            }
            case 23:{
                Facility = "LOG_LOCAL7" ;
                facility = syslog.LOG_LOCAL7 ;
            }
        }

        switch(priorityN){
            case 0:{
                Priority = "LOG_EMERG" ;
                priority = syslog.LOG_EMERG ;
            }
            case 1:{
                Priority = "LOG_ALERT" ;
                priority = syslog.LOG_ALERT ;
            }
            case 2:{
                Priority = "LOG_CRIT" ;
                priority = syslog.LOG_CRIT ;
            }
            case 3:{
                Priority = "LOG_ERR" ;
                priority = syslog.LOG_ERR ;
            }
            case 4:{
                Priority = "LOG_WARNING" ;
                priority = syslog.LOG_WARNING ;
            }
            case 5:{
                Priority = "LOG_NOTICE" ;
                priority = syslog.LOG_NOTICE ;
            }
            case 6:{
                Priority = "LOG_INFO" ;
                priority = syslog.LOG_INFO ;
            }
            case 7:{
                Priority = "LOG_DEBUG" ;
                priority = syslog.LOG_DEBUG ;
            }
        }

        printf("[%s][%s][%s][%s]\n",Facility,Priority,date,mess) ;
    }
}

func SyslogDaemonNode(addrListen string,router *SyslogDaemonRouter){
    netDial := "unix" ; _ = netDial ;
    addrDial := "/dev/log" ; _ = addrDial ;

    if(addrListen != ""){
        if ui , err := url.Parse(addrListen) ; (err != nil){
            printf("err-8[%s]\n",err) ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    netDial = "unix" ;
                    addrDial = ui.Path ;
                }
            }
        }
    }

    if(netDial == "unix"){
        if _ , err := os.Stat(addrDial) ; (err == nil){
            if(addrDial == "/dev/log"){
                os.Remove(addrDial) ;
            }
        }
    }

    unixAddr, err := net.ResolveUnixAddr(netDial,addrDial) ;

    if(err != nil){
        printf("err-9[%s]\n",err) ;
    }else{
        sockListen, err := net.ListenUnix("unix",unixAddr) ; _ = sockListen ;
        if(err != nil){
            printf("err-10[%s]\n",err) ;
        }else{
            printf("ok[%s]\n",addrDial) ;
            for{
                unixConn, err := sockListen.Accept() ;
                if(err != nil){
                    printf("err-11[%s]\n",err) ;
                }else{
                    buf := make([]byte,4096) ;
                    var szRc int ; _ = szRc ;
                    szRc,err = unixConn.Read(buf) ;
                    if(err != nil){
                        printf("err-12[%s]\n",err) ;
                    }else{
                        EvRecvSyslog(router,string(buf)) ;
                    }
                }
            }
        }
    }
}

func SyslogDaemon(opts ... any) (error){

    var router *SyslogDaemonRouter = nil ;

    addrListens := make([]string,0) ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;

        switch(t){
            case "*BerdyshFrameworkGoLang.SyslogDaemonRouter":{
                router = opt.(*SyslogDaemonRouter)
            }
            case "string":{
                addrListens = append(addrListens,opt.(string)) ;
            }
        }
    }

    if(len(addrListens) == 0){
        addrListens = append(addrListens,"unix:///dev/log") ;
    }

    for _,addrListen := range addrListens{
        SyslogDaemonNode(addrListen,router) ;
    }

    // time.Sleep(1 * time.Second) ;

    return nil ;
}




















