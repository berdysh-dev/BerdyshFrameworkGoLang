package BerdyshFrameworkGoLang

import (
    "io"
    "os"
    "log"
    "log/slog"
    "log/syslog"
    "net/url"
    "net/netip"
    "runtime"
    "strconv"
    "strings"
    "context"
    "go.uber.org/zap"
    "net"
    "time"
    "sync"
_   "regexp"
_   "strconv"
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

        printf("p2[%V]",p2) ;

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
func ErrorfLog  (f string,a ... any){ DefaultLogger.Errorf      (f,a ...) ; }
func Noticef    (f string,a ... any){ DefaultLogger.Noticef     (f,a ...) ; }
func Criticalf  (f string,a ... any){ DefaultLogger.Criticalf   (f,a ...) ; }
func Alertf     (f string,a ... any){ DefaultLogger.Alertf      (f,a ...) ; }
func Emergf     (f string,a ... any){ DefaultLogger.Emergf      (f,a ...) ; }

func Debugf_    (f string,a ... any){ ; }
func Infof_     (f string,a ... any){ ; }
func Warnf_     (f string,a ... any){ ; }
func ErrorfLog_ (f string,a ... any){ ; }
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
    SyslogSeverity      syslog.Priority ;
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
                this.SyslogSeverity = def.SyslogSeverity ;

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

    // printf("\n%s\n",Hexdump(line)) ;

    sysLog, err := syslog.Dial(network, addr,this.SyslogFacility|this.SyslogSeverity,"") ;

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

func slogLevel2SyslogSeverity(level any) (syslog.Priority){

    if(sprintf("%T",level) == "string"){
        switch(level.(string)){
            case DEBUG:{ return syslog.LOG_DEBUG ; }
            case INFO:{ return syslog.LOG_INFO ; }
            case NOTICE:{ return syslog.LOG_NOTICE ; }
            case WARNING:{ return syslog.LOG_WARNING ; }
            case ERROR:{ return syslog.LOG_ERR ; }
            case CRITICAL:{ return syslog.LOG_CRIT ; }
            case ALERT:{ return syslog.LOG_ALERT ; }
            case EMERGENCY:{ return syslog.LOG_EMERG ; }
            default:{ printf("!!![%s]\n",level.(string)) ; }
        }
    }
    return 0 ;
}

func (this *XWriter) WriteSyslog(p []byte) (n int, err error){

    // printf("[%s:%d:%d][%s]-427\n",this.SyslogAddr,this.SyslogFacility,this.SyslogSeverity,Trim(string(p))) ;

    network := "unix" ;
    addr := "/dev/log" ;

    var syslogSeverity syslog.Priority = -1 ;

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

    msg := "" ;
    as := NewAssoc().DecodeJson(p) ;
    kv := TypeKV{} ;

    countOther := 0 ;
    for i := as.Iterator() ; i.HasNext(&kv) ;i.Next(){
        switch(kv.K){
            case "time":{
                ;
            }
            case "msg":{
                msg = kv.V.Raw.(string) ;
            }
            case "level":{
                syslogSeverity = slogLevel2SyslogSeverity(kv.V.Raw) ;
            }
            default:{
                countOther += 1 ;
            }
        }
    }

    if(syslogSeverity < 0){
        return n,errorf("Severity") ;
    }else{
        sysLog, err := syslog.Dial(network, addr,this.SyslogFacility|syslogSeverity,"") ;
        if(err != nil){
            printf("err-2[%s]\n",err) ;
        }else{
            defer sysLog.Close() ;
            if((countOther > 0) || (msg == "")){
                sysLog.Write(p) ;
            }else{
                sysLog.Write(([]byte)(msg)) ;
            }
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
                return this.WriteSyslog(p) ;
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

type syslogEntryInited  int ;

const (
    syslogEntryInitedRandom = 432271
)

type SyslogEntry struct {

    inited          syslogEntryInited ;

    Pri             int ;
    Facility        syslog.Priority ;
    Severity        syslog.Priority ;

    Date            time.Time ;

    Timestamp       string ;
    Tag             string ;
    AppName         string ;
    Hostname        string ;
    MsgId           string ;
    StructuredData  string ;
    ProcId          string ;
    Version         int ;

    IsRFC3164       bool ;
    IsRFC5424       bool ;
    IsRFC6587       bool ;

    Message         string ;

    Handle          SyslogHandle ;
}

type SyslogHandle interface {
    EvRecv(rc *SyslogEntry) ;
    GetId() (string) ;
    Init() ;
    IsInited() (bool) ;
}

func NewSyslogEntry() (SyslogEntry){
    ret := SyslogEntry{} ;

    ret.Facility = -1 ;
    ret.Severity = -1 ;

    ret.ProcId          = "-" ;
    ret.Tag             = "-" ;
    ret.AppName         = "-" ;
    ret.Hostname        = "-" ;
    ret.MsgId           = "-" ;
    ret.StructuredData  = "-" ;

    ret.inited  = syslogEntryInitedRandom ;

    return ret ;
}

type SyslogRouter struct {
    Err         error ;
    Entrys      []SyslogEntry ;
}

func (this *SyslogRouter) Init() (*SyslogRouter){
    this.Entrys = make([]SyslogEntry,0) ;
    return this ;
}

func (this *SyslogRouter) Handle(entry SyslogEntry,handle SyslogHandle) (*SyslogRouter){

    entry.Handle = handle ;

    id := handle.GetId()

    if(id == ""){
        this.Err = errorf("Id [%s] is empty.",id) ;
    }else{

        if(! handle.IsInited()){
            handle.Init() ;
            if(! handle.IsInited()){
                this.Err = errorf("Id [%s] Init Failed.",id) ;

                printf("Id [%s] Init Failed.\n",id) ;

                return this ;
            }
        }

        if(entry.inited != syslogEntryInitedRandom){
            this.Err = errorf("Id [%s] not NewSyslogEntry(%d:%d).",id,entry.inited , syslogEntryInitedRandom) ;
        }else{
            this.Entrys = append(this.Entrys,entry) ;
        }
    }

    return this ;
}

func NewSyslogRouter() (*SyslogRouter){
    ret := SyslogRouter{} ;
    return ret.Init() ;
}

func Tick(){
    for lp:=1;;lp+=1 {
        time.Sleep(30 * time.Second) ;
        // printf("Syslogd[%06d].\n",lp) ;
    }
}

func (this *TypeSyslogDaemon) SyslogRouting(rc *SyslogEntry){

    maxScore := -1 ;

    IsFind := false ;

    var entry SyslogEntry ; _ = entry ;

    for _,e := range this.router.Entrys{
        score := 0 ;

        if(e.Facility == rc.Facility){
            if(e.Severity == rc.Severity){
                score += 100 ;
            }else{
                score += 200 ;
            }
        }else if(e.Facility == -1){
            if(e.Severity == rc.Severity){
                score += 50 ;
            }else if(e.Severity == -1){
                score += 20 ;
            }
        }

        if(score > 0){
            if(e.Tag == rc.Tag){
                score += 5 ;
            }
        }

        if(score > 0){
            if(maxScore < score){
                maxScore = score ;
                entry = e ;
                IsFind = true ;
            }
        }
    }

    if(IsFind){
        entry.Handle.EvRecv(rc) ;
    }
}

func Hexdump(x any) (string){
    data := []byte(x.(string)) ;

    len := len(data) ;

    ascii := "" ;

    var iii int ;

    text := sprintf("%04x: ",0) ;

    for iii = 0 ; iii < len ; iii++ {
        c := data[iii] ;
        if(((iii % 16) == 0) && (iii != 0)){
            text = text + "  " + ascii + "\n" ;
            text = text + sprintf("%04x: ",iii) ;
            ascii = "" ;
        }
        text = text + sprintf("%02x ",c) ;
        if((c >= 0x20) && (c <= 0x7e)){
            ascii = ascii + Chr(c) ;
        }else{
            ascii = ascii + "." ;
        }
    }

    for {
        if((iii % 16) == 0){
            break ;
        }else{
            text = text + "  " ;
        }
        iii++ ;
    }
    text = text + "  " + ascii + "\n" ;
    return text ;
}

func (this *TypeSyslogDaemon) EvLine(line []rune){
    var rc SyslogEntry ;
    var err error ;

    // printf("[%s]\n",string(line)) ;

    if rc,err = ParseSyslogProtocol(line) ; (err != nil){
        printf("err[%s]\n",err) ;
    }else{
        if(false){
            printf("Pri[%d]\n",rc.Pri) ;
            printf("Facility[0x%02x]\n",rc.Facility) ;
            printf("Severity[0x%02x]\n",rc.Severity) ;
            printf("Timestamp[%s]\n",rc.Timestamp) ;
            printf("Hostname[%s]\n",rc.Hostname) ;
            printf("Tag[%s]\n",rc.Tag) ;
            printf("ProcId[%s]\n",rc.ProcId) ;
            printf("Message[%s]\n",rc.Message) ;
        }

        this.SyslogRouting(&rc) ;
    }
}

func IsNumPri(r []rune) (int,error) {
    str := string(r) ;
    return strconv.Atoi(str) ;
}

func SyslogMon2Mon(mon string) (int){
    switch(mon){
        case "Jan":{ return 1 ; }
        case "Feb":{ return 2 ; }
        case "Mar":{ return 3 ; }
        case "Apr":{ return 4 ; }
        case "May":{ return 5 ; }
        case "Jun":{ return 6 ; }
        case "Jul":{ return 7 ; }
        case "Aug":{ return 8 ; }
        case "Sep":{ return 9 ; }
        case "Oct":{ return 10 ; }
        case "Nov":{ return 11 ; }
        case "Dec":{ return 12 ; }
    }
    return 0 ;
}

// 2006-01-02T15:04:05

func SyslogDate2Str(src string)(string){
    var year int ;
    var mon int ;
    var mday int ;
    var hour int ;
    var min int ;
    var sec int ;

    if(len(src) == 15){
        mon = SyslogMon2Mon(Substr(src,0,3)) ;
        if(mon > 0){
            now := time.Now() ;
            year = now.Year()

            if(Substr(src,4,1) == " "){
                mday = Atoi(Substr(src,5,1)) ;
            }else{
                mday = Atoi(Substr(src,4,2)) ;
            }

            hour = Atoi(Substr(src,7,2)) ;
            min = Atoi(Substr(src,10,2)) ;
            sec = Atoi(Substr(src,13,2)) ;

            return sprintf("%04d/%02d/%02d %02d:%02d:%02d",year,mon,mday,hour,min,sec) ;
        }
    }else{
        if((len(src) >= 19) && (Substr(src,4,1) == "-") && (Substr(src,7,1) == "-") && (Substr(src,10,1) == "T")){
            year = Atoi(Substr(src,0,4)) ;
            mon  = Atoi(Substr(src,5,2)) ;
            mday = Atoi(Substr(src,8,2)) ;

            hour = Atoi(Substr(src,11,2)) ;
            min = Atoi(Substr(src,14,2)) ;
            sec = Atoi(Substr(src,17,2)) ;

            if(len(src) >= 20){
                xxx := Substr(src,19) ;
                var x2 string ; _ = x2 ;
                sz := len(xxx) ;
                if(sz >= 1){
                    z := Substr(xxx,-1) ;

                    if(z == "Z"){
                        x2 = Substr(xxx,0,(sz-1)) ;
                    }else{
                        x2 = xxx ;
                    }


                }


            }
        }

    }
    return "BAD" ;
}

// 2006-01-02T15:04:05

func ParseSyslogProtocolDate(rc *SyslogEntry) (error){

    // printf("Timestamp[%s]\n",rc.Timestamp) ;

    return nil ;
}

func SyslogFacility2str(facility syslog.Priority) (string){
    ret := "***" ;
    switch(facility){
        case syslog.LOG_KERN    :{ ret = "KERN" ; }
        case syslog.LOG_USER    :{ ret = "USER" ; }
        case syslog.LOG_MAIL    :{ ret = "MAIL" ; }
        case syslog.LOG_DAEMON  :{ ret = "DAEMON" ; }
        case syslog.LOG_AUTH    :{ ret = "AUTH" ; }
        case syslog.LOG_SYSLOG  :{ ret = "SYSLOG" ; }
        case syslog.LOG_LPR     :{ ret = "LPR" ; }
        case syslog.LOG_NEWS    :{ ret = "NEWS" ; }
        case syslog.LOG_UUCP    :{ ret = "UUCP" ; }
        case syslog.LOG_CRON    :{ ret = "CRON" ; }
        case syslog.LOG_AUTHPRIV:{ ret = "AUTHPRIV" ; }
        case syslog.LOG_FTP     :{ ret = "FTP" ; }
        case syslog.LOG_LOCAL0  :{ ret = "LOCAL0" ; }
        case syslog.LOG_LOCAL1  :{ ret = "LOCAL1" ; }
        case syslog.LOG_LOCAL2  :{ ret = "LOCAL2" ; }
        case syslog.LOG_LOCAL3  :{ ret = "LOCAL3" ; }
        case syslog.LOG_LOCAL4  :{ ret = "LOCAL4" ; }
        case syslog.LOG_LOCAL5  :{ ret = "LOCAL5" ; }
        case syslog.LOG_LOCAL6  :{ ret = "LOCAL6" ; }
        case syslog.LOG_LOCAL7  :{ ret = "LOCAL7" ; }
    }
    return ret ;
}

func SyslogSeverity2str(severity syslog.Priority) (string){
    ret := "***" ;
    switch(severity){
        case syslog.LOG_EMERG   :{ ret = "EMERG" ; }
        case syslog.LOG_ALERT   :{ ret = "ALERT" ; }
        case syslog.LOG_CRIT    :{ ret = "CRIT" ; }
        case syslog.LOG_ERR     :{ ret = "ERR" ; }
        case syslog.LOG_WARNING :{ ret = "WARNING" ; }
        case syslog.LOG_NOTICE  :{ ret = "NOTICE" ; }
        case syslog.LOG_INFO    :{ ret = "INFO" ; }
        case syslog.LOG_DEBUG   :{ ret = "DEBUG" ; }

    }
    return ret ;
}

func ParseSyslogProtocolPri(rc *SyslogEntry){

    facilityN := rc.Pri / 8 ; _ = facilityN ;
    priorityN := rc.Pri % 8 ; _ = priorityN ;

    switch(facilityN){
        case 0:{ rc.Facility = syslog.LOG_KERN ; }
        case 1:{ rc.Facility = syslog.LOG_USER ; }
        case 2:{ rc.Facility = syslog.LOG_MAIL ; }
        case 3:{ rc.Facility = syslog.LOG_DAEMON ; }
        case 4:{ rc.Facility = syslog.LOG_AUTH ; }
        case 5:{ rc.Facility = syslog.LOG_SYSLOG ; }
        case 6:{ rc.Facility = syslog.LOG_LPR ; }
        case 7:{ rc.Facility = syslog.LOG_NEWS ; }
        case 8:{ rc.Facility = syslog.LOG_UUCP ; }
        case 9:{ rc.Facility = syslog.LOG_CRON ; }
        case 10:{ rc.Facility = syslog.LOG_AUTHPRIV ; }
        case 11:{ rc.Facility = syslog.LOG_FTP ; }
        case 16:{ rc.Facility = syslog.LOG_LOCAL0 ; }
        case 17:{ rc.Facility = syslog.LOG_LOCAL1 ; }
        case 18:{ rc.Facility = syslog.LOG_LOCAL2 ; }
        case 19:{ rc.Facility = syslog.LOG_LOCAL3 ; }
        case 20:{ rc.Facility = syslog.LOG_LOCAL4 ; }
        case 21:{ rc.Facility = syslog.LOG_LOCAL5 ; }
        case 22:{ rc.Facility = syslog.LOG_LOCAL6 ; }
        case 23:{ rc.Facility = syslog.LOG_LOCAL7 ; }
    }

    switch(priorityN){
        case 0:{ rc.Severity = syslog.LOG_EMERG ; }
        case 1:{ rc.Severity = syslog.LOG_ALERT ; }
        case 2:{ rc.Severity = syslog.LOG_CRIT ; }
        case 3:{ rc.Severity = syslog.LOG_ERR ; }
        case 4:{ rc.Severity = syslog.LOG_WARNING ; }
        case 5:{ rc.Severity = syslog.LOG_NOTICE ; }
        case 6:{ rc.Severity = syslog.LOG_INFO ; }
        case 7:{ rc.Severity = syslog.LOG_DEBUG ; }
    }
}

func ParseSyslogProtocol(line []rune) (SyslogEntry,error){

    rc := NewSyslogEntry() ;

    var err error = nil ; _ = err ;

    var mark_st rune = Ord("<") ;
    var mark_en rune = Ord(">") ;

    token := make([]rune,0) ;

    prio := make([]rune,0) ;
    date := make([]rune,0) ;

    tag  := make([]rune,0) ;
    pid  := make([]rune,0) ;
    mes  := make([]rune,0) ;

    flagTag := false ; _ = flagTag ;
    flagHostname := false ; _ = flagHostname ;

    max := len(line) ;
    idx := 0 ;
    step := 0 ;

    var c  rune ; _ = c ;
    var c2 rune ; _ = c2 ;

    for(idx < max){
        c  = line[idx + 0] ;
        if((idx+2) < max){
            c2 = line[idx + 1] ;
        }else{
            c2 = 0 ;
        }

        if((c == 0) || (c == 0x0a)){
            idx++ ;
            continue ;
        }

        switch(step){
            case 0:{
                if(c == mark_st){
                    step = 1 ;
                    idx++ ;
                }else{
                    return rc,errorf("Broken-1") ;
                }
            }
            case 1:{
                if(c == mark_en){
                    idx++ ;
                    rc.Pri,err = IsNumPri(prio) ;
                    if(err != nil){
                        return rc,err ;
                    }else{
                        ParseSyslogProtocolPri(&rc) ;
                        step = 2 ;
                    }
                }else{
                    prio = append(prio,c) ;
                    idx++ ;
                }
            }
            case 2:{
                if(c == Ord("1") && c2 == Ord(" ")){ /* <123>1 */
                    idx += 2 ;
                    step = 40 ;
                    rc.IsRFC5424 = true ;
                }else if((c >= Ord("A")) && (c <= Ord("Z"))){ /* Oct */
                    date = append(date,c) ;
                    idx++ ;
                    step = 10 ;
                    rc.IsRFC3164 = true ;
                }else if((c >= Ord("1")) && (c <= Ord("9"))){ /* 2023-10-02T08:18:35Z */
                    date = append(date,c) ;
                    idx++ ;
                    step = 5 ;
                    rc.IsRFC3164 = true ;
                }
            }
            case 5:{
                if(c == Ord(" ")){
                    rc.Timestamp = string(date) ;
                    ParseSyslogProtocolDate(&rc) ;
                    step = 11 ;
                }else{
                    date = append(date,c) ;
                    idx++ ;
                }
            }

            case 10:{
                date = append(date,c) ;
                idx++ ;

                if(len(date) == 15){
                    // len("Oct  2 03:01:01") == 15
                    rc.Timestamp = string(date) ;
                    ParseSyslogProtocolDate(&rc) ;
                    step = 11 ;
                }
            }
            case 11:{
                if(c == Ord(" ")){
                    idx++ ;
                    step = 12 ;
                }else{
                    return rc,errorf("Broken-2") ;
                }
            }
            case 12:{
                if(c == Ord(":")){
                    step = 18 ;
                    idx++ ;
                    rc.Tag = string(tag) ;
                    tag = make([]rune,0) ;
                    flagTag = true ;
                }else if(c == Ord("[")){
                    step = 14 ;
                    idx++ ;
                    rc.Tag = string(tag) ;
                    tag = make([]rune,0) ;
                    flagTag = true ;
                }else if(c == Ord(" ")){
                    if(flagHostname != false){
                        step = 30 ;
                        idx++ ;
                        flagTag = true ;
                        mes = append(tag,c) ;
                        tag = make([]rune,0) ;
                    }else{
                        flagHostname = true ;
                        rc.Hostname = string(tag) ;
                        tag = make([]rune,0) ;
                        idx++ ;
                    }
                }else{
                    tag = append(tag,c) ;
                    idx++ ;
                }
            }
            case 14:{
                if(c == Ord("]")){
                    rc.ProcId = string(pid) ;
                    step = 17 ;
                    idx++ ;
                }else{
                    pid = append(pid,c) ;
                    idx++ ;
                }
            }
            case 17:{
                if(c == Ord(":")){
                    idx++ ;
                    step = 18 ;
                }else{
                    return rc,errorf("Broken-3[0x%02x]",c) ;
                }
            }
            case 18:{
                if(c == Ord(" ")){
                    idx++ ;
                    step = 30 ;
                }else{
                    return rc,errorf("Broken-4[0x%02x]",c) ;
                }
            }

            case 30:{
                mes = append(mes,c) ;
                idx++ ;
            }

            case 40:{
                if(c == Ord(" ")){
                    rc.Timestamp = string(token) ;
                    ParseSyslogProtocolDate(&rc) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 41:{
                if(c == Ord(" ")){
                    rc.Hostname = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 42:{
                if(c == Ord(" ")){
                    rc.AppName = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 43:{
                if(c == Ord(" ")){
                    rc.ProcId = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 44:{
                if(c == Ord(" ")){
                    rc.MsgId = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 45:{
                if(c == Ord("-")){
                    idx++ ;
                    step = 47 ;
                }else if(c == Ord("[")){
                    step = 46 ;
                }else{
                    step = 49 ;
                }
            }

            case 46:{
                if((c == Ord("]")) && (c2 != Ord("["))){
                    token = append(token,c) ;
                    rc.StructuredData = string(token) ;
                    token = make([]rune,0) ;
                    step = 47 ;
                    idx++ ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 47:{
                if(c == Ord(" ")){
                    step = 49 ;
                    idx++ ;
                }else{
                    return rc,errorf("Broken(%c)-1111",c) ;
                }
            }

            case 49:{
                mes = append(mes,c) ;
                idx++ ;
            }

        }
    }

    if(len(tag) > 0){
        rc.Message = string(tag) ;
    }else{
        rc.Message = "" ;
    }

    if(len(mes) > 0){
        rc.Message += string(mes) ;
    }

    return rc,nil ;
}

func (this *TypeSyslogDaemon) SyslogSplit(fifo string) (string,error){

    runes := []rune(fifo) ; _ = runes ;
    max := len(runes) ;
    idx := 0 ;
    offset := 0 ;
    step := 0 ;

    // printf("----[%s]\n",fifo) ;
    // printf("\n%s\n",Hexdump(fifo)) ;

    var mark_st rune = Ord("<") ;
    var mark_en rune = Ord(">") ;

    line := make([]rune,0) ;
    priStr := make([]rune,0) ;

    priLen      := -1 ; _ = priLen ;
    priLenAfter := -1 ; _ = priLenAfter ;

    headLen := -1 ; _ = headLen ;

    loop := 0 ;
    for ((idx + offset) < max){

        c := runes[idx + offset] ;
        priLenTmp := -1 ;
        if(c == mark_st){
            if((max > (idx + offset + 1)) && (mark_en == runes[idx + offset + 1])){ priLenTmp = 2 ; }else
            if((max > (idx + offset + 2)) && (mark_en == runes[idx + offset + 2])){ priLenTmp = 3 ; }else
            if((max > (idx + offset + 3)) && (mark_en == runes[idx + offset + 3])){ priLenTmp = 4 ; }else
            if((max > (idx + offset + 4)) && (mark_en == runes[idx + offset + 4])){ priLenTmp = 5 ; }

            if(priLenTmp >= 0){
                pri,err := IsNumPri(runes[(idx + offset+1):(idx + offset + priLenTmp-1)]) ;
                if(err != nil){
                    for xxx := 0;xxx < priLenTmp ; xxx++ {
                        c2 := runes[idx + offset + xxx] ;
                        line = append(line,c2) ;
                    }
                    idx += priLenTmp ;
                }else{
                    if(pri == 999){
                        headLen = priLenTmp ;
                    }else{
                        headLen = priLenTmp ;
                    }
                }
            }

            if(headLen >= 0){
                if(step == 0){
                    priLen = priLenTmp ;
                    for xxx := 0;xxx < priLenTmp ; xxx++ {
                        c2 := runes[offset + xxx] ;
                        line = append(line,c2) ;
                        priStr = append(priStr,c2) ;
                    }
                    step = 1 ;
                    idx += priLenTmp ;
                }else{
                    priLenAfter = priLenTmp ;
                    priTmpAfter := make([]rune,0) ;

                    for xxx := 0;xxx < priLenAfter ; xxx++ {
                        priTmpAfter = append(priTmpAfter,runes[offset + idx + xxx]) ;
                    }

                    step = 0 ;
                    offset += idx ;
                    idx = 0 ;
                    this.EvLine(line) ;
                    line = make([]rune,0) ;
                    priStr = make([]rune,0) ;
                    loop++ ;
                }
                headLen = -1 ;
            }else{
                idx += 1 ;
                line = append(line,c) ;
            }
        }else{
            idx += 1 ;
            line = append(line,c) ;
        }
    }

    return string(line),nil ;
}

func (this *TypeSyslogDaemon) DoTcp(tcpConn *net.TCPConn) (error){
    var szRc int ;
    var err error ;

    printf("TCP-Accept.\n") ;
    buf := make([]byte,0x1) ;
    var fifo string ;
    for{
        szRc,err = tcpConn.Read(buf) ;
        if((err == nil) && (szRc == 1)){
            fifo,err = this.SyslogSplit(fifo + string(buf)) ;
            if(err != nil){
                return err ;
            }
        }else{
            this.SyslogSplit(fifo + "<999>") ;
            if(err == io.EOF){
                printf("recv(%d)[%s]\n",szRc,err) ;
                break ;
            }else{
                printf("recv(%d)[%s]\n",szRc,err) ;
                return err ;
            }
        }
    }
    return nil ;
}

func (this *TypeSyslogDaemon) SyslogDaemonNode(addrListen string) (error){
    netDial := "unix" ; _ = netDial ;
    addrDial := "/dev/log" ; _ = addrDial ;

    var addrFrom netip.AddrPort ; _ = addrFrom ;

    if(this.router == nil){
        return errorf("router 未設定") ;
    }

    if(this.router.Err != nil){
        return this.router.Err
    }

    if(addrListen != ""){
        // printf("[%s]\n",addrListen) ;
        if ui , err := url.Parse(addrListen) ; (err != nil){
            return err ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    netDial = "unix" ;
                    addrDial = ui.Path ;
                }
                case "tcp","udp":{
                    netDial = ui.Scheme ;
                    addrDial = ui.Host ;
                }
                default:{
                    a := strings.Split(ui.Host,":") ;
                    printf("Other:Host[%s:%s]\n",a[0],a[1]) ;
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

    if(netDial == "udp"){
        go func()(error){
            udpAddr, err := net.ResolveUDPAddr(netDial,addrDial) ;
            if(err != nil){
                return err ;
            }else{
                if udpConn,err := net.ListenUDP(netDial,udpAddr) ; (err != nil){
                    return err ;
                }else{
                    // printf("UDP-Listen.\n") ;
                    buf := make([]byte,0x1000) ;
                    for {
                        szRc,addr,err := udpConn.ReadFromUDPAddrPort(buf) ; _ = szRc ; _ = addr ; _ = err ;
                        if(err != nil){
                            printf("err[%s].\n",err) ;
                        }else{
                            // printf("UDP\n%s\n",Hexdump(string(buf[:szRc]))) ;

                            this.SyslogSplit(string(buf[:szRc]) + "<999>") ;
                        }
                    }
                }
            }
            return nil ;
        }() ;
    }else if(netDial == "tcp"){
        go func() (error){
            tcpAddr, err := net.ResolveTCPAddr(netDial,addrDial) ;

            if(err != nil){
                return err ;
            }else{
                if tcpListener,err := net.ListenTCP(netDial,tcpAddr) ; (err != nil){
                    return err ;
                }else{
                    defer tcpListener.Close() ;
                    // printf("TCP-Listen.\n") ;
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
                        }()

                        select {
                            case tcpConn := <-chanTcpConn:{
                                go this.DoTcp(tcpConn) ;
                            }
                            case err := <-chanTcpErr:{
                                printf("err[%s]\n",err)
                            }
                        }

                        chanTcpConn = nil
                        chanTcpErr = nil
                    }
                }
            }
        }() ;
    }else if(netDial == "unix"){
        go func() (error){
            unixAddr, err := net.ResolveUnixAddr(netDial,addrDial) ;
            if(err != nil){
                return err ;
            }else{
                sockListen, err := net.ListenUnix("unix",unixAddr) ; _ = sockListen ;
                if(err != nil){
                    return err ;
                }else{
                    // printf("UNIX-Listen.\n") ;
                    for{
                        unixConn, err := sockListen.Accept() ;
                        if(err != nil){
                            return err ;
                        }else{
                            go func() (error){
                                buf := make([]byte,0x1000) ;
                                var szRc int ;
                                var fifo string ;
                                for {
                                    szRc,err = unixConn.Read(buf) ;
                                    if(err == nil){

                                        // printf("\nUnix[0x%x]\n%s\n",szRc,Hexdump(string(buf[:szRc]))) ;

                                        fifo,err = this.SyslogSplit(fifo + string(buf[:szRc])) ;
                                    }else{
                                        unixConn.Close() ;
                                        this.SyslogSplit(fifo + "<999>") ;
                                        if(err == io.EOF){
                                            break ;
                                        }else{
                                            printf("recv[%s]\n",err) ;
                                            return err ;
                                        }
                                    }
                                }
                                return nil ;
                            }() ;
                        }
                    }
                }
            }
        }() ;
    }
    return nil ;
    // return errorf("Assert(%s)-1302",netDial) ;
}

type TypeSyslogDaemon struct {
    router *SyslogRouter ;
} ;

func SyslogDaemon(opts ... any) (error){

    T := TypeSyslogDaemon{} ;

    addrListens := make([]string,0) ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;

        switch(t){
            case "*BerdyshFrameworkGoLang.SyslogRouter":{
                T.router = opt.(*SyslogRouter)
            }
            case "string":{
                if ui , err := url.Parse(opt.(string)) ; (err != nil){
                    return err ;
                }else{
                    switch(ui.Scheme){
                        case "tcp","udp","unix":{
                            // printf("Set[%s]\n",opt.(string)) ;
                            addrListens = append(addrListens,opt.(string)) ;
                        }
                        default:{
                            return errorf("%s",opt.(string)) ;
                        }
                    }
                }
            }
            case "[]string":{
                for _,addr := range(opt.([]string)){
                    if ui , err := url.Parse(addr) ; (err != nil){
                        return err ;
                    }else{
                        switch(ui.Scheme){
                            case "tcp","udp","unix":{
                                // printf("Set[%s]\n",addr) ;
                                addrListens = append(addrListens,addr) ;
                            }
                            default:{
                                return errorf("%s",opt.(string)) ;
                            }
                        }
                    }
                }
            }
            default:{
                return errorf("%s",t) ;
            }
        }
    }

    if(len(addrListens) == 0){
        if(true){
            addrListens = append(addrListens,"unix:///dev/log") ;
            addrListens = append(addrListens,"tcp://:514") ;
            addrListens = append(addrListens,"udp://:514") ;
        }
    }

    // for idx,addrListen := range addrListens{ printf("[%d][%s]\n",idx,addrListen) ; }

    for idx,addrListen := range addrListens{
        func(){
            if err := T.SyslogDaemonNode(addrListen) ; (err != nil){
                printf("%d:[%s]/err[%s]-1349\n",idx,addrListen,err) ;
            }
        }() ;
    }

    // printf("Ready.\n") ;

    time.Sleep(1 * time.Second) ;

    return nil ;
}

type HandlerLocal struct {
    Id  string ;
    mu sync.Mutex ;
    inited bool ;
} ;

func (this *HandlerLocal) GetId() (string){ return this.Id ; }

func (this *HandlerLocal) Init(){
    this.inited = true ;
}

func (this *HandlerLocal) IsInited() (bool){
    return this.inited ;
}

func (this *HandlerLocal) EvRecv(rc *SyslogEntry){
    if(false){
        printf("[%s]\n",this.Id) ;
        printf("\n%s\n",Hexdump(rc.Message)) ;
    }else{
        printf("%s.%s:%s\n",SyslogFacility2str(rc.Facility),SyslogSeverity2str(rc.Severity),rc.Message) ;
    }
}

func TestSyslogServer(){

    var router *SyslogRouter = NewSyslogRouter() ;
    handler := HandlerLocal{Id: "HI"} ;
    handler2 := HandlerLocal{Id: "LO"} ;
    handler3 := HandlerLocal{Id: "Other"} ;
    handler4 := HandlerLocal{Id: "Error"} ;

    entry := NewSyslogEntry() ;

    router.Handle(entry,&handler3) ;
    entry.Severity = syslog.LOG_ERR ; router.Handle(entry,&handler4) ;

    entry.Facility = syslog.LOG_LOCAL0 ; router.Handle(entry,&handler) ;
    entry.Facility = syslog.LOG_LOCAL1 ; router.Handle(entry,&handler) ;
    entry.Facility = syslog.LOG_LOCAL2 ; router.Handle(entry,&handler) ;
    entry.Facility = syslog.LOG_LOCAL3 ; router.Handle(entry,&handler) ;
    entry.Facility = syslog.LOG_LOCAL4 ; router.Handle(entry,&handler2) ;
    entry.Facility = syslog.LOG_LOCAL5 ; router.Handle(entry,&handler2) ;
    entry.Facility = syslog.LOG_LOCAL6 ; router.Handle(entry,&handler2) ;
    entry.Facility = syslog.LOG_LOCAL7 ; router.Handle(entry,&handler2) ;

    if(true){
        addrs := make([]string,0) ;
        addrs = append(addrs,"unix:///dev/log") ;
        addrs = append(addrs,"tcp://:514") ;
        addrs = append(addrs,"udp://:514") ;

        if err := SyslogDaemon(addrs,router) ; (err != nil){
            printf("err[%s]-1672.\n",err) ;
        }
    }else{
        if err := SyslogDaemon("unix:///dev/log","tcp://:514","udp://:514",router) ; (err != nil){
            printf("err[%s]-1672.\n",err) ;
        }
    }
}


















