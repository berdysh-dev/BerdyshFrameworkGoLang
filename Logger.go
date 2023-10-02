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

    // printf("\n%s\n",Hexdump(line)) ;

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

type SyslogHandle interface {
    EvRecv(facility syslog.Priority,level syslog.Priority,date string,mess string) ;
    GetId() (string) ;
}

type SyslogEntry struct {
    Facility        syslog.Priority ;
    Level           syslog.Priority ;
    Handle          SyslogHandle ;
}


type SyslogRouter struct {
    Err         error ;
    Entrys      map[string]SyslogEntry ;
}

func (this *SyslogRouter) Init() (*SyslogRouter){

    this.Entrys = make(map[string]SyslogEntry) ;

    return this ;
}

func (this *SyslogRouter) Handle(entry SyslogEntry,handle SyslogHandle) (*SyslogRouter){

    entry.Handle = handle ;

    id := handle.GetId()

    if(id == ""){
        this.Err = errorf("Id [%s] is empty.",id) ;
    }else{
        if _, ok := this.Entrys[id]; ok {
            this.Err = errorf("Id [%s] exists",id) ;
        }else{
            this.Entrys[id] = entry ;
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

func SyslogRouting(router *SyslogRouter,rc SyslogProtocol){

    maxScore := -1 ;

    IsFind := false ;

    var entry SyslogEntry ; _ = entry ;
    var last  SyslogEntry ; _ = last ;

    count := 0 ;
    for _,e := range router.Entrys{
        score := 0 ;

        if(e.Facility == rc.Facility){
            if(e.Level == rc.Priority){
                score += 1 ;
            }else{
                score += 2 ;
            }
        }

        if(score > 0){
            if(maxScore < score){
                maxScore = score ;
                entry = e ;
                IsFind = true ;
            }
        }
        count++ ;
        last = e ;
    }

    if((IsFind == false) && (count == 1) && (last.Facility == 0) && (last.Level == 0)){
        entry = last ;
        IsFind = true ;
    }

    if(IsFind){
        entry.Handle.EvRecv(rc.Facility,rc.Priority,rc.Timestamp,rc.Message) ;
    }else{
        printf("NotFound[%d].\n",count) ;
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

type SyslogProtocol struct {
    Pri int ;
    Facility    syslog.Priority ;
    Priority    syslog.Priority ;

    Timestamp   string ;
    Tag         string ;
    AppName     string ;
    Hostname    string ;
    Msgid       string ;
    Pid         int ;
    Version     int ;

    IsRFC3164   bool ;
    IsRFC5424   bool ;
    IsRFC6587   bool ;

    Message     string ;
}

func (this *TypeSyslogDaemon) EvLine(line []rune){
    var rc SyslogProtocol ;
    var err error ;
    printf("[%s]\n",string(line)) ;
    if rc,err = parseSyslogProtocol(line) ; (err != nil){
        printf("err[%s]\n",err) ;
    }else{
        printf("Pri[%d]\n",rc.Pri) ;
        printf("Timestamp[%s]\n",rc.Timestamp) ;
        printf("Tag[%s]\n",rc.Tag) ;
        if(rc.Pid != 0){ printf("Pid[%d]\n",rc.Pid) ; }
        printf("Message[%s]\n",rc.Message) ;
    }
}

func IsNumPri(r []rune) (int,error) {
    str := string(r) ;
    return strconv.Atoi(str) ;
}

func parseSyslogProtocol(line []rune) (SyslogProtocol,error){
    rc := SyslogProtocol{} ;
    var err error = nil ; _ = err ;

    var mark_st rune = 0x3C ; // <
    var mark_en rune = 0x3E ; // >

    prio := make([]rune,0) ;
    date := make([]rune,0) ;
    tag  := make([]rune,0) ;
    pid  := make([]rune,0) ;
    mes  := make([]rune,0) ;

    flagTag := false ;

    max := len(line) ;
    idx := 0 ;
    step := 0 ;

    for(idx < max){
        c := line[idx] ;
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
                        step = 2 ;
                    }
                }else{
                    prio = append(prio,c) ;
                    idx++ ;
                }
            }
            case 2:{
                if(c == Ord("1")){ /* <123>1 */
                    idx++ ;
                    step = 20 ;
                }else{
                    date = append(date,c) ;
                    idx++ ;
                    step = 10 ;
                }
            }
            case 10:{
                date = append(date,c) ;
                idx++ ;

                if(len(date) == 15){
                    // len("Oct  2 03:01:01") == 15
                    rc.Timestamp = string(date) ;
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
                    flagTag = true ;
                }else if(c == Ord("[")){
                    step = 14 ;
                    idx++ ;
                    rc.Tag = string(tag) ;
                    flagTag = true ;

                }else{
                    tag = append(tag,c) ;
                    idx++ ;
                }
            }
            case 14:{
                if(c == Ord("]")){
                    if rc.Pid,err = strconv.Atoi(string(pid)) ; (err != nil){
                        return rc,err ;
                    }else{
                        step = 17 ;
                        idx++ ;
                    }
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
            case 20:{
            }
            case 30:{
                mes = append(mes,c) ;
                idx++ ;
            }
        }
    }

    if((flagTag == false) && (len(tag)>0)){
        rc.Message = string(tag) ;
    }else{
        rc.Message = string(mes) ;
    }

    return rc,nil ;
/*

    var allMatches [][]string ;

    a := Substr(str,0,1) ; _ = a ;
    b := Substr(str,1,1) ; _ = b ;
    c := Substr(str,2,1) ; _ = c ;
    d := Substr(str,3,1) ; _ = d ;
    e := Substr(str,4,1) ; _ = e ;

    var head string ; _ = head ;
    var timestamp string ; _ = timestamp ;
    var tag string ; _ = tag ;
    var pid string ; _ = pid ;
    var mess string ; _ = mess ;

    lenDec := 0 ;

    if(a != "<"){ return ret,errorf("broken") ; }

    if(c == ">"){ lenDec = 1 ; }
    if(d == ">"){ lenDec = 2 ; }
    if(e == ">"){ lenDec = 3 ; }

    if ret.Pri,err = strconv.Atoi(Substr(str,1,lenDec)) ; (err != nil){
        return ret,err ;
    }else{
        facilityN := ret.Pri / 8 ; _ = facilityN ;
        priorityN := ret.Pri % 8 ; _ = priorityN ;

        switch(facilityN){
            case 0:{ ret.Facility = syslog.LOG_KERN ; }
            case 1:{ ret.Facility = syslog.LOG_USER ; }
            case 2:{ ret.Facility = syslog.LOG_MAIL ; }
            case 3:{ ret.Facility = syslog.LOG_DAEMON ; }
            case 4:{ ret.Facility = syslog.LOG_AUTH ; }
            case 5:{ ret.Facility = syslog.LOG_SYSLOG ; }
            case 6:{ ret.Facility = syslog.LOG_LPR ; }
            case 7:{ ret.Facility = syslog.LOG_NEWS ; }
            case 8:{ ret.Facility = syslog.LOG_UUCP ; }
            case 9:{ ret.Facility = syslog.LOG_CRON ; }
            case 10:{ ret.Facility = syslog.LOG_AUTHPRIV ; }
            case 11:{ ret.Facility = syslog.LOG_FTP ; }
            case 16:{ ret.Facility = syslog.LOG_LOCAL0 ; }
            case 17:{ ret.Facility = syslog.LOG_LOCAL1 ; }
            case 18:{ ret.Facility = syslog.LOG_LOCAL2 ; }
            case 19:{ ret.Facility = syslog.LOG_LOCAL3 ; }
            case 20:{ ret.Facility = syslog.LOG_LOCAL4 ; }
            case 21:{ ret.Facility = syslog.LOG_LOCAL5 ; }
            case 22:{ ret.Facility = syslog.LOG_LOCAL6 ; }
            case 23:{ ret.Facility = syslog.LOG_LOCAL7 ; }
        }

        switch(priorityN){
            case 0:{ ret.Priority = syslog.LOG_EMERG ; }
            case 1:{ ret.Priority = syslog.LOG_ALERT ; }
            case 2:{ ret.Priority = syslog.LOG_CRIT ; }
            case 3:{ ret.Priority = syslog.LOG_ERR ; }
            case 4:{ ret.Priority = syslog.LOG_WARNING ; }
            case 5:{ ret.Priority = syslog.LOG_NOTICE ; }
            case 6:{ ret.Priority = syslog.LOG_INFO ; }
            case 7:{ ret.Priority = syslog.LOG_DEBUG ; }
        }
    }

    if(true){
        lenPri := lenDec + 2 ;
        tmp := string([]rune(str)[lenPri:]) ;

        reg_01 := regexp.MustCompile(`^(.*\d\d:\d\d:\d\d\s*)([^\[\]\:]*)\[(\d+)\]\:\s*`)
        reg_02 := regexp.MustCompile(`^(.*\d\d:\d\d:\d\d\s*)([^\[\]\:]*)\:\s*`)
        reg_03 := regexp.MustCompile(`^(.*\d\d:\d\d:\d\d\s*)`)

        allMatches = reg_01.FindAllStringSubmatch(Trim(tmp),-1)
        if(len(allMatches) == 1){
            // for idx,x := range allMatches[0]{ printf("[%d][%s]\n",idx,x) ; }

            head        = allMatches[0][0] ;
            timestamp   = allMatches[0][1] ;
            tag         = allMatches[0][2] ;
            pid         = allMatches[0][3] ;

            // printf("A[%s]\n",head) ;
        }else{
            allMatches := reg_02.FindAllStringSubmatch(Trim(tmp),-1)
            if(len(allMatches) == 1){
                // for idx,x := range allMatches[0]{ printf("[%d][%s]\n",idx,x) ; }
                head      = allMatches[0][0] ;
                timestamp = allMatches[0][1] ;
                tag       = allMatches[0][2] ;
                // printf("B[%s]\n",head) ;
            }else{
                allMatches := reg_03.FindAllStringSubmatch(Trim(tmp),-1)
                if(len(allMatches) == 1){
                    // for idx,x := range allMatches[0]{ printf("[%d][%s]\n",idx,x) ; }

                    head      = allMatches[0][0] ;
                    timestamp = allMatches[0][1] ;
                    // printf("C[%s]\n",head) ;
                }
            }
        }

        if(timestamp != ""){
            ret.Timestamp = Trim(timestamp) ;
        }
        if(tag != ""){
            ret.Tag = Trim(tag) ;
        }
        if(pid != ""){
            ret.Pri,_ = strconv.Atoi(pid) ;
        }

        if(head != ""){
            mess = Substr(tmp,len(head)) ;
        }

        if(mess != ""){
            printf("!!!-mess[%s]\n",mess) ;

            ret.Message = Ltrim(mess) ;
        }
    }
*/
}

func (this *TypeSyslogDaemon) SyslogSplit(fifo string) (string,error){

    runes := []rune(fifo) ; _ = runes ;
    max := len(runes) ;
    idx := 0 ;
    offset := 0 ;
    step := 0 ;

    // printf("----[%s]\n",fifo) ;

    var mark_st rune = 0x3C ; // <
    var mark_en rune = 0x3E ; // >

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
        printf("[%s]\n",addrListen) ;
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
                    printf("UDP-Listen.\n") ;
                    buf := make([]byte,0x1000) ;
                    for {
                        szRc,addr,err := udpConn.ReadFromUDPAddrPort(buf) ; _ = szRc ; _ = addr ; _ = err ;
                        if(err != nil){
                            printf("err[%s].\n",err) ;
                        }else{
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
                    printf("TCP-Listen.\n") ;
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
                    printf("UNIX-Listen.\n") ;
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
    return errorf("Assert") ;
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
                if(true){
                    printf("Set[%s]\n",opt.(string)) ;
                    addrListens = append(addrListens,opt.(string)) ;
                }
            }
        }
    }

    if(len(addrListens) == 0){
        if(true){
            addrListens = append(addrListens,"unix:///dev/log") ;
        }else{
            addrListens = append(addrListens,"tcp://0.0.0.0:514") ;
            addrListens = append(addrListens,"udp://0.0.0.0:514") ;
        }
    }else{
        printf("NumListen[%d]\n",len(addrListens)) ;
    }

    for idx,addrListen := range addrListens{
        printf("[%d][%s]\n",idx,addrListen) ;
    }

    for idx,addrListen := range addrListens{
        func(){
            if err := T.SyslogDaemonNode(addrListen) ; (err != nil){
                printf("%d:[%s]/err[%s]-1202\n",idx,addrListen,err) ;
            }
        }() ;
    }

    printf("Ready.\n") ;

    time.Sleep(1 * time.Second) ;

    return nil ;
}

func SyslogServer(){

    var router *SyslogRouter = NewSyslogRouter() ;

    if err := SyslogDaemon(router,"unix:///dev/log","tcp://0.0.0.0:514","udp://0.0.0.0:514") ; (err != nil){
        printf("err[%s]-1217.\n",err) ;
    }
}


















