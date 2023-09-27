package BerdyshFrameworkGoLang

import (
    "fmt"
    "io"
_   "os"
    "log/slog"
    "log/syslog"
    "runtime"
    "strings"
    "context"
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
    // fmt.Printf("きた[%d][%s]\n",level,msg) ;

    this.slogLogger.Log(context.Background(),level,msg,a ...) ;
}

func (this *Logger) Logf(level slog.Level,f string,a ... any){
    var msg string ;
    if(true){
        _, fileFull, line, _ := runtime.Caller(1) ;
        paths := strings.Split(fileFull, "/") ;
        file := paths[len(paths)-1] ;
        msg = fmt.Sprintf("%04d:%s:%s",line,file,fmt.Sprintf(f,a ...)) ;
    }else{
        msg = fmt.Sprintf(f,a ...) ;
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

func (this *Logger) Debug   (msg string, a ... any){ this.Log(LevelDebug        ,msg,a ...) ; }
func (this *Logger) Info    (msg string, a ... any){ this.Log(LevelInfo         ,msg,a ...) ; }
func (this *Logger) Warn    (msg string, a ... any){ this.Log(LevelWarn         ,msg,a ...) ; }
func (this *Logger) Error   (msg string, a ... any){ this.Log(LevelError        ,msg,a ...) ; }
func (this *Logger) Notice  (msg string, a ... any){ this.Log(LevelNotice       ,msg,a ...) ; }
func (this *Logger) Critical(msg string, a ... any){ this.Log(LevelCritical     ,msg,a ...) ; }
func (this *Logger) Alert   (msg string, a ... any){ this.Log(LevelAlert        ,msg,a ...) ; }
func (this *Logger) Emerg   (msg string, a ... any){ this.Log(LevelEmerg        ,msg,a ...) ; }

func Debugf     (f string,a ... any){ DefaultLogger.Debugf      (f,a ...) ; }
func Infof      (f string,a ... any){ DefaultLogger.Infof       (f,a ...) ; }
func Warnf      (f string,a ... any){ DefaultLogger.Warnf       (f,a ...) ; }
func Errorf     (f string,a ... any){ DefaultLogger.Errorf      (f,a ...) ; }
func Noticef    (f string,a ... any){ DefaultLogger.Noticef     (f,a ...) ; }
func Criticalf  (f string,a ... any){ DefaultLogger.Criticalf   (f,a ...) ; }
func Alertf     (f string,a ... any){ DefaultLogger.Alertf      (f,a ...) ; }
func Emergf     (f string,a ... any){ DefaultLogger.Emergf      (f,a ...) ; }

func Debug   (msg string, args ...any){ DefaultLogger.Debug     (msg,args ...) ; }
func Info    (msg string, args ...any){ DefaultLogger.Info      (msg,args ...) ; }
func Warn    (msg string, args ...any){ DefaultLogger.Warn      (msg,args ...) ; }
func Error   (msg string, args ...any){ DefaultLogger.Error     (msg,args ...) ; }
func Notice  (msg string, args ...any){ DefaultLogger.Notice    (msg,args ...) ; }
func Critical(msg string, args ...any){ DefaultLogger.Critical  (msg,args ...) ; }
func Alert   (msg string, args ...any){ DefaultLogger.Alert     (msg,args ...) ; }
func Emerg   (msg string, args ...any){ DefaultLogger.Emerg     (msg,args ...) ; }

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
        case LevelDebug     : attr.Value = slog.StringValue("DEBUG") ;
        case LevelInfo      : attr.Value = slog.StringValue("INFO") ;
        case LevelNotice    : attr.Value = slog.StringValue("NOTICE") ;
        case LevelWarn      : attr.Value = slog.StringValue("WARNING") ;
        case LevelError     : attr.Value = slog.StringValue("ERROR") ;
        case LevelCritical  : attr.Value = slog.StringValue("CRITICAL") ;
        case LevelAlert     : attr.Value = slog.StringValue("ALERT") ;
        case LevelEmerg     : attr.Value = slog.StringValue("EMERGENCY") ;
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
        case LevelDebug     : attr.Value = slog.StringValue("DEBUG") ;
        case LevelInfo      : attr.Value = slog.StringValue("INFO") ;
        case LevelNotice    : attr.Value = slog.StringValue("NOTICE") ;
        case LevelWarn      : attr.Value = slog.StringValue("WARNING") ;
        case LevelError     : attr.Value = slog.StringValue("ERROR") ;
        case LevelCritical  : attr.Value = slog.StringValue("CRITICAL") ;
        case LevelAlert     : attr.Value = slog.StringValue("ALERT") ;
        case LevelEmerg     : attr.Value = slog.StringValue("EMERGENCY") ;
        }
    }
    return attr ;
}

type TypeXWriterFuncOutput  func(opts ... any) ;

type XWriter struct {
    Mode int ;
    Disable             bool ;
    FuncOutput          TypeXWriterFuncOutput ;
    SyslogFacility      syslog.Priority ;
    SyslogLevel         syslog.Priority ;
    SyslogAddr          string ;
}

func (this *XWriter) Setter(opts ... any) (*XWriter){
    var def XWriter ;

    for _,opt := range opts{
        def = opts[0].(XWriter) ; _ = opt ;
        this.Disable = def.Disable ;
        if(def.FuncOutput != nil){
            this.FuncOutput = def.FuncOutput
        }
    }
    return this ;
}

const (
    XWriterEnumNull     = iota
    XWriterEnumStdout
    XWriterEnumStderr
    XWriterEnumSyslog
    XWriterEnumHook
    XWriterEnumGoogleCloudLogging
)

type IF_XWriter interface {
    io.Writer
    Setter(opts ... any) (*XWriter)
}

func (this *XWriter) Write(p []byte) (n int, err error){

    if(this.FuncOutput != nil){
        this.FuncOutput(Trim(string(p))) ;
    }else{
        switch(this.Mode){
            case XWriterEnumStdout:{
                fmt.Printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumStderr:{
                fmt.Printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumSyslog:{
                fmt.Printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumHook:{
                fmt.Printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumGoogleCloudLogging:{
                return this.WriteGoogleCloudLogging(p) ;
            }
            default:{
                fmt.Printf("[%d]%s",this.Mode,string(p)) ;
            }
        }
    }
    return n,nil ;
}

var XWriterStdout               IF_XWriter = &XWriter{Mode: XWriterEnumStdout} ;
var XWriterStderr               IF_XWriter = &XWriter{Mode: XWriterEnumStderr} ;
var XWriterSyslog               IF_XWriter = &XWriter{Mode: XWriterEnumSyslog} ;
var XWriterHook                 IF_XWriter = &XWriter{Mode: XWriterEnumHook} ;
var XWriterGoogleCloudLogging   IF_XWriter = &XWriter{Mode: XWriterEnumGoogleCloudLogging} ;

func NewLogger(opts ... any) (*Logger){

    var ret *Logger ;
    ret = &Logger{} ;

    var jh *JSONHandler ;

    for _,opt := range opts{
        switch(fmt.Sprintf("%T",opt)){
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
            fmt.Printf("severity[%s]/msg[%s]\n",severity,message) ;
        } ;
    }

    loggerHandler := slog.NewJSONHandler(jsonWriter.Hook,&op) ;

    ret.slogLogger = slog.New(loggerHandler) ;

    return ret ;
}


























































