package BerdyshFrameworkGoLang

import (
    "strings"
    "net"
    "io"
    "log/syslog"
    "log/slog"
)

type LogWriter struct {
    syslogFacility  syslog.Priority
}

func (this *LogWriter)  SetSyslogFacility(facility syslog.Priority){
    this.syslogFacility = facility ;
}

func (this *LogWriter) Write(p []byte) (n int, err error){

    printf("あああ\n") ;

    slogJson := NewAssoc() ;
    slogJson.LoadContents("application/json",p) ;

    timestamp   := "" ; _ = timestamp ;
    severity    := "" ; _ = severity ;
    message     := "" ; _ = message ;

    if(true){
        i := slogJson.Iterator() ;
        for i.HasNext(){
            K,_ := i.Next() ;

            V := slogJson.Get(K) ;
            k := Strtolower(K) ;

            switch(k){
            case "time"     :{ timestamp    = Strval(V) ; }
            case "timestamp":{ timestamp    = Strval(V) ; }
            case "level"    :{ severity     = Strval(V) ; }
            case "severity" :{ severity     = Strval(V) ; }
            case "msg"      :{ message      = Strval(V) ; }
            case "message"  :{ message      = Strval(V) ; }
            }

        }
    }

    facility    := syslog.LOG_LOCAL7 ; _ = facility ;
    syslog_lv   := syslog.LOG_NOTICE ; _ = syslog_lv ;

    if(this.syslogFacility > 0){
        facility = this.syslogFacility ;
    }

    switch(severity){
        case "DEBUG"    :{syslog_lv   = syslog.LOG_DEBUG}
        case "INFO"     :{syslog_lv   = syslog.LOG_INFO}
        case "NOTICE"   :{syslog_lv   = syslog.LOG_NOTICE}
        case "WARN"     :{syslog_lv   = syslog.LOG_WARNING}
        case "WARNING"  :{syslog_lv   = syslog.LOG_WARNING}
        case "ERROR"    :{syslog_lv   = syslog.LOG_ERR}
        case "CRITICAL" :{syslog_lv   = syslog.LOG_CRIT}
        case "ALERT"    :{syslog_lv   = syslog.LOG_ALERT}
        case "EMERGENCY":{syslog_lv   = syslog.LOG_EMERG }
    }

    if(true){
        conn, err := net.Dial("unix","/dev/log") ;
        if(err != nil){
            printf("err[%s]\n",err) ;
        }else{
            ar := strings.Split(message,"\n") ;
            for idx,line := range ar {
                if((idx > 0) && (line == "")){ continue ; }
                packet := sprintf("<%d>Sep  4 09:09:02 : ",(facility + syslog_lv)) ;
                packet = packet + line ;
                rc , _ := conn.Write([]byte(packet)) ; _ = rc ;
            }
            conn.Close() ;
        }
    }

    return len(p) , nil ;
}

func    SlogInit() {

    // slog の出力先を syslog にセットする

    XLogWriter := &LogWriter{} ;

    XLogWriter.SetSyslogFacility(syslog.LOG_LOCAL7) ;
    var ioWriterHook io.Writer = XLogWriter ;

    logLevel := new(slog.LevelVar)
    opts := slog.HandlerOptions{
        Level: logLevel,
        AddSource: true,
        ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
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
            if(attr.Key == "source"){
                attr.Key = "sourceLocation" ;
            }
            return attr ;
        },
    }

    loggerHandler := slog.NewJSONHandler(ioWriterHook,&opts) ;
    logger := slog.New(loggerHandler) ;

    slog.SetDefault(logger) ;
    logLevel.Set(slog.LevelDebug) ;

    // slog.Debug("Debug") ;
    // slog.Info("Info") ;
    // slog.Warn("Warn") ;
    // slog.Error("Error") ;
}




































