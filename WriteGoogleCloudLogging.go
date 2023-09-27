package BerdyshFrameworkGoLang

import (
    "fmt"
    "context"
    "runtime"
    "strings"
)

import  CloudLoggingV2  "cloud.google.com/go/logging/apiv2"
import  MonitoGCP       "google.golang.org/genproto/googleapis/api/monitoredres"
import  LogProtoBufAPI  "google.golang.org/genproto/googleapis/logging/v2"
import  LogProtoBufType "google.golang.org/genproto/googleapis/logging/type"
import  OptionApiGCP    "google.golang.org/api/option"

import  structpb        "google.golang.org/protobuf/types/known/structpb"

type XWriterOptionGoogleCloudLogging struct {
    LogName     string ;
    ProjectID   string ;
    ApiKey      string ;
}

func (this *XWriter) WriteGoogleCloudLogging(p []byte) (n int, err error){

    var e   error ;
    var cli *CloudLoggingV2.Client ;

    ProjectID   := this.GoogleCloudLogging.ProjectID ;
    LogName     := this.GoogleCloudLogging.LogName ;
    ApiKey      := this.GoogleCloudLogging.ApiKey ;

    formattedLogName := fmt.Sprintf("projects/%s/logs/%s",ProjectID,LogName) ;

    // fmt.Printf("!!![%s]",string(p)) ;

    ctx := context.Background() ; _ = ctx ;

    opt := OptionApiGCP.WithCredentialsJSON([]byte(ApiKey)) ; _ = opt ;

    cli , e = CloudLoggingV2.NewClient(ctx,opt) ;

    if(e == nil){
        defer cli.Close()
        req := LogProtoBufAPI.WriteLogEntriesRequest{} ;

        entry := LogProtoBufAPI.LogEntry{} ;

        entry.Severity  = LogProtoBufType.LogSeverity_DEFAULT ;

        entry.LogName   = formattedLogName ;
        entry.Resource  = &MonitoGCP.MonitoredResource{Type: "global"}

        m := make(map[string]interface{}) ;

        jsrc := NewAssoc().DecodeJson(p) ;

        kv := TypeKV{} ;
        for i := jsrc.Iterator() ; i.HasNext(&kv) ;i.Next(){
            switch(kv.K.(string)){
                case "severity":{
                    // fmt.Printf("severity[%s]\n",kv.V.Raw.(string)) ;
                    switch(kv.V.Raw.(string)){
                        case "DEBUG"    :{ entry.Severity  = LogProtoBufType.LogSeverity_DEBUG      ; }
                        case "INFO"     :{ entry.Severity  = LogProtoBufType.LogSeverity_INFO       ; }
                        case "NOTICE"   :{ entry.Severity  = LogProtoBufType.LogSeverity_NOTICE     ; }
                        case "WARNING"  :{ entry.Severity  = LogProtoBufType.LogSeverity_WARNING    ; }
                        case "ERROR"    :{ entry.Severity  = LogProtoBufType.LogSeverity_ERROR      ; }
                        case "CRITICAL" :{ entry.Severity  = LogProtoBufType.LogSeverity_CRITICAL   ; }
                        case "ALERT"    :{ entry.Severity  = LogProtoBufType.LogSeverity_ALERT      ; }
                        case "EMERGENCY":{ entry.Severity  = LogProtoBufType.LogSeverity_EMERGENCY  ; }
                    }
                }
            }
            m[kv.K.(string)] = kv.V.Raw ;
        }
        
        j , err := structpb.NewStruct(m) ;

        if(err != nil){
            fmt.Printf("err[%s]\n",err) ;
            entry.Payload   = &LogProtoBufAPI.LogEntry_TextPayload{"ERROR"} ;
        }else{
            entry.Payload   = &LogProtoBufAPI.LogEntry_JsonPayload{JsonPayload: j } ;
        }

        location := LogProtoBufAPI.LogEntrySourceLocation{} ;

        dept := 1 ;

        for {
            _, fileFull, line, ok := runtime.Caller(dept) ;

            if(ok){
                paths := strings.Split(fileFull, "/") ;
                file := paths[len(paths)-1] ;

                if((file == "WriteGoogleCloudLogging.go") || (file == "Logger.go") || IsPathGOROOT(fileFull)){
                    dept++ ; continue ;
                }

                location.Function   = "" ;
                location.File       = fileFull ;
                location.Line       = int64(line) ;

                entry.SourceLocation = &location ;
                break ;
            }else{
                break ;
            }
        }

        req.Entries = make([]*LogProtoBufAPI.LogEntry,0) ;
        req.Entries = append(req.Entries,&entry) ;

        if resp, err := cli.WriteLogEntries(ctx,&req) ; (err != nil){
            fmt.Printf("err[%s]\n",err) ;
        }else{
            _ = resp ;
            // fmt.Printf("resp.String[%s]\n",resp.String()) ;
        }
    }

    return n,nil ;
}

/*
    https://pkg.go.dev/cloud.google.com/go/logging/apiv2
    https://pkg.go.dev/cloud.google.com/go/logging/apiv2/loggingpb#WriteLogEntriesRequest.

    logging.logEntries.create

    LogName string
    Resource *monitoredres.MonitoredResource
    Labels map[string]string
    Entries []*LogEntry
    PartialSuccess bool
    DryRun bool

    https://golang.hotexamples.com/jp/examples/github.com.golang.protobuf.ptypes/-/MarshalAny/golang-marshalany-function-examples.html
    https://golang.hotexamples.com/jp/site/file?hash=0x32320d0388d7b8193cd7837519a1fb97af0aaa36169e8a0012c7aff3e87e0e82&fullName=vendor/cloud.google.com/go/logging/logadmin_test.go&project=trythings/trythings
*/

/*

type LogEntry_JsonPayload struct {
    // The log entry payload, represented as a structure that is
    // expressed as a JSON object.

    JsonPayload *structpb.Struct `protobuf:"bytes,6,opt,name=json_payload,json=jsonPayload,proto3,oneof"`
}

*/





































