#include <stdio.h>
#include <syslog.h>
#include <syslog-ng.h>
#include <syslog-ng/logwriter.h>

void    BySyslog(){
    openlog("ident", 0, LOG_LOCAL7) ;
    syslog(LOG_DEBUG    ,"%s","X_1") ;
    syslog(LOG_INFO     ,"%s","X_2") ;
    syslog(LOG_WARNING  ,"%s","X_3") ;
    closelog() ;
}

void    BySyslogNg(){
    guint writer_flags = 0 ;
    LogWriter   *writer ;
    LogMessage  Msg[1] ;
    const gchar *msg_string = "hoge" ;
    gboolean is_rfc5424 = 1 ;

    MsgFormatOptions parse_options ;

    LogWriterOptions opt = {0} ;
    LogQueue *queue ;

    GlobalConfig *cfg = cfg_new_snippet() ;

    writer = log_writer_new(writer_flags,cfg) ;
    log_writer_set_options(writer, NULL, &opt, NULL, NULL);

    if(is_rfc5424){
        parse_options.flags |= LP_SYSLOG_PROTOCOL ;
    }else{
        parse_options.flags &= ~LP_SYSLOG_PROTOCOL ;
    }

    msg_format_parse(&parse_options,Msg,(const guchar *)msg_string,(gsize)strlen(msg_string)) ;

    // queue = log_queue_fifo_new(1000, NULL, STATS_LEVEL0, NULL, NULL) ;
    // log_writer_set_queue(writer, queue) ;
}

int main(){
    if(1){
        BySyslog() ;
    }else{
        BySyslogNg() ;
    }
    return 0 ;
}

/*

yum install ivykis ivykis-devel

*/

