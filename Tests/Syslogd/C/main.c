#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#if 0
#include <syslog-ng.h>
#include <syslog-ng/logwriter.h>
#endif

void    ByUnix(){
    struct sockaddr_un sa = {0} ;
    int fd ;

    puts("unix") ;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
        puts("err-socket") ;
    }else{
        sa.sun_family = AF_UNIX ;
        strcpy(sa.sun_path, "/dev/log") ;
        if(connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_un)) < 0){
            printf("err-connect[%d][%s]\n",errno,strerror(errno)) ;

        }else{
            puts("ok-connect") ;
        }
    }
}

void    BySyslog(){
    openlog("ident", 0, LOG_LOCAL2) ;
    syslog(LOG_DEBUG    ,"%s","X_1") ;
    syslog(LOG_INFO     ,"%s","X_2") ;
    syslog(LOG_WARNING  ,"%s","X_3") ;
    closelog() ;
}

#if 0
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
#endif

int main(){
//  BySyslog() ;
    ByUnix() ;
    return 0 ;
}

/*

yum install ivykis ivykis-devel

*/

