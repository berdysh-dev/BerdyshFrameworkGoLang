#include <stdio.h>
#include <syslog.h>

int main(){

    openlog("ident", 0, LOG_LOCAL7) ;
    syslog(LOG_DEBUG    ,"%s","X_1") ;
    syslog(LOG_INFO     ,"%s","X_2") ;
    syslog(LOG_WARNING  ,"%s","X_3") ;
    closelog() ;

    return 0 ;
}
