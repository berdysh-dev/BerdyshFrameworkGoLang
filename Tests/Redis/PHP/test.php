<?php
    ini_set('display_errors', "On") ;

    class CL {

        function Connect($addr){
            $errno = $errstr = '' ;
            $this->SOCK = stream_socket_client($addr, $errno, $errstr, 30) ;
        }

        function Decode($A){
            echo $A . "\n" ;
        }

        function Cmd($x){
            $Q = "" ;
            $Q .= sprintf("*%d\r\n",count($x)) ;
            foreach($x as $k => $v){
                $Q .= sprintf("$%d\r\n%s\r\n",strlen($v),$v) ;
            }

            printf("[%s]\n",$Q) ;

            $rc = fwrite($this->SOCK,$Q) ;
            printf("rc[%d]\n",$rc) ;

            for(;;){
                $A = fread($this->SOCK,0x1000) ;
                printf("[%s]\n",$A) ;
            }

            // $this->Decode($A) ;
        }

        function Test(){
            $this->Connect('tcp://127.0.0.1:6379') ;

            if(0){
                $this->Cmd(['HELP','CLIENT']) ;
            }else{
//              $this->Cmd(['HELLO','3']) ;
//              $this->Cmd(['CLIENT','SETINFO','LIB-NAME','go-redis(,go1.21.0)']) ;
                if(0){
                    $this->Cmd(['SET','HOHO','123']) ;
                }else{
                    $this->Cmd(['GET','HOHO']) ;
                }
            }
        }
    }

    if(1){
        if($ctx = new CL()){
            $ctx->Test() ;
        }
    }

    if(0){
        $redis = new Redis() ;
        if(0){ $redis->ping() ; }
        if(1){ $redis->set('KEY','VAL') ; }
        if(0){ $redis->get('KEY') ; }
    }
    

