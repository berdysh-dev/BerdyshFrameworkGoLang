<?php
    ini_set('display_errors', "On") ;

    class CL {

        function Connect($addr){
            $errno = $errstr = '' ;
            $this->SOCK = stream_socket_client($addr, $errno, $errstr, 30) ;
        }

        function Decode($A){
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

            $A = fread($this->SOCK,0x1000) ;

            
            $this->Decode($A) ;
        }

        function Test(){
            $this->Connect('tcp://127.0.0.1:16379') ;
            $this->Cmd(['hello','3']) ;
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
    

