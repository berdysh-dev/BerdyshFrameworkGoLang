<?php
    ini_set('display_errors', "On") ;

    class CL {

        function CMD($x){
            $packet = "" ;
            $packet .= sprintf("*%d\r\n",count($x)) ;
            foreach($x as $k => $v){
                $packet .= sprintf("$%d\r\n%s\r\n",strlen($v),$v) ;
            }
            echo $packet ;
        }

        function Test(){
            $this->CMD(['hello','3']) ;
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
    

