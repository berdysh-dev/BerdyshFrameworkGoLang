package main

import(
    "context"
)

import X "local/BerdyshFrameworkGoLang" ;
import R "github.com/redis/go-redis/v9" ;

func main(){
    X.Printf("Cli-Start.\n") ;

/*
    var ctx = context.Background() ;
    cli := R.NewClient(&R.Options{Addr: "localhost:6379"}) ;
    if err := cli.Set(ctx, "key", "漢字", 0).Err() ; (err != nil){
        X.Printf("Set.err[%s].\n",err) ;
    }else{
        X.Printf("Set.OK[].\n") ;
        if val, err := cli.Get(ctx, "key").Result() ; (err != nil){
            if(err == R.Nil){
                X.Printf("Nil[%s].\n",err) ;
            }else{
                X.Printf("Get.err[%s].\n",err) ;
            }
        }else{
            X.Printf("お手本[%s].\n",val) ;
        }
    }
*/

    //
    // Redis Raw Command
    //
    // https://redis.io/commands/

    c := X.NewRedisClient(X.RedisClient{Addr: "tcp://127.0.0.1:6379"}) ;

    if err := c.LastErr() ; (err != nil){
        X.Printf("err[%s].\n",err) ;
    }else{
/*
        if res,err := c.Call("COMMAND") ; (err != nil){
            X.Printf("err[%s].\n",err) ;
        }else{
            X.Printf("res[%V].\n",res) ;
        }
*/

/*

        if res,err := c.Call("set","key","いろは") ; (err != nil){
            X.Printf("err[%s].\n",err) ;
        }else{
            X.Printf("res[%V].\n",res) ;
        }
        if res,err := c.Call("get","key") ; (err != nil){
            X.Printf("err[%s].\n",err) ;
        }else{
            X.Printf("res[%V].\n",res) ;
        }
*/
    }

    X.Printf("Cli-Fin.\n") ;
}

func main2(){

    var ctx = context.Background() ;

    if(false){

        X.Printf("Start.\n") ;

        Q := make([]interface{},0) ;
        Q = append(Q,"hello") ;
        Q = append(Q,"3") ;

        X.TestRedis("tcp://:6379",Q) ;

    }else if err := X.NewRedisServer("tcp://:16379") ; (err != nil){
        X.Printf("err[%s].\n",err) ;
    }else{
        X.Printf("Ready.\n") ;


        cli := R.NewClient(&R.Options{Addr: "localhost:16379"}) ;
        if err := cli.Set(ctx, "key", "value", 0).Err() ; (err != nil){
            X.Printf("Set.err[%s].\n",err) ;
        }else{
            if val, err := cli.Get(ctx, "key").Result() ; (err != nil){
                if(err == R.Nil){
                    X.Printf("Nil[%s].\n",err) ;
                }else{
                    X.Printf("Get.err[%s].\n",err) ;
                }
            }else{
                X.Printf("val[%s].\n",val) ;
            }
            if val, err := cli.Get(ctx, "key2").Result() ; (err != nil){
                if(err == R.Nil){
                    X.Printf("Nil[%s].\n",err) ;
                }else{
                    X.Printf("Get2.err[%s].\n",err) ;
                }
            }else{
                X.Printf("val[%s].\n",val) ;
            }
        }
    }
    X.Printf("Fin.\n") ;
    X.Tick() ;
}













