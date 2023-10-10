package main

import(
    "context"
)

import X "local/BerdyshFrameworkGoLang" ;
import R "github.com/redis/go-redis/v9" ;

func main(){

    var ctx = context.Background() ;

    if(false){

        X.Printf("Start.\n") ;

        Q := make([]interface{},0) ;
        Q = append(Q,"hello") ;
        Q = append(Q,"3") ;

        X.TestRedis("tcp://:16379",Q) ;

    }else if err := X.NewRedisServer("tcp://:6379") ; (err != nil){
        X.Printf("err[%s].\n",err) ;
    }else{
        X.Printf("Ready.\n") ;

        X.Tick() ;

        cli := R.NewClient(&R.Options{Addr: "localhost:6379"}) ;
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
}













