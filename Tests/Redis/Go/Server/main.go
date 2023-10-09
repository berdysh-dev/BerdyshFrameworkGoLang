package main

import(
    "time"
    "github.com/redis-go/redcon"
)

import X "local/BerdyshFrameworkGoLang" ;
import R "github.com/redis-go/redis" ;
         "github.com/redis-go/redcon"

func main(){
    X.Printf("Start.\n") ;

    go func(addr string){

        r := &R.Redis{} ;

        r.KeyExpirer().Start(100*time.Millisecond, 20, 25) ;

        redcon.ListenAndServe(
            addr,
            func(conn redcon.Conn, cmd redcon.Command) {
                r.HandlerFn()(r.NewClient(conn), cmd)
            },
            func(conn redcon.Conn) bool {
                return r.AcceptFn()(r.NewClient(conn))
            },
            func(conn redcon.Conn, err error) {
                r.OnCloseFn()(r.NewClient(conn), err)
            },
        ) ;

    }(":6379") ;

    X.Printf("Fin.\n") ;
    X.Tick();
}













