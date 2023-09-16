package ExampleRouter

import (
    "net/http"
)

import X "local/BerdyshFrameworkGoLang"

type HandlerA struct { }
func (h *HandlerA) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("A") ; }

type HandlerB struct { }
func (h *HandlerB) ServeHTTP(w http.ResponseWriter, r *http.Request) { X.Debugf("B") ; }

func    Entry() {

    X.Debugf("起動開始") ;

    router := X.NewRouter().StrictSlash(true).StrictSlash(false) ;

    router.Handle("/",new(HandlerA)).Methods("POST","GET").Methods("DELETE") ;
    router.Handle("/",new(HandlerB)) ;
    router.Handle("/",new(HandlerA)).Methods("HOHO") ;

    http.ListenAndServe(":9005",router) ;
}
