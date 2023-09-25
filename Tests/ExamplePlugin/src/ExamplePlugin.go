package ExamplePlugin

import (
    "plugin"
)

import X "local/BerdyshFrameworkGoLang"

func    Entry() {
    var err error ;
    var def *X.TypePlugin ;
    var pFunc X.TypeFuncPlugin ; _ = pFunc ;

    X.Debugf("Plugin.\n") ;

    dh, err := plugin.Open("./mods/plugin.so") ; _ = dh ;

    if(err != nil){
        X.Debugf("err[%s]\n",err) ;
    }else{
        ptr, err := dh.Lookup("DefB") ; _ = ptr ;
        if(err != nil){
            X.Debugf("err[%s]\n",err) ;
        }else{
            X.Debugf("OK[%T]\n",ptr) ;

            def = ptr.(*X.TypePlugin) ;
            X.Debugf("Name[%s]\n",def.Name) ;
            X.Debugf("Entry[%T]\n",def.Entry) ;

            rcEnt := def.Entry(1,2,3) ;

            X.Debugf("rcEnt[%T][%s]\n",rcEnt,rcEnt) ;

        }
    }
}















