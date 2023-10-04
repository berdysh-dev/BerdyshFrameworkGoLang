package BerdyshFrameworkGoLang

import ()

type ScriptLet struct {
    Err error ;
}

func (this *ScriptLet) Error(args ... any) (error){
    return this.Err ;
}

func (this *ScriptLet) Init() (*ScriptLet){
    this.Err = nil ;
    return this ;
}

func (this *ScriptLet) Do(args ... any) (*ScriptLet){

    debugf("[%d]",999) ;

    return this ;
}

func NewScriptLet() (*ScriptLet){
    ret := ScriptLet{} ;
    return ret.Init() ;
}

