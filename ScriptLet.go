package BerdyshFrameworkGoLang

import (
    "io"
    "time"
    "os/exec"
)

type ScriptLetLine struct {
    Fd  int ;
    S   string ;
}

type ScriptLet struct {
    Err error ;

    Stdin   io.WriteCloser ;
    Stdout  io.ReadCloser ;
    Stderr  io.ReadCloser ;

    Cmd     *exec.Cmd

    IsEOF   bool ;

    Lines   []ScriptLetLine ;

    chanStdout      chan string ;
    chanStderr      chan string ;
    chanStdoutErr   chan error ;
    chanStderrErr   chan error ;

    SecTimeout      int ;
}

func (this *ScriptLet) Error(args ... any) (error){
    return this.Err ;
}

func (this *ScriptLet) Init() (*ScriptLet){
    this.Err = nil ;

    this.Lines = make([]ScriptLetLine,0) ;

    return this ;
}

func (this *ScriptLet) Do(name string,args ... string) (*ScriptLet){
    var err error ;

    this.Cmd = exec.Command(name,args ...) ;

    if this.Stdin  , err = this.Cmd.StdinPipe()  ; (err != nil){ this.Err = err ; }
    if this.Stdout , err = this.Cmd.StdoutPipe() ; (err != nil){ this.Err = err ; }
    if this.Stderr , err = this.Cmd.StderrPipe() ; (err != nil){ this.Err = err ; }

    this.chanStdout = make(chan string) ;
    this.chanStderr = make(chan string) ;

    this.chanStdoutErr = make(chan error) ;
    this.chanStderrErr = make(chan error) ;

    if(this.Err == nil){
        if err := this.Cmd.Start() ; (err != nil){
            this.Err = err ;
        }else{
            go func(){
                buf := make([]byte,0x1000) ;
                for {
                    if szRc,err := this.Stdout.Read(buf) ; (err != nil){
                        this.chanStdoutErr <- err ;
                        break ;
                    }else{
                        this.chanStdout <- string(buf[:szRc]) ;
                    }
                }
                this.chanStdout = nil ;
                this.chanStdoutErr = nil ;
            }() ;

            go func(){
                buf := make([]byte,0x1000) ;
                for {
                    if szRc,err := this.Stderr.Read(buf) ; (err != nil){
                        this.chanStderrErr <- err ;
                        break ;
                    }else{
                        this.chanStderr <- string(buf[:szRc]) ;
                    }
                }
                this.chanStderr = nil ;
                this.chanStderrErr = nil ;
            }() ;
        }
    }

    return this ;
}

func (this *ScriptLet) Proc() (error){

    printf("[Proc]\n") ;

    chanTimeout := make(chan bool) ;

    if(this.SecTimeout > 0){
        go func(){
            time.Sleep((time.Duration)(this.SecTimeout) * time.Second) ;
            chanTimeout <- true ;
        }() ;
    }

    select {
        case err := <-this.chanStdoutErr:{
            return err ;
        }
        case err := <-this.chanStderrErr:{
            return err ;
        }
        case str := <-this.chanStdout:{
            // printf("[%s]\n",Trim(str));
            this.Lines = append(this.Lines,ScriptLetLine{Fd:1,S:str}) ;
        }
        case str := <-this.chanStderr:{
            this.Lines = append(this.Lines,ScriptLetLine{Fd:2,S:str}) ;
        }
        case isTimeout := <-chanTimeout:{
            if(isTimeout == true){
                return Errorf("TIMEOUT") ;
            }
        }
    }

    return nil ;
}

func NewScriptLet() (*ScriptLet){
    ret := ScriptLet{} ;
    return ret.Init() ;
}































