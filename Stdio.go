package BerdyshFrameworkGoLang

import (
    "fmt"
)

func Printf(f string, args ...any){ fmt.Printf(f,args ...) ; }
func Printf_(f string, args ...any){ ; }
func printf(f string, args ...any){ fmt.Printf(f,args ...) ; }
func printf_(f string, args ...any){ ; }

func Sprintf(f string, args ...any) (string) { return fmt.Sprintf(f,args ...) ; }
func sprintf(f string, args ...any) (string) { return fmt.Sprintf(f,args ...) ; }

func errorf(f string, args ...any) (error) { return fmt.Errorf(f,args ...) ; }

func    StdioTest(){

    x := sprintf("[%d]",339);

    printf("[%s]\n",x) ;
}
