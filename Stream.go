package BerdyshFrameworkGoLang

import (
    "os"
    "errors"
    "io/fs"
    "io/ioutil"
//    "log"
)

type FileHandler struct {
    path    string ;
    fp      *os.File ;
}

func Fopen(path string,mode string) (FileHandler,error) {
    var fh FileHandler ;
    var err error ;

    fh.fp,err = os.Open(path) ;

    return fh,err ;
}

func Fread(fh *FileHandler,len int) (string,error) {

    var rc int ;
    err := errors.New("ASSERT") ;
    buf := make([]byte,len) ;
    rc, err = fh.fp.Read(buf) ;

    if(err != nil){
        return "" , err ;
    }else{
        if(rc == 0){
            err = errors.New("EOF") ;
            return "" , err ;
        }else{
            return string(buf) , err ;
        }
    }
}

func Fclose(fh *FileHandler){
    fh.fp.Close() ;
}

func File_get_contents(path string) (string,error) {

    fp, err := os.Open(path) ;

    if(err != nil){
        return "" , err ;
    }else{
        buff , err := ioutil.ReadAll(fp) ;
        if(err != nil){
            return "" , err ;
        }else{
            return string(buff) , err ;
        }
    }
}

type TypeStat struct {
    Mode    fs.FileMode ;
    Uid     int ;
    Gid     int ;
    Size    int64 ;
    Atime   int64 ;
    Mtime   int64 ;
    Ctime   int64 ;
}

func Stat(path string) (TypeStat,error) {
    var ret TypeStat ;
    err := errors.New("ASSERT") ;

    info , err := os.Stat(path) ;
    if(err == nil){

        var fs_FileMode fs.FileMode = info.Mode() ;

        _ = fs_FileMode ;

        // log.Print(fs_FileMode) ;
        // log.Print(fs_FileMode.Type()) ;

        ret.Mode = fs_FileMode ;
        ret.Size = info.Size() ;
        ret.Mtime = info.ModTime().Unix() ;


    }

    return ret , err ;
}


















