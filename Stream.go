package BerdyshFrameworkGoLang

import (
    "os"
    "errors"
    "io/fs"
    "io/ioutil"
_   "path/filepath"

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

type TypeDir struct {
    Path    string ;

    Files   []fs.FileInfo ;
}

type TypeDirIterator struct {
    Dir *TypeDir ;

    Idx int ;
    Max int ;
}

type TypeDirEntry struct {
    Filename    string ;
    Size        int64 ;
    Mtime       int64 ;
    Mode        int64 ;
    IsDir       bool ;
}

func Opendir(path string) (*TypeDir,error){
    var err error ;
    ret := TypeDir{} ;
    ret.Path = path ;

    if ret.Files, err = ioutil.ReadDir(path) ; (err != nil){
        return &ret,err ;
    }

    return &ret,nil ;
}

func (this *TypeDir) Close(){
    debugf("DIR CLOSE") ;
}

func (this *TypeDir) NewDirEntry() (*TypeDirEntry){
    ret := TypeDirEntry{} ;
    return &ret ;
}

func (this *TypeDir) Iterator(opts ... interface{}) (*TypeDirIterator){
    ret := TypeDirIterator{};

    ret.Dir = this ;
    ret.Idx = 0 ;
    ret.Max = len(ret.Dir.Files) ;

    return &ret ;
}

func (this *TypeDirIterator) HasNext(opts ... any) bool{
    if(this.Idx < this.Max){
        return true ;
    }else{
        return false ;
    }
}

func (this *TypeDirIterator) Next() (any, error){
    this.Idx += 1 ;
    return nil,nil ;
}

func (this *TypeDirIterator) CurrentDirEntry() (TypeDirEntry){
    ret := TypeDirEntry{} ;

    var x fs.FileInfo ; _ = x ;
    x = this.Dir.Files[this.Idx] ;

    ret.Filename    = x.Name() ;
    ret.IsDir       = x.IsDir() ;
    ret.Size        = x.Size() ;
    ret.Mode        = (int64)(x.Mode()) ;
    ret.Mtime       = x.ModTime().Unix() ;

    return ret ;
}















