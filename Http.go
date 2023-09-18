package BerdyshFrameworkGoLang

import (
_   "fmt"
_   "io"
_   "strconv"
    "strings"
_   "net/http"
)

type TypeContentTypeParser struct {
    contentTypeFull string
    contentType     string
    contentTypeMime string
}

func ContentTypeParser(contentTypePostFull string) (TypeContentTypeParser,error){
    this := TypeContentTypeParser{} ;


    this.contentTypeFull = contentTypePostFull ;

    ar := strings.Split(contentTypePostFull,";")
    if(len(ar) >= 1){ this.contentType      = strings.TrimSpace(ar[0]) ; }
    if(len(ar) >= 2){ this.contentTypeMime  = strings.TrimSpace(ar[1]) ; }

    return this,nil ;
}


