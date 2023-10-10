package BerdyshFrameworkGoLang

import (
    "io"
    "os"
    "log"
    "log/slog"
    "log/syslog"
    "net"
    "net/url"
    "net/netip"
    "crypto/tls"
    "runtime"
    "bufio"
    "strconv"
    "strings"
    "context"
    "go.uber.org/zap"
    "time"
    "errors"
    "sync"
    "bytes"
_   "regexp"
_   "reflect"

)

type Level int ;

const (
    LevelDebug      slog.Level = slog.LevelDebug
    LevelInfo       slog.Level = slog.LevelInfo
    LevelWarn       slog.Level = slog.LevelWarn
    LevelError      slog.Level = slog.LevelError
    LevelNotice     slog.Level = 2
    LevelCritical   slog.Level = 12
    LevelAlert      slog.Level = 16
    LevelEmerg      slog.Level = 20
)

const (
    DEBUG       = "DEBUG"
    INFO        = "INFO"
    NOTICE      = "NOTICE"
    WARNING     = "WARNING"
    ERROR       = "ERROR"
    CRITICAL    = "CRITICAL"
    ALERT       = "ALERT"
    EMERGENCY   = "EMERGENCY"
)

const (
    LOG_KERN        = syslog.LOG_KERN
    LOG_USER        = syslog.LOG_USER
    LOG_MAIL        = syslog.LOG_MAIL
    LOG_DAEMON      = syslog.LOG_DAEMON
    LOG_AUTH        = syslog.LOG_AUTH
    LOG_SYSLOG      = syslog.LOG_SYSLOG
    LOG_LPR         = syslog.LOG_LPR
    LOG_NEWS        = syslog.LOG_NEWS
    LOG_UUCP        = syslog.LOG_UUCP
    LOG_CRON        = syslog.LOG_CRON
    LOG_AUTHPRIV    = syslog.LOG_AUTHPRIV
    LOG_FTP         = syslog.LOG_FTP
    LOG_LOCAL0      = syslog.LOG_LOCAL0
    LOG_LOCAL1      = syslog.LOG_LOCAL1
    LOG_LOCAL2      = syslog.LOG_LOCAL2
    LOG_LOCAL3      = syslog.LOG_LOCAL3
    LOG_LOCAL4      = syslog.LOG_LOCAL4
    LOG_LOCAL5      = syslog.LOG_LOCAL5
    LOG_LOCAL6      = syslog.LOG_LOCAL6
    LOG_LOCAL7      = syslog.LOG_LOCAL7

    LOG_EMERG       = syslog.LOG_EMERG
    LOG_ALERT       = syslog.LOG_ALERT
    LOG_CRIT        = syslog.LOG_CRIT
    LOG_ERR         = syslog.LOG_ERR
    LOG_WARNING     = syslog.LOG_WARNING
    LOG_NOTICE      = syslog.LOG_NOTICE
    LOG_INFO        = syslog.LOG_INFO
    LOG_DEBUG       = syslog.LOG_DEBUG
) ;

const (
    hostname            = "hostname"
    client              = "client"
    tls_peer            = "tls_peer"
    timestamp           = "timestamp"
    msg_id              = "msg_id"
    facility            = "facility"
    version             = "version"
    proc_id             = "proc_id"
    message             = "message"
    priority            = "priority"
    severity            = "severity"
    app_name            = "app_name"
    structured_data     = "structured_data"
    tag                 = "tag"
    content             = "content"
) ;

type ParserError struct {
    ErrorString string ;
}

func (err *ParserError) Error() string {
    return err.ErrorString ;
}

type XFacility struct {
    Value int ;
}

type XSeverity struct {
    Value int ;
}

type XPriority struct {
    P int ;
    F XFacility ;
    S XSeverity ;
}

const (
    PRI_PART_START = '<'
    PRI_PART_END   = '>'
    NO_VERSION = -1
)

const (
    CR  =   0x0D
    LF  =   0x0A
)

var (
    ErrSuccess      = &ParserError{"ErrSuccess"}
    ErrContinue     = &ParserError{"ErrContinue"}
    ErrNotEnough    = &ParserError{"ErrNotEnough"}
    ErrEagain       = &ParserError{"ErrEagain"}

    ErrEOL     = &ParserError{"End of log line"}
    ErrNoSpace = &ParserError{"No space found"}

    ErrPriorityNoStart  = &ParserError{"No start char found for priority"}
    ErrPriorityEmpty    = &ParserError{"Priority field empty"}
    ErrPriorityNoEnd    = &ParserError{"No end char found for priority"}
    ErrPriorityTooShort = &ParserError{"Priority field too short"}
    ErrPriorityTooLong  = &ParserError{"Priority field too long"}
    ErrPriorityNonDigit = &ParserError{"Non digit found in priority"}

    ErrVersionNotFound = &ParserError{"Can not find version"}

    ErrTimestampUnknownFormat = &ParserError{"Timestamp format unknown"}

    ErrHostnameTooShort = &ParserError{"Hostname field too short"}
)

type TlsPeerNameFunc func(tlsConn *tls.Conn) (tlsPeer string, ok bool) ;

type TimeoutCloser interface {
    Close() error ;
    SetReadDeadline(t time.Time) error ;
}

type ScanCloser struct {
    *bufio.Scanner ;
    closer TimeoutCloser ;
}

type DatagramMessage struct {
    message []byte ;
    client  string ;
}

type Handler interface {
    Handle(LogParts, int64, error) ;
}

type Server struct {

    listeners           []net.Listener
    connections         []net.PacketConn

    handler             Handler ;

    lastError   error ;
    readTimeoutMilliseconds int64 ;

    format      Format ;

    wait        sync.WaitGroup ;
    doneTcp     chan bool ;

    tlsPeerNameFunc         TlsPeerNameFunc ;
    datagramPool            sync.Pool ;
    datagramChannelSize     int ;
    datagramChannel         chan DatagramMessage ;
} ;

type LogParts map[string]interface{} ;
type LogPartsChannel chan LogParts ;

type ISyslogHandler interface {
    Handle(LogParts, int64, error) ;
}

type ChannelHandler struct {
    channel LogPartsChannel ;
} ;

func defaultTlsPeerName(tlsConn *tls.Conn) (tlsPeer string, ok bool) {
    state := tlsConn.ConnectionState() ;
    if len(state.PeerCertificates) <= 0 {
        return "", false ;
    }else{
        cn := state.PeerCertificates[0].Subject.CommonName ;
        return cn, true ;
    }
}

func (h *ChannelHandler) SetChannel(channel LogPartsChannel) {
    h.channel = channel ;
}

func NewChannelHandler(channel LogPartsChannel) *ChannelHandler {
    handler := new(ChannelHandler) ;
    handler.SetChannel(channel) ;
    return handler ;
}

type TypeRFC3164 struct {} ;
type TypeRFC5424 struct {} ;
type TypeRFC6587 struct {} ;
type TypeAutomatic struct {} ;

var (
    RFC3164   = &TypeRFC3164{}
    RFC5424   = &TypeRFC5424{}
    RFC6587   = &TypeRFC6587{}
    Automatic = &TypeAutomatic{}
)

const (
    detectedUnknown = iota
    detectedRFC3164 = iota
    detectedRFC5424 = iota
    detectedRFC6587 = iota
)

func detect(data []byte) int {
    if i := bytes.IndexByte(data, ' '); i > 0 {
        pLength := data[0:i] ;
        if _, err := strconv.Atoi(string(pLength)); err == nil {
            return detectedRFC6587 ;
        }
        if data[0] != '<' {
            return detectedRFC3164 ;
        }
        angle := bytes.IndexByte(data, '>')
        if (angle < 0) || (angle >= i) {
            return detectedRFC3164 ;
        }

        if (angle+2 == i) && (data[angle+1] >= '0') && (data[angle+1] <= '9') {
            return detectedRFC5424 ;
        } else {
            return detectedRFC3164 ;
        }
    }
    return detectedRFC3164 ;
}

func (f *TypeAutomatic) GetParser(line []byte) LogParser {
    switch format := detect(line); format {
    case detectedRFC3164:
        return &parserWrapper{NewParserRFC3164(line)}
    case detectedRFC5424:
        return &parserWrapper{NewParserRFC5424(line)}
    default:
        return &parserWrapper{NewParserRFC3164(line)}
    }
}

func (f *TypeAutomatic) automaticScannerSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {

    if atEOF && len(data) == 0 {
        return 0, nil, nil ;
    }

    switch format := detect(data); format {
        case detectedRFC6587:{
            return rfc6587ScannerSplit(data, atEOF) ;
        }
        case detectedRFC3164, detectedRFC5424:{
            return bufio.ScanLines(data, atEOF) ;
        }
        default:{
            if err != nil { return 0, nil, err ; }
            return 0, nil, nil ;
        }
    }
}

func (f *TypeAutomatic) GetSplitFunc() bufio.SplitFunc {
    return f.automaticScannerSplit ;
}

const (
    datagramChannelBufferSize = 10
    datagramReadBufferSize    = 64 * 1024
)

type parserWrapper struct {
    LogParser
}

func (w *parserWrapper) Dump() LogParts {
    return LogParts(w.LogParser.Dump())
}

type header struct {
    priority  XPriority
    version   int
    timestamp time.Time
    hostname  string
    appName   string
    procId    string
    msgId     string
}

type rfc3164message struct {
    tag     string
    content string
}

type ParserRFC3164 struct {
    buff     []byte
    cursor   int
    l        int
    priority XPriority
    version  int
    header   header
    message  rfc3164message
    location *time.Location
    skipTag  bool
}

type ParserRFC5424 struct {
    buff            []byte
    cursor          int
    l               int
    header          header
    structuredData  string
    message         string
}

func NewParserRFC3164(buff []byte) *ParserRFC3164 {
    ret := ParserRFC3164{} ;

    ret.buff        = buff ;
    ret.cursor      = 0 ;
    ret.l           = len(buff) ;
    ret.location    = time.UTC ;

    return &ret ;
}

func NewParserRFC5424(buff []byte) *ParserRFC5424 {
    printf("NewParserRFC5424[%s].\n",(string)(buff));
    return &ParserRFC5424{
        buff:   buff,
        cursor: 0,
        l:      len(buff),
    }
}

func (this *TypeRFC5424) GetParser(line []byte) LogParser{
    return &parserWrapper{NewParserRFC5424(line)} ;
}

func (this *TypeRFC5424) GetSplitFunc() bufio.SplitFunc{
    return nil ;
}

func (p* ParserRFC3164) Dump() LogParts {

    ret := LogParts{
        timestamp: p.header.timestamp,
        hostname:  p.header.hostname,
        tag:       p.message.tag,
        content:   p.message.content,
        priority:  p.priority.P,
        facility:  p.priority.F.Value,
        severity:  p.priority.S.Value,
    }

    return ret ;
}

func (this *ParserRFC3164) Location(location *time.Location) {
    printf("ParserRFC3164.Location\n") ;

    this.location = location ;
}

func (this *ParserRFC5424) Location(location *time.Location) {
    printf("ParserRFC5424.Location\n") ;
}

func newPriority(p int) XPriority {
    return XPriority{
        P: p,
        F: XFacility{Value: p / 8},
        S: XSeverity{Value: p % 8},
    }
}

func IsDigit(c byte) bool {
    return (c >= '0' && c <= '9') ;
}

func ParsePriority(buff []byte, cursor *int, l int) (XPriority, error) {
    pri := newPriority(0) ;
    if l <= 0 { return pri, ErrPriorityEmpty ; }
    if buff[*cursor] != PRI_PART_START { return pri, ErrPriorityNoStart ; }

    i := 1 ;
    priDigit := 0 ;

    for i < l {
        if i >= 5 { return pri, ErrPriorityTooLong ; }
        c := buff[i] ;
        if (c == PRI_PART_END) {
            if i == 1 { return pri, ErrPriorityTooShort ; }
            *cursor = i + 1 ;
            return newPriority(priDigit), nil ;
        }

        if(IsDigit(c)){
            v, e := strconv.Atoi(string(c)) ;
            if e != nil { return pri, e ; }
            priDigit = (priDigit * 10) + v ;
        } else {
            return pri, ErrPriorityNonDigit ;
        }

        i++ ;
    }

    return pri, ErrPriorityNoEnd ;
}

func (p *ParserRFC3164) parsePriority() (XPriority, error) {
    return ParsePriority(p.buff, &p.cursor, p.l) ;
}

func (p *ParserRFC3164) parseContent() (string, error) {
    if(p.cursor > p.l){
        return "", ErrEOL ;
    }else{
        content := bytes.Trim(p.buff[p.cursor:p.l], " ") ;
        p.cursor += len(content) ;
        return string(content), ErrEOL ;
    }
}

func (p *ParserRFC3164) parseHeader() (header, error) {
    hdr := header{} ;

    if ts, err := p.parseTimestamp() ; (err != nil){
        return hdr, err ;
    }else{
        if hostname, err := p.parseHostname() ; (err != nil){
            return hdr, err ;
        }else{
            hdr.timestamp = ts ;
            hdr.hostname = hostname ;
            return hdr, nil ;
        }
    }
}

func (p *ParserRFC3164) parsemessage() (rfc3164message, error) {
    msg := rfc3164message{} ;

    if !p.skipTag {
        if tag, err := p.parseTag() ; (err != nil) {
            return msg, err ;
        }else{
            msg.tag = tag ;
        }
    }

    if content, err := p.parseContent() ; (err != ErrEOL) {
        return msg, err ;
    }else{
        msg.content = content ;
        return msg, err ;
    }
}

func fixTimestampIfNeeded(ts *time.Time) {
    now := time.Now() ;
    y := ts.Year() ;
    if ts.Year() == 0 { y = now.Year() ; }
    newTs := time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(), ts.Location()) ;
    *ts = newTs ;
}

func (p *ParserRFC3164) parseTimestamp() (time.Time, error) {
    var ts time.Time ;
    var err error ;
    var tsFmtLen int ;
    var sub []byte ;

    tsFmts := []string{
        time.Stamp,
        time.RFC3339,
    }
    if c := p.buff[p.cursor]; c > '0' && c < '9' {
        tsFmts = []string{
            time.RFC3339,
            time.Stamp,
        }
    }

    found := false ;
    for _, tsFmt := range tsFmts {
        tsFmtLen = len(tsFmt) ;

        if(p.cursor+tsFmtLen > p.l){ continue ; }

        sub = p.buff[p.cursor : tsFmtLen+p.cursor] ;
        ts, err = time.ParseInLocation(tsFmt, string(sub), p.location) ;
        if err == nil {
            found = true ;
            break ;
        }
    }

    if !found {
        p.cursor = len(time.Stamp) ;
        if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') { p.cursor++ ; }
        return ts, ErrTimestampUnknownFormat ;
    }

    fixTimestampIfNeeded(&ts) ;
    p.cursor += tsFmtLen ;
    if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') { p.cursor++ ; }
    return ts, nil ;
}

func ParseHostname(buff []byte, cursor *int, l int) (string, error) {
    from := *cursor ;
    if from >= l { return "", ErrHostnameTooShort ; }
    var to int ;
    for to = from; to < l; to++ {
        if buff[to] == ' ' {
            break ;
        }
    }
    hostname := buff[from:to] ;
    *cursor = to ;
    return string(hostname), nil ;
}

func (p *ParserRFC3164) parseHostname() (string, error) {
    oldcursor := p.cursor ;
    if hostname, err := ParseHostname(p.buff, &p.cursor, p.l) ; (err == nil && len(hostname) > 0 && string(hostname[len(hostname)-1]) == ":") {
        p.cursor = oldcursor - 1 ;
        myhostname, err := os.Hostname() ;
        if err == nil { return myhostname, nil ; }
        return "", nil ;
    }else{
        return hostname, err ;
    }
}

func (p *ParserRFC3164) parseTag() (string, error) {
    var b byte ;
    var endOfTag bool ;
    var bracketOpen bool ;
    var tag []byte ;
    var err error ;
    var found bool ;

    from := p.cursor ;

    for {
        if p.cursor == p.l {
            p.cursor = from ;
            return "", nil ;
        }

        b = p.buff[p.cursor] ;
        bracketOpen = (b == '[') ;
        endOfTag = (b == ':' || b == ' ') ;

        if bracketOpen {
            tag = p.buff[from:p.cursor] ;
            found = true ;
        }

        if endOfTag {
            if !found {
                tag = p.buff[from:p.cursor] ;
                found = true ;
            }

            p.cursor++ ;
            break ;
        }

        p.cursor++ ;
    }

    if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') { p.cursor++ ; }

    return string(tag), err ;
}

func (p *ParserRFC3164) Parse() error {
    // printf("ParserRFC3164.Parse\n") ;

    tcursor := p.cursor ;
    pri, err := p.parsePriority() ;
    if err != nil {
        p.priority = XPriority{13, XFacility{Value: 1}, XSeverity{Value: 5}}
        p.cursor = tcursor ;
        content, err := p.parseContent() ;
        p.header.timestamp = time.Now().Round(time.Second) ;
        if err != ErrEOL {
            return err ;
        }
        p.message = rfc3164message{content: content} ;
        return nil ;
    }

    tcursor = p.cursor ;
    hdr, err := p.parseHeader() ;
    if err == ErrTimestampUnknownFormat {
        hdr.timestamp = time.Now().Round(time.Second)
        p.skipTag = true ;
        p.cursor = tcursor ;
    } else if err != nil {
        return err ;
    } else {
        p.cursor++ ;
    }

    msg, err := p.parsemessage() ;
    if err != ErrEOL { return err ; }

    p.priority = pri ;
    p.version = NO_VERSION ;
    p.header = hdr ;
    p.message = msg ;

    return nil ;
}

func (this *ParserRFC5424) Parse() error {
    return nil ;
}

func (p *ParserRFC5424) Dump() LogParts{

    return LogParts{
        priority:           p.header.priority.P,
        facility:           p.header.priority.F.Value,
        severity:           p.header.priority.S.Value,
        version:            p.header.version,
        timestamp:          p.header.timestamp,
        hostname:           p.header.hostname,
        app_name:           p.header.appName,
        proc_id:            p.header.procId,
        msg_id:             p.header.msgId,
        structured_data:    p.structuredData,
        message:            p.message,
    }
}

func (f *TypeRFC3164) GetParser(line []byte) LogParser {
    return &parserWrapper{NewParserRFC3164(line)} ;
}

func (f *TypeRFC3164) GetSplitFunc() bufio.SplitFunc {
    return nil ;
}

func (f *TypeRFC6587) GetParser(line []byte) LogParser {
    return &parserWrapper{NewParserRFC5424(line)} ;
}


func rfc6587ScannerSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
    if(atEOF && len(data) == 0){
        return 0, nil, nil ;
    }

    if i := bytes.IndexByte(data, ' '); i > 0 {
        pLength := data[0:i] ;
        if length, err := strconv.Atoi(string(pLength)) ; (err != nil) {
            if string(data[0:1]) == "<" {
                return len(data), data, nil ;
            }else{
                return 0, nil, err ;
            }
        }else{
            end := length + i + 1 ;
            if len(data) >= end {
                return end, data[i+1 : end], nil ;
            }
        }
    }

    return 0, nil, nil ;
}

func (f *TypeRFC6587) GetSplitFunc() bufio.SplitFunc {
    return rfc6587ScannerSplit ;
}

type LogParser interface {
    Parse() error ;
    Dump() LogParts ;
    Location(*time.Location) ;
}

type Format interface {
    GetParser([]byte) LogParser ;
    GetSplitFunc() bufio.SplitFunc ;
}

func NewServer() *Server{
    server := Server{} ;
    server.tlsPeerNameFunc = defaultTlsPeerName ;
    server.datagramChannelSize = datagramChannelBufferSize ;

    server.datagramPool = sync.Pool{} ;
    server.datagramPool.New = func() interface{} {
        return make([]byte, 65536) ;
    } ;

    return &server ;
}

func (s *Server) scan(scanCloser *ScanCloser, client string, tlsPeer string) {
loop:
    for {
        select {
        case <-s.doneTcp:
            break loop
        default:
        }

        if s.readTimeoutMilliseconds > 0 {
            scanCloser.closer.SetReadDeadline(time.Now().Add(time.Duration(s.readTimeoutMilliseconds) * time.Millisecond)) ;
        }

        if scanCloser.Scan() {
            s.parser([]byte(scanCloser.Text()), client, tlsPeer) ;
        } else {
            break loop ;
        }
    }
    scanCloser.closer.Close() ;
    s.wait.Done() ;
}

func (h *ChannelHandler) Handle(logParts LogParts, messageLength int64, err error) {
    // printf("BBB[%d].\n",messageLength) ;
    h.channel <- logParts ;
}

func (s *Server) parser(line []byte, client string, tlsPeer string) {
    parser := s.format.GetParser(line) ;
    if err := parser.Parse() ; (err != nil) {
        s.lastError = err ;
    }else{

        logParts := parser.Dump() ;
        logParts["client"] = client ;

        if logParts["hostname"] == "" && (s.format == RFC3164 || s.format == Automatic) {
            if i := strings.Index(client, ":"); i > 1 {
                logParts["hostname"] = client[:i] ;
            } else {
                logParts["hostname"] = client ;
            }
        }

        logParts["tls_peer"] = tlsPeer ;

        /// printf("AAA.\n") ;

        s.handler.Handle(logParts, int64(len(line)), err) ;
    }
}

func (s *Server) goScanConnection(connection net.Conn) {
    scanner := bufio.NewScanner(connection) ;

    if sf := s.format.GetSplitFunc(); sf != nil {
        scanner.Split(sf) ;
    }

    // printf("goScanConnection\n") ;

    var client string ;
    if remoteAddr := connection.RemoteAddr() ; (remoteAddr != nil) {
        client = remoteAddr.String() ;
    }

    tlsPeer := "" ;
    if tlsConn, ok := connection.(*tls.Conn); ok {
        if err := tlsConn.Handshake(); err != nil {
            connection.Close() ;
            return ;
        }
        if s.tlsPeerNameFunc != nil {
            var ok bool ;
            if tlsPeer, ok = s.tlsPeerNameFunc(tlsConn) ; (!ok) {
                connection.Close() ;
                return ;
            }
        }
    }

    var scanCloser *ScanCloser ;
    scanCloser = &ScanCloser{scanner, connection} ;

    s.wait.Add(1) ;
    go s.scan(scanCloser, client, tlsPeer) ;
}

func (this *Server) goAcceptConnection(listener net.Listener) {
    this.wait.Add(1)
    go func(listener net.Listener){
        loop:
            for {
                select {
                    case <-this.doneTcp:
                        break loop ;
                    default:
                }
                if connection, err := listener.Accept() ; (err != nil){
                    printf("err[%s]\n",err) ;
                    continue ;
                }else{
                    this.goScanConnection(connection) ;
                }
            }
        this.wait.Done() ;
    }(listener) ;
}

func (s *Server) goParseDatagrams() {
    s.datagramChannel = make(chan DatagramMessage, s.datagramChannelSize) ;
    s.wait.Add(1) ;
    go func() {
        defer s.wait.Done()
        for {
            select {
            case msg, ok := (<-s.datagramChannel):
                if !ok { return }

                // printf("goParseDatagrams\n") ;

                if sf := s.format.GetSplitFunc(); sf != nil {
                    if _, token, err := sf(msg.message, true); err == nil {
                        s.parser(token, msg.client, "") ;
                    }else{
                        printf("err[%s].\n",err) ;
                    }
                }else{
                    s.parser(msg.message, msg.client, "") ;
                }
                s.datagramPool.Put(msg.message[:cap(msg.message)]) ;
            }
        }
    }() ;
}

func (s *Server) goReceiveDatagrams(packetconn net.PacketConn) {
    s.wait.Add(1) ;
    go func() {
        defer s.wait.Done() ;
        for {
            // printf("Datagram\n") ;
            buf := s.datagramPool.Get().([]byte) ;
            if n, addr, err := packetconn.ReadFrom(buf) ; (err == nil) {
                for ; (n > 0) && (buf[n-1] < 32); n-- { ; }
                if (n > 0) {
                    var address string ;
                    if (addr != nil) {
                        address = addr.String() ;
                    }
                    s.datagramChannel <- DatagramMessage{buf[:n], address} ;
                }
            } else {
                if opError, ok := err.(*net.OpError) ; (ok) && !opError.Temporary() && !opError.Timeout(){
                    return ;
                }
                time.Sleep(10 * time.Millisecond) ;
            }
        }
    }() ;
}

func (this *Server) Boot() error{

    if this.format == nil {
        return errors.New("please set a valid format") ;
    }

    if this.handler == nil {
        return errors.New("please set a valid handler") ;
    }

    for _, listener := range this.listeners {
        this.goAcceptConnection(listener) ;
    }

    if len(this.connections) > 0 {
        this.goParseDatagrams() ;
    }

    for _, connection := range this.connections {
        this.goReceiveDatagrams(connection) ;
    }

    return nil ;
}

func (this *Server) GetLastError() error{
    return this.lastError ;
}

func (s *Server) Kill() error{
    for _, connection := range s.connections {
        if err := connection.Close() ; (err != nil) {
            return err ;
        }
    }

    for _, listener := range s.listeners {
        if err := listener.Close() ; (err != nil) {
            return err ;
        }
    }
    if s.doneTcp != nil {
        close(s.doneTcp) ;
    }
    if s.datagramChannel != nil {
        close(s.datagramChannel) ;
    }
    return nil ;
}

func (s *Server) ListenTCP(addr string) error{
    if tcpAddr, err := net.ResolveTCPAddr("tcp", addr) ; (err != nil) {
        return err ;
    }else{
        if listener, err := net.ListenTCP("tcp", tcpAddr) ; (err != nil) {
            return err ;
        }else{
            s.doneTcp = make(chan bool) ;
            s.listeners = append(s.listeners, listener) ;
            printf("OK:ListenTCP\n") ;
            return nil ;
        }
    }
}

func (s *Server) ListenTCPTLS(addr string, config *tls.Config) error{
    if listener, err := tls.Listen("tcp", addr, config) ; (err != nil) {
        return err ;
    }else{
        s.doneTcp = make(chan bool) ;
        s.listeners = append(s.listeners, listener) ;
        return nil ;
    }
}

func (this *Server) ListenUDP(addr string) error{

    if udpAddr, err := net.ResolveUDPAddr("udp", addr) ; (err != nil) {
        return err ;
    }else{
        if connection, err := net.ListenUDP("udp", udpAddr) ; (err != nil) {
            return err ;
        }else{
            connection.SetReadBuffer(datagramReadBufferSize) ;
            this.connections = append(this.connections,connection) ;
            printf("OK:ListenUDP\n") ;
            return nil ;
        }
    }
}

func (this *Server) ListenUnixgram(addr string) error{
    if unixAddr, err := net.ResolveUnixAddr("unixgram", addr) ; (err != nil){
        return err ;
    }else{
        if connection, err := net.ListenUnixgram("unixgram", unixAddr) ; (err != nil) {
            return err ;
        }else{
            connection.SetReadBuffer(datagramReadBufferSize)
            this.connections = append(this.connections, connection) ;
            printf("OK:ListenUnixgram\n") ;
            return nil ;
        }
    }
}

func (this *Server) SetHandler(handler Handler) (*Server){
    this.handler = handler ;
    return this ;
}

func (this *Server) SetFormat(f Format) (*Server){
    this.format = f ;
    return this ;
}

func (this *Server) SetTimeout(millseconds int64) (*Server){
    this.readTimeoutMilliseconds = millseconds ;
    return this ;
}

func (this *Server) SetTlsPeerNameFunc(tlsPeerNameFunc TlsPeerNameFunc) (*Server){
    return this ;
}

func (this *Server) Wait() (*Server){
    this.wait.Wait() ;
    return this ;
}

type Priority syslog.Priority ;
type Facility syslog.Priority ;
type Severity syslog.Priority ;

type Value struct {
}

type JSONHandler struct {
    w       io.Writer ;
    opts    *HandlerOptions ;
}

type Logger struct {
    slogLogger      *slog.Logger ;
    Jh              JSONHandler ;
} ;

type LevelVar struct {
}

type Leveler interface {
    Level() Level
}

type HandlerOptions struct {
    AddSource bool ;
    Level Leveler ;
    ReplaceAttr func(groups []string, a slog.Attr) slog.Attr ;
} ;

var DefaultLogger   *Logger = &Logger{} ;

func SetDefault(logger *Logger){
    DefaultLogger = logger ;
    if(DefaultLogger.slogLogger != nil){
        slog.SetDefault(DefaultLogger.slogLogger) ;
    }
}

func (this *Logger) Log(level slog.Level,msg string,a ... any){
    this.slogLogger.Log(context.Background(),level,msg,a ...) ;
}

func IsPathGOROOT(path string) bool{
    p2,ok := os.LookupEnv("GOROOT") ;
    if(ok){
        // printf("p2[%V]",p2) ;
        a := strings.Split(p2,      "/") ;
        b := strings.Split(path,    "/") ;
        for idx,_ := range a{
            if(a[idx] != b[idx]){
                return false ;
            }
        }
        return true ;
    }else{
        return false ;
    }
}

func (this *Logger) Logf(level slog.Level,f string,a ... any){
    var msg string ;
    mode := XWriterEnumNull ;
    if(sprintf("%T",this.Jh.w) == "*BerdyshFrameworkGoLang.XWriter"){
        mode = this.Jh.w.(*XWriter).Mode ;
    }
    if(mode == XWriterEnumGoogleCloudLogging){
        msg = sprintf(f,a ...) ;
    }else{
        dept := 1 ;
        for {
            _, fileFull, line, ok := runtime.Caller(dept) ;
            if(ok){
                paths := strings.Split(fileFull, "/") ;
                file := paths[len(paths)-1] ;
                if((file == "WriteGoogleCloudLogging.go") || (file == "Logger.go") || IsPathGOROOT(fileFull)){
                    dept++ ; continue ;
                }
                msg = sprintf("%04d:%s:%s",line,file,sprintf(f,a ...)) ;
                break ;
            }else{
                break ;
            }
        }
    }
    this.Log(level,msg) ;
}

func (this *Logger) Debugf      (f string,a ... any){ this.Logf(LevelDebug      ,f,a ...) ; }
func (this *Logger) Infof       (f string,a ... any){ this.Logf(LevelInfo       ,f,a ...) ; }
func (this *Logger) Warnf       (f string,a ... any){ this.Logf(LevelWarn       ,f,a ...) ; }
func (this *Logger) Errorf      (f string,a ... any){ this.Logf(LevelError      ,f,a ...) ; }
func (this *Logger) Noticef     (f string,a ... any){ this.Logf(LevelNotice     ,f,a ...) ; }
func (this *Logger) Criticalf   (f string,a ... any){ this.Logf(LevelCritical   ,f,a ...) ; }
func (this *Logger) Alertf      (f string,a ... any){ this.Logf(LevelAlert      ,f,a ...) ; }
func (this *Logger) Emergf      (f string,a ... any){ this.Logf(LevelEmerg      ,f,a ...) ; }

func (this *Logger) Debugf_     (f string,a ... any){ ; }
func (this *Logger) Infof_      (f string,a ... any){ ; }
func (this *Logger) Warnf_      (f string,a ... any){ ; }
func (this *Logger) Errorf_     (f string,a ... any){ ; }
func (this *Logger) Noticef_    (f string,a ... any){ ; }
func (this *Logger) Criticalf_  (f string,a ... any){ ; }
func (this *Logger) Alertf_     (f string,a ... any){ ; }
func (this *Logger) Emergf_     (f string,a ... any){ ; }

func (this *Logger) Debug       (msg string, a ... any){ this.Log(LevelDebug        ,msg,a ...) ; }
func (this *Logger) Info        (msg string, a ... any){ this.Log(LevelInfo         ,msg,a ...) ; }
func (this *Logger) Warn        (msg string, a ... any){ this.Log(LevelWarn         ,msg,a ...) ; }
func (this *Logger) Error       (msg string, a ... any){ this.Log(LevelError        ,msg,a ...) ; }
func (this *Logger) Notice      (msg string, a ... any){ this.Log(LevelNotice       ,msg,a ...) ; }
func (this *Logger) Critical    (msg string, a ... any){ this.Log(LevelCritical     ,msg,a ...) ; }
func (this *Logger) Alert       (msg string, a ... any){ this.Log(LevelAlert        ,msg,a ...) ; }
func (this *Logger) Emerg       (msg string, a ... any){ this.Log(LevelEmerg        ,msg,a ...) ; }

func (this *Logger) Debug_      (msg string, a ... any){ ; }
func (this *Logger) Info_       (msg string, a ... any){ ; }
func (this *Logger) Warn_       (msg string, a ... any){ ; }
func (this *Logger) Error_      (msg string, a ... any){ ; }
func (this *Logger) Notice_     (msg string, a ... any){ ; }
func (this *Logger) Critical_   (msg string, a ... any){ ; }
func (this *Logger) Alert_      (msg string, a ... any){ ; }
func (this *Logger) Emerg_      (msg string, a ... any){ ; }

func debugf     (f string,a ... any){ DefaultLogger.Debugf      (f,a ...) ; }
func debugf_    (f string,a ... any){  ; }

func Debugf     (f string,a ... any){ DefaultLogger.Debugf      (f,a ...) ; }
func Infof      (f string,a ... any){ DefaultLogger.Infof       (f,a ...) ; }
func Warnf      (f string,a ... any){ DefaultLogger.Warnf       (f,a ...) ; }
func ErrorfLog  (f string,a ... any){ DefaultLogger.Errorf      (f,a ...) ; }
func Noticef    (f string,a ... any){ DefaultLogger.Noticef     (f,a ...) ; }
func Criticalf  (f string,a ... any){ DefaultLogger.Criticalf   (f,a ...) ; }
func Alertf     (f string,a ... any){ DefaultLogger.Alertf      (f,a ...) ; }
func Emergf     (f string,a ... any){ DefaultLogger.Emergf      (f,a ...) ; }

func Debugf_    (f string,a ... any){ ; }
func Infof_     (f string,a ... any){ ; }
func Warnf_     (f string,a ... any){ ; }
func ErrorfLog_ (f string,a ... any){ ; }
func Noticef_   (f string,a ... any){ ; }
func Criticalf_ (f string,a ... any){ ; }
func Emergf_    (f string,a ... any){ ; }

func Debug      (msg string, args ...any){ DefaultLogger.Debug     (msg,args ...) ; }
func Info       (msg string, args ...any){ DefaultLogger.Info      (msg,args ...) ; }
func Warn       (msg string, args ...any){ DefaultLogger.Warn      (msg,args ...) ; }
func Error      (msg string, args ...any){ DefaultLogger.Error     (msg,args ...) ; }
func Notice     (msg string, args ...any){ DefaultLogger.Notice    (msg,args ...) ; }
func Critical   (msg string, args ...any){ DefaultLogger.Critical  (msg,args ...) ; }
func Alert      (msg string, args ...any){ DefaultLogger.Alert     (msg,args ...) ; }
func Emerg      (msg string, args ...any){ DefaultLogger.Emerg     (msg,args ...) ; }

func Debug_     (msg string, args ...any){ ; }
func Info_      (msg string, args ...any){ ; }
func Warn_      (msg string, args ...any){ ; }
func Error_     (msg string, args ...any){ ; }
func Notice_    (msg string, args ...any){ ; }
func Critical_  (msg string, args ...any){ ; }
func Alert_     (msg string, args ...any){ ; }
func Emerg_     (msg string, args ...any){ ; }

func NewJSONHandler(w io.Writer, opts *HandlerOptions) *JSONHandler{
    ret := JSONHandler{} ;
    ret.w = w ;
    ret.opts = opts ;
    return &ret ;
}

type    TypeFuncSLogJsonWriter  func(string,string) ;

type SLogJsonWriter struct {
    Hook        io.Writer ;
    Output      io.Writer ;
    CallBack    TypeFuncSLogJsonWriter ;
} ;

func (this *SLogJsonWriter) Write(p []byte) (n int, err error){

    var severity string ; _ = severity ;
    var message string ; _ = message ;
    var timestamp string ; _ = timestamp ;

    as := NewAssoc().DecodeJson(p) ;

    kv := TypeKV{} ;
    for i := as.Iterator() ; i.HasNext(&kv) ;i.Next(){

        switch(kv.K){
            case "timestamp":{
                timestamp = kv.V.Raw.(string) ;
            }
            case "severity":{
                severity = kv.V.Raw.(string) ;
            }
            case "message":{
                message = kv.V.Raw.(string) ;
            }
        }
    }

    if(this.Output != nil){
        return this.Output.Write(p) ;
    }else{
        if(this.CallBack != nil){
            this.CallBack(severity,message) ;
        }
    }

    return len(p) , nil ;
}

func NewSLogJsonWriter() (*SLogJsonWriter){
    ret := SLogJsonWriter{} ;
    ret.Hook  = &ret ;
    return &ret ;
}

func ReplaceAttrSlog(groups []string, attr slog.Attr) (slog.Attr){
    if(attr.Key == slog.LevelKey){
        level := attr.Value.Any().(slog.Level) ;
        switch(level){
        case LevelDebug     : attr.Value = slog.StringValue(DEBUG) ;
        case LevelInfo      : attr.Value = slog.StringValue(INFO) ;
        case LevelNotice    : attr.Value = slog.StringValue(NOTICE) ;
        case LevelWarn      : attr.Value = slog.StringValue(WARNING) ;
        case LevelError     : attr.Value = slog.StringValue(ERROR) ;
        case LevelCritical  : attr.Value = slog.StringValue(CRITICAL) ;
        case LevelAlert     : attr.Value = slog.StringValue(ALERT) ;
        case LevelEmerg     : attr.Value = slog.StringValue(EMERGENCY) ;
        }
    }
    return attr ;
}

func ReplaceAttrSlogGoogleCloudLogging(groups []string, attr slog.Attr) (slog.Attr){
    if(attr.Key == "time"){
        attr.Key = "timestamp" ;
    }
    if(attr.Key == "msg"){
        attr.Key = "message" ;
    }
    if(attr.Key == slog.LevelKey){
        attr.Key = "severity" ;
        level := attr.Value.Any().(slog.Level) ;
        switch(level){
        case LevelDebug     : attr.Value = slog.StringValue(DEBUG) ;
        case LevelInfo      : attr.Value = slog.StringValue(INFO) ;
        case LevelNotice    : attr.Value = slog.StringValue(NOTICE) ;
        case LevelWarn      : attr.Value = slog.StringValue(WARNING) ;
        case LevelError     : attr.Value = slog.StringValue(ERROR) ;
        case LevelCritical  : attr.Value = slog.StringValue(CRITICAL) ;
        case LevelAlert     : attr.Value = slog.StringValue(ALERT) ;
        case LevelEmerg     : attr.Value = slog.StringValue(EMERGENCY) ;
        }
    }
    return attr ;
}

type TypeXWriterFuncOutput  func(opts ... any) ;

type TypeXWriterFuncMiddleWareOutput    func(opts ... any)(any) ;

type XWriter struct {
    Mode int ;
    Disable             bool ;
    FuncOutput          TypeXWriterFuncOutput ;
    SyslogFacility      syslog.Priority ;
    SyslogSeverity      syslog.Priority ;
    SyslogAddr          string ;

    MiddleWareOutput    TypeXWriterFuncMiddleWareOutput ;
    MiddleWareOutputs   []TypeXWriterFuncMiddleWareOutput ;

    GoogleCloudLogging  XWriterOptionGoogleCloudLogging ;
}

func (this *XWriter) GetMode() int{
    return this.Mode ;
}

func (this *XWriter) Setter(opts ... any) (*XWriter){

    for _,opt := range opts{
        t := sprintf("%T",opt) ;
        switch(t){
            case "BerdyshFrameworkGoLang.XWriter":{
                def := opt.(XWriter) ;
                this.Disable = def.Disable ;
                if(def.FuncOutput != nil){
                    this.FuncOutput = def.FuncOutput
                }
                if(def.MiddleWareOutput != nil){
                    this.MiddleWareOutputs = append(this.MiddleWareOutputs,def.MiddleWareOutput) ;
                }

                if(def.SyslogAddr != ""){
                    this.SyslogAddr = def.SyslogAddr
                }

                this.SyslogFacility = def.SyslogFacility ;
                this.SyslogSeverity = def.SyslogSeverity ;

            }
            case "BerdyshFrameworkGoLang.XWriterOptionGoogleCloudLogging":{
                this.GoogleCloudLogging = opt.(XWriterOptionGoogleCloudLogging) ;
            }
            default:{
                printf("Unknowns[%s]\n",t) ;
            }
        }
    }
    return this ;
}

const (
    XWriterEnumNull     = iota
    XWriterEnumStdout
    XWriterEnumStderr
    XWriterEnumSyslog
    XWriterEnumStdLog
    XWriterEnumHook
    XWriterEnumGoogleCloudLogging
    XWriterEnumTest
    XWriterEnumTest2
    XWriterEnumTest3
)

type IF_XWriter interface {
    io.Writer
    Setter(opts ... any) (*XWriter)
    GetMode() int
}

func getBytes(str string) ([]byte){
    return []byte(str) ;
}

func (this *XWriter) lineSyslog(line string){

    network := "unix" ;
    addr := "/dev/log" ;

    if(this.SyslogAddr != ""){
        ui , err := url.Parse(this.SyslogAddr) ; _ = ui ;
        if(err != nil){
            printf("err-1[%s]\n",err) ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    network = "unix" ;
                    addr = ui.Path ;
                }
            }
        }
    }

    // printf("\n%s\n",Hexdump(line)) ;

    sysLog, err := syslog.Dial(network, addr,this.SyslogFacility|this.SyslogSeverity,"") ;

    if(err != nil){
        printf("err-2[%s]\n",err) ;
    }else{
        defer sysLog.Close() ;
        sysLog.Write(getBytes(line)) ;
    }
}

func (this *XWriter) WriteSub(p []byte) (n int, err error){

    lines := strings.Split(string(p),"\n") ;

    for _,line := range lines{
        if(line != ""){
            this.lineSyslog(line) ;
        }
    }

    return n,nil ;
}

func slogLevel2SyslogSeverity(level any) (syslog.Priority){

    if(sprintf("%T",level) == "string"){
        switch(level.(string)){
            case DEBUG      :{ return LOG_DEBUG ; }
            case INFO       :{ return LOG_INFO ; }
            case NOTICE     :{ return LOG_NOTICE ; }
            case WARNING    :{ return LOG_WARNING ; }
            case ERROR      :{ return LOG_ERR ; }
            case CRITICAL   :{ return LOG_CRIT ; }
            case ALERT      :{ return LOG_ALERT ; }
            case EMERGENCY  :{ return LOG_EMERG ; }
            default:{ printf("!!![%s]\n",level.(string)) ; }
        }
    }
    return 0 ;
}

func (this *XWriter) WriteSyslog(p []byte) (n int, err error){

    // printf("[%s:%d:%d][%s]-427\n",this.SyslogAddr,this.SyslogFacility,this.SyslogSeverity,Trim(string(p))) ;

    network := "unix" ;
    addr := "/dev/log" ;

    var syslogSeverity syslog.Priority = -1 ;

    if(this.SyslogAddr != ""){
        ui , err := url.Parse(this.SyslogAddr) ; _ = ui ;
        if(err != nil){
            printf("err-1[%s]\n",err) ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    network = "unix" ;
                    addr = ui.Path ;
                }
            }
        }
    }

    msg := "" ;
    as := NewAssoc().DecodeJson(p) ;
    kv := TypeKV{} ;

    countOther := 0 ;
    for i := as.Iterator() ; i.HasNext(&kv) ;i.Next(){
        switch(kv.K){
            case "time":{
                ;
            }
            case "msg":{
                msg = kv.V.Raw.(string) ;
            }
            case "level":{
                syslogSeverity = slogLevel2SyslogSeverity(kv.V.Raw) ;
            }
            default:{
                countOther += 1 ;
            }
        }
    }

    if(syslogSeverity < 0){
        return n,errorf("Severity") ;
    }else{
        sysLog, err := syslog.Dial(network, addr,this.SyslogFacility|syslogSeverity,"") ;
        if(err != nil){
            printf("err-2[%s]\n",err) ;
        }else{
            defer sysLog.Close() ;
            if((countOther > 0) || (msg == "")){
                sysLog.Write(p) ;
            }else{
                sysLog.Write(([]byte)(msg)) ;
            }
        }
    }

    return n,nil ;
}

func (this *XWriter) Write(p []byte) (n int, err error){

    if(this.FuncOutput != nil){
        this.FuncOutput(Trim(string(p))) ;
    }else{
        switch(this.Mode){
            case XWriterEnumStdout:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumStderr:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumSyslog:{
                return this.WriteSyslog(p) ;
            }
            case XWriterEnumStdLog:{
                return this.WriteSub(p) ;
            }
            case XWriterEnumHook:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumGoogleCloudLogging:{
                return this.WriteGoogleCloudLogging(p) ;
            }
            case XWriterEnumTest:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumTest2:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            case XWriterEnumTest3:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
            default:{
                printf("[%d]%s",this.Mode,string(p)) ;
            }
        }
    }
    return n,nil ;
}

var XWriterStdout               IF_XWriter = &XWriter{Mode: XWriterEnumStdout} ;
var XWriterStderr               IF_XWriter = &XWriter{Mode: XWriterEnumStderr} ;
var XWriterSyslog               IF_XWriter = &XWriter{Mode: XWriterEnumSyslog} ;
var XWriterStdLog               IF_XWriter = &XWriter{Mode: XWriterEnumStdLog} ;
var XWriterHook                 IF_XWriter = &XWriter{Mode: XWriterEnumHook} ;
var XWriterGoogleCloudLogging   IF_XWriter = &XWriter{Mode: XWriterEnumGoogleCloudLogging} ;
var XWriterTest                 IF_XWriter = &XWriter{Mode: XWriterEnumTest} ;
var XWriterTest2                IF_XWriter = &XWriter{Mode: XWriterEnumTest2} ;
var XWriterTest3                IF_XWriter = &XWriter{Mode: XWriterEnumTest3} ;

func NewLogger(opts ... any) (*Logger){

    var ret *Logger ;
    ret = &Logger{} ;

    var jh *JSONHandler ;

    for _,opt := range opts{
        switch(sprintf("%T",opt)){
            case "*BerdyshFrameworkGoLang.JSONHandler":{
                jh = opt.(*JSONHandler) ;
                ret.Jh.w = jh.w ;
                ret.Jh.opts = jh.opts ;
            }
        }
    }

    logLevel := new(slog.LevelVar) ;
    logLevel.Set(slog.LevelDebug) ;
    op := slog.HandlerOptions{ Level: logLevel }
    
    if(ret.Jh.opts.ReplaceAttr != nil){
        op.ReplaceAttr = ret.Jh.opts.ReplaceAttr ;
    }else{
        op.ReplaceAttr = ReplaceAttrSlog ;
    }

    jsonWriter := NewSLogJsonWriter() ;

    jsonWriter.Output = ret.Jh.w ;

    if(true){
        jsonWriter.CallBack = func(severity string,message string){
            printf("severity[%s]/msg[%s]\n",severity,message) ;
        } ;
    }

    loggerHandler := slog.NewJSONHandler(jsonWriter.Hook,&op) ;

    ret.slogLogger = slog.New(loggerHandler) ;

    return ret ;
}

type MySlogHandler struct {
}

func (this *MySlogHandler) Enabled(context.Context, slog.Level) bool{

    printf("Enabled.\n") ;

    return false ;
}

func (this *MySlogHandler) Handle(context.Context, slog.Record) error{
    printf("Handle.\n") ;
    return nil ;
}

func (this *MySlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler{
    printf("WithAttrs.\n") ;
    return this ;
}

func (this *MySlogHandler) WithGroup(name string) slog.Handler{
    printf("WithGroup.\n") ;
    return this ;
}

func TestSlog(){

    var handler slog.Handler = &MySlogHandler{} ;
    var oldLogger *log.Logger ;

    oldLogger = slog.NewLogLogger(handler,slog.LevelInfo) ; _ = oldLogger ;

//    logger.Debug("XXX") ;

}

func TestLogStd(){
    var oldLogger *log.Logger ; _ = oldLogger ;

    if(true){
        oldLogger = log.Default() ;
    }else{
        oldLogger = log.New(XWriterTest,"prefix" ,0) ;
    }

    w := oldLogger.Writer() ;

    if(sprintf("%T",w) == "*os.File"){
    }

    oldLogger.SetOutput(XWriterStdLog) ;
    oldLogger.SetPrefix("") ;
    oldLogger.SetFlags(0) ;

    log.Printf("XXX\n") ;

}

func TestLogZap(){
    logger, err := zap.NewDevelopment()

    if(err != nil){
        printf("err-3[%s]\n",err) ;
    }else{
        defer logger.Sync() ;
        var cfg zap.Config ;
        printf("type[%T]\n",cfg) ;
    }

}

const (
    SOCKET_LOG  = "/dev/log"
)

type syslogEntryInited  int ;

const (
    syslogEntryInitedRandom = 432271
)

type SyslogEntry struct {

    inited          syslogEntryInited ;

    Pri             int ;
    Facility        syslog.Priority ;
    Severity        syslog.Priority ;

    Date            time.Time ;

    Timestamp       string ;
    Tag             string ;
    AppName         string ;
    Hostname        string ;
    MsgId           string ;
    StructuredData  string ;
    ProcId          string ;
    Version         int ;

    IsRFC3164       bool ;
    IsRFC5424       bool ;
    IsRFC6587       bool ;

    Message         string ;

    Handle          SyslogHandle ;
}

type SyslogHandle interface {
    EvRecv(rc *SyslogEntry) ;
    GetId() (string) ;
    Init() ;
    IsInited() (bool) ;
}

func NewSyslogEntry() (SyslogEntry){
    ret := SyslogEntry{} ;

    ret.Facility = -1 ;
    ret.Severity = -1 ;

    ret.ProcId          = "-" ;
    ret.Tag             = "-" ;
    ret.AppName         = "-" ;
    ret.Hostname        = "-" ;
    ret.MsgId           = "-" ;
    ret.StructuredData  = "-" ;

    ret.inited  = syslogEntryInitedRandom ;

    return ret ;
}

type SyslogRouter struct {
    Err         error ;
    Entrys      []SyslogEntry ;
}

func (this *SyslogRouter) Init() (*SyslogRouter){
    this.Entrys = make([]SyslogEntry,0) ;
    return this ;
}

func (this *SyslogRouter) Handle(entry SyslogEntry,handle SyslogHandle) (*SyslogRouter){

    entry.Handle = handle ;

    id := handle.GetId()

    if(id == ""){
        this.Err = errorf("Id [%s] is empty.",id) ;
    }else{

        if(! handle.IsInited()){
            handle.Init() ;
            if(! handle.IsInited()){
                this.Err = errorf("Id [%s] Init Failed.",id) ;

                printf("Id [%s] Init Failed.\n",id) ;

                return this ;
            }
        }

        if(entry.inited != syslogEntryInitedRandom){
            this.Err = errorf("Id [%s] not NewSyslogEntry(%d:%d).",id,entry.inited , syslogEntryInitedRandom) ;
        }else{
            this.Entrys = append(this.Entrys,entry) ;
        }
    }

    return this ;
}

func NewSyslogRouter() (*SyslogRouter){
    ret := SyslogRouter{} ;
    return ret.Init() ;
}

func Tick(){
    for lp:=1;;lp+=1 {
        time.Sleep(30 * time.Second) ;
        // printf("Syslogd[%06d].\n",lp) ;
    }
}

func (this *TypeSyslogDaemon) SyslogRouting(rc *SyslogEntry){

    maxScore := -1 ;

    IsFind := false ;

    var entry SyslogEntry ; _ = entry ;

    for _,e := range this.router.Entrys{
        score := 0 ;

        if(e.Facility == rc.Facility){
            if(e.Severity == rc.Severity){
                score += 100 ;
            }else{
                score += 200 ;
            }
        }else if(e.Facility == -1){
            if(e.Severity == rc.Severity){
                score += 50 ;
            }else if(e.Severity == -1){
                score += 20 ;
            }
        }

        if(score > 0){
            if(e.Tag == rc.Tag){
                score += 5 ;
            }
        }

        if(score > 0){
            if(maxScore < score){
                maxScore = score ;
                entry = e ;
                IsFind = true ;
            }
        }
    }

    if(IsFind){
        entry.Handle.EvRecv(rc) ;
    }
}

func Hexdump(x any) (string){
    data := []byte(x.(string)) ;

    len := len(data) ;

    ascii := "" ;

    var iii int ;

    text := sprintf("%04x: ",0) ;

    for iii = 0 ; iii < len ; iii++ {
        c := data[iii] ;
        if(((iii % 16) == 0) && (iii != 0)){
            text = text + "  " + ascii + "\n" ;
            text = text + sprintf("%04x: ",iii) ;
            ascii = "" ;
        }
        text = text + sprintf("%02x ",c) ;
        if((c >= 0x20) && (c <= 0x7e)){
            ascii = ascii + Chr(c) ;
        }else{
            ascii = ascii + "." ;
        }
    }

    for {
        if((iii % 16) == 0){
            break ;
        }else{
            text = text + "  " ;
        }
        iii++ ;
    }
    text = text + "  " + ascii + "\n" ;
    return text ;
}

func (this *TypeSyslogDaemon) EvLine(line []rune){
    var rc SyslogEntry ;
    var err error ;

    // printf("[%s]\n",string(line)) ;

    if rc,err = ParseSyslogProtocol(line) ; (err != nil){
        printf("err[%s]\n",err) ;
    }else{
        if(false){
            printf("Pri[%d]\n",rc.Pri) ;
            printf("Facility[0x%02x]\n",rc.Facility) ;
            printf("Severity[0x%02x]\n",rc.Severity) ;
            printf("Timestamp[%s]\n",rc.Timestamp) ;
            printf("Hostname[%s]\n",rc.Hostname) ;
            printf("Tag[%s]\n",rc.Tag) ;
            printf("ProcId[%s]\n",rc.ProcId) ;
            printf("Message[%s]\n",rc.Message) ;
        }

        this.SyslogRouting(&rc) ;
    }
}

func IsNumPri(r []rune) (int,error) {
    str := string(r) ;
    return strconv.Atoi(str) ;
}

func SyslogMon2Mon(mon string) (int){
    switch(mon){
        case "Jan":{ return 1 ; }
        case "Feb":{ return 2 ; }
        case "Mar":{ return 3 ; }
        case "Apr":{ return 4 ; }
        case "May":{ return 5 ; }
        case "Jun":{ return 6 ; }
        case "Jul":{ return 7 ; }
        case "Aug":{ return 8 ; }
        case "Sep":{ return 9 ; }
        case "Oct":{ return 10 ; }
        case "Nov":{ return 11 ; }
        case "Dec":{ return 12 ; }
    }
    return 0 ;
}

// 2006-01-02T15:04:05

func SyslogDate2Str(src string)(string){
    var year int ;
    var mon int ;
    var mday int ;
    var hour int ;
    var min int ;
    var sec int ;

    if(len(src) == 15){
        mon = SyslogMon2Mon(Substr(src,0,3)) ;
        if(mon > 0){
            now := time.Now() ;
            year = now.Year()

            if(Substr(src,4,1) == " "){
                mday = Atoi(Substr(src,5,1)) ;
            }else{
                mday = Atoi(Substr(src,4,2)) ;
            }

            hour = Atoi(Substr(src,7,2)) ;
            min = Atoi(Substr(src,10,2)) ;
            sec = Atoi(Substr(src,13,2)) ;

            return sprintf("%04d/%02d/%02d %02d:%02d:%02d",year,mon,mday,hour,min,sec) ;
        }
    }else{
        if((len(src) >= 19) && (Substr(src,4,1) == "-") && (Substr(src,7,1) == "-") && (Substr(src,10,1) == "T")){
            year = Atoi(Substr(src,0,4)) ;
            mon  = Atoi(Substr(src,5,2)) ;
            mday = Atoi(Substr(src,8,2)) ;

            hour = Atoi(Substr(src,11,2)) ;
            min = Atoi(Substr(src,14,2)) ;
            sec = Atoi(Substr(src,17,2)) ;

            if(len(src) >= 20){
                xxx := Substr(src,19) ;
                var x2 string ; _ = x2 ;
                sz := len(xxx) ;
                if(sz >= 1){
                    z := Substr(xxx,-1) ;

                    if(z == "Z"){
                        x2 = Substr(xxx,0,(sz-1)) ;
                    }else{
                        x2 = xxx ;
                    }


                }


            }
        }

    }
    return "BAD" ;
}

// 2006-01-02T15:04:05

func ParseSyslogProtocolDate(rc *SyslogEntry) (error){

    // printf("Timestamp[%s]\n",rc.Timestamp) ;

    return nil ;
}

func SyslogFacility2str(facility syslog.Priority) (string){
    ret := "***" ;
    switch(facility){
        case LOG_KERN    :{ ret = "KERN" ; }
        case LOG_USER    :{ ret = "USER" ; }
        case LOG_MAIL    :{ ret = "MAIL" ; }
        case LOG_DAEMON  :{ ret = "DAEMON" ; }
        case LOG_AUTH    :{ ret = "AUTH" ; }
        case LOG_SYSLOG  :{ ret = "SYSLOG" ; }
        case LOG_LPR     :{ ret = "LPR" ; }
        case LOG_NEWS    :{ ret = "NEWS" ; }
        case LOG_UUCP    :{ ret = "UUCP" ; }
        case LOG_CRON    :{ ret = "CRON" ; }
        case LOG_AUTHPRIV:{ ret = "AUTHPRIV" ; }
        case LOG_FTP     :{ ret = "FTP" ; }
        case LOG_LOCAL0  :{ ret = "LOCAL0" ; }
        case LOG_LOCAL1  :{ ret = "LOCAL1" ; }
        case LOG_LOCAL2  :{ ret = "LOCAL2" ; }
        case LOG_LOCAL3  :{ ret = "LOCAL3" ; }
        case LOG_LOCAL4  :{ ret = "LOCAL4" ; }
        case LOG_LOCAL5  :{ ret = "LOCAL5" ; }
        case LOG_LOCAL6  :{ ret = "LOCAL6" ; }
        case LOG_LOCAL7  :{ ret = "LOCAL7" ; }
    }
    return ret ;
}

func SyslogSeverity2str(severity syslog.Priority) (string){
    ret := "***" ;
    switch(severity){
        case LOG_EMERG   :{ ret = "EMERG" ; }
        case LOG_ALERT   :{ ret = "ALERT" ; }
        case LOG_CRIT    :{ ret = "CRIT" ; }
        case LOG_ERR     :{ ret = "ERR" ; }
        case LOG_WARNING :{ ret = "WARNING" ; }
        case LOG_NOTICE  :{ ret = "NOTICE" ; }
        case LOG_INFO    :{ ret = "INFO" ; }
        case LOG_DEBUG   :{ ret = "DEBUG" ; }
    }
    return ret ;
}

func ParseSyslogProtocolPri(rc *SyslogEntry){

    facilityN := rc.Pri / 8 ; _ = facilityN ;
    priorityN := rc.Pri % 8 ; _ = priorityN ;

    switch(facilityN){
        case 0:{ rc.Facility = LOG_KERN ; }
        case 1:{ rc.Facility = LOG_USER ; }
        case 2:{ rc.Facility = LOG_MAIL ; }
        case 3:{ rc.Facility = LOG_DAEMON ; }
        case 4:{ rc.Facility = LOG_AUTH ; }
        case 5:{ rc.Facility = LOG_SYSLOG ; }
        case 6:{ rc.Facility = LOG_LPR ; }
        case 7:{ rc.Facility = LOG_NEWS ; }
        case 8:{ rc.Facility = LOG_UUCP ; }
        case 9:{ rc.Facility = LOG_CRON ; }
        case 10:{ rc.Facility = LOG_AUTHPRIV ; }
        case 11:{ rc.Facility = LOG_FTP ; }
        case 16:{ rc.Facility = LOG_LOCAL0 ; }
        case 17:{ rc.Facility = LOG_LOCAL1 ; }
        case 18:{ rc.Facility = LOG_LOCAL2 ; }
        case 19:{ rc.Facility = LOG_LOCAL3 ; }
        case 20:{ rc.Facility = LOG_LOCAL4 ; }
        case 21:{ rc.Facility = LOG_LOCAL5 ; }
        case 22:{ rc.Facility = LOG_LOCAL6 ; }
        case 23:{ rc.Facility = LOG_LOCAL7 ; }
    }

    switch(priorityN){
        case 0:{ rc.Severity = LOG_EMERG ; }
        case 1:{ rc.Severity = LOG_ALERT ; }
        case 2:{ rc.Severity = LOG_CRIT ; }
        case 3:{ rc.Severity = LOG_ERR ; }
        case 4:{ rc.Severity = LOG_WARNING ; }
        case 5:{ rc.Severity = LOG_NOTICE ; }
        case 6:{ rc.Severity = LOG_INFO ; }
        case 7:{ rc.Severity = LOG_DEBUG ; }
    }
}

func ParseSyslogProtocol(line []rune) (SyslogEntry,error){

    rc := NewSyslogEntry() ;

    var err error = nil ; _ = err ;

    var mark_st rune = Ord("<") ;
    var mark_en rune = Ord(">") ;

    token := make([]rune,0) ;

    prio := make([]rune,0) ;
    date := make([]rune,0) ;

    tag  := make([]rune,0) ;
    pid  := make([]rune,0) ;
    mes  := make([]rune,0) ;

    flagTag := false ; _ = flagTag ;
    flagHostname := false ; _ = flagHostname ;

    max := len(line) ;
    idx := 0 ;
    step := 0 ;

    var c  rune ; _ = c ;
    var c2 rune ; _ = c2 ;

    for(idx < max){
        c  = line[idx + 0] ;
        if((idx+2) < max){
            c2 = line[idx + 1] ;
        }else{
            c2 = 0 ;
        }

        if((c == 0) || (c == 0x0a)){
            idx++ ;
            continue ;
        }

        switch(step){
            case 0:{
                if(c == mark_st){
                    step = 1 ;
                    idx++ ;
                }else{
                    return rc,errorf("Broken-1") ;
                }
            }
            case 1:{
                if(c == mark_en){
                    idx++ ;
                    rc.Pri,err = IsNumPri(prio) ;
                    if(err != nil){
                        return rc,err ;
                    }else{
                        ParseSyslogProtocolPri(&rc) ;
                        step = 2 ;
                    }
                }else{
                    prio = append(prio,c) ;
                    idx++ ;
                }
            }
            case 2:{
                if(c == Ord("1") && c2 == Ord(" ")){ /* <123>1 */
                    idx += 2 ;
                    step = 40 ;
                    rc.IsRFC5424 = true ;
                }else if((c >= Ord("A")) && (c <= Ord("Z"))){ /* Oct */
                    date = append(date,c) ;
                    idx++ ;
                    step = 10 ;
                    rc.IsRFC3164 = true ;
                }else if((c >= Ord("1")) && (c <= Ord("9"))){ /* 2023-10-02T08:18:35Z */
                    date = append(date,c) ;
                    idx++ ;
                    step = 5 ;
                    rc.IsRFC3164 = true ;
                }
            }
            case 5:{
                if(c == Ord(" ")){
                    rc.Timestamp = string(date) ;
                    ParseSyslogProtocolDate(&rc) ;
                    step = 11 ;
                }else{
                    date = append(date,c) ;
                    idx++ ;
                }
            }

            case 10:{
                date = append(date,c) ;
                idx++ ;

                if(len(date) == 15){
                    // len("Oct  2 03:01:01") == 15
                    rc.Timestamp = string(date) ;
                    ParseSyslogProtocolDate(&rc) ;
                    step = 11 ;
                }
            }
            case 11:{
                if(c == Ord(" ")){
                    idx++ ;
                    step = 12 ;
                }else{
                    return rc,errorf("Broken-2") ;
                }
            }
            case 12:{
                if(c == Ord(":")){
                    step = 18 ;
                    idx++ ;
                    rc.Tag = string(tag) ;
                    tag = make([]rune,0) ;
                    flagTag = true ;
                }else if(c == Ord("[")){
                    step = 14 ;
                    idx++ ;
                    rc.Tag = string(tag) ;
                    tag = make([]rune,0) ;
                    flagTag = true ;
                }else if(c == Ord(" ")){
                    if(flagHostname != false){
                        step = 30 ;
                        idx++ ;
                        flagTag = true ;
                        mes = append(tag,c) ;
                        tag = make([]rune,0) ;
                    }else{
                        flagHostname = true ;
                        rc.Hostname = string(tag) ;
                        tag = make([]rune,0) ;
                        idx++ ;
                    }
                }else{
                    tag = append(tag,c) ;
                    idx++ ;
                }
            }
            case 14:{
                if(c == Ord("]")){
                    rc.ProcId = string(pid) ;
                    step = 17 ;
                    idx++ ;
                }else{
                    pid = append(pid,c) ;
                    idx++ ;
                }
            }
            case 17:{
                if(c == Ord(":")){
                    idx++ ;
                    step = 18 ;
                }else{
                    return rc,errorf("Broken-3[0x%02x]",c) ;
                }
            }
            case 18:{
                if(c == Ord(" ")){
                    idx++ ;
                    step = 30 ;
                }else{
                    return rc,errorf("Broken-4[0x%02x]",c) ;
                }
            }

            case 30:{
                mes = append(mes,c) ;
                idx++ ;
            }

            case 40:{
                if(c == Ord(" ")){
                    rc.Timestamp = string(token) ;
                    ParseSyslogProtocolDate(&rc) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 41:{
                if(c == Ord(" ")){
                    rc.Hostname = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 42:{
                if(c == Ord(" ")){
                    rc.AppName = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 43:{
                if(c == Ord(" ")){
                    rc.ProcId = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 44:{
                if(c == Ord(" ")){
                    rc.MsgId = string(token) ;
                    token = make([]rune,0) ;
                    idx++ ;
                    step += 1 ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 45:{
                if(c == Ord("-")){
                    idx++ ;
                    step = 47 ;
                }else if(c == Ord("[")){
                    step = 46 ;
                }else{
                    step = 49 ;
                }
            }

            case 46:{
                if((c == Ord("]")) && (c2 != Ord("["))){
                    token = append(token,c) ;
                    rc.StructuredData = string(token) ;
                    token = make([]rune,0) ;
                    step = 47 ;
                    idx++ ;
                }else{
                    token = append(token,c) ;
                    idx++ ;
                }
            }

            case 47:{
                if(c == Ord(" ")){
                    step = 49 ;
                    idx++ ;
                }else{
                    return rc,errorf("Broken(%c)-1111",c) ;
                }
            }

            case 49:{
                mes = append(mes,c) ;
                idx++ ;
            }

        }
    }

    if(len(tag) > 0){
        rc.Message = string(tag) ;
    }else{
        rc.Message = "" ;
    }

    if(len(mes) > 0){
        rc.Message += string(mes) ;
    }

    return rc,nil ;
}

func (this *TypeSyslogDaemon) SyslogSplit(fifo string) (string,error){

    runes := []rune(fifo) ; _ = runes ;
    max := len(runes) ;
    idx := 0 ;
    offset := 0 ;
    step := 0 ;

    // printf("----[%s]\n",fifo) ;
    // printf("\n%s\n",Hexdump(fifo)) ;

    var mark_st rune = Ord("<") ;
    var mark_en rune = Ord(">") ;

    line := make([]rune,0) ;
    priStr := make([]rune,0) ;

    priLen      := -1 ; _ = priLen ;
    priLenAfter := -1 ; _ = priLenAfter ;

    headLen := -1 ; _ = headLen ;

    loop := 0 ;
    for ((idx + offset) < max){

        c := runes[idx + offset] ;
        priLenTmp := -1 ;
        if(c == mark_st){
            if((max > (idx + offset + 1)) && (mark_en == runes[idx + offset + 1])){ priLenTmp = 2 ; }else
            if((max > (idx + offset + 2)) && (mark_en == runes[idx + offset + 2])){ priLenTmp = 3 ; }else
            if((max > (idx + offset + 3)) && (mark_en == runes[idx + offset + 3])){ priLenTmp = 4 ; }else
            if((max > (idx + offset + 4)) && (mark_en == runes[idx + offset + 4])){ priLenTmp = 5 ; }

            if(priLenTmp >= 0){
                pri,err := IsNumPri(runes[(idx + offset+1):(idx + offset + priLenTmp-1)]) ;
                if(err != nil){
                    for xxx := 0;xxx < priLenTmp ; xxx++ {
                        c2 := runes[idx + offset + xxx] ;
                        line = append(line,c2) ;
                    }
                    idx += priLenTmp ;
                }else{
                    if(pri == 999){
                        headLen = priLenTmp ;
                    }else{
                        headLen = priLenTmp ;
                    }
                }
            }

            if(headLen >= 0){
                if(step == 0){
                    priLen = priLenTmp ;
                    for xxx := 0;xxx < priLenTmp ; xxx++ {
                        c2 := runes[offset + xxx] ;
                        line = append(line,c2) ;
                        priStr = append(priStr,c2) ;
                    }
                    step = 1 ;
                    idx += priLenTmp ;
                }else{
                    priLenAfter = priLenTmp ;
                    priTmpAfter := make([]rune,0) ;

                    for xxx := 0;xxx < priLenAfter ; xxx++ {
                        priTmpAfter = append(priTmpAfter,runes[offset + idx + xxx]) ;
                    }

                    step = 0 ;
                    offset += idx ;
                    idx = 0 ;
                    this.EvLine(line) ;
                    line = make([]rune,0) ;
                    priStr = make([]rune,0) ;
                    loop++ ;
                }
                headLen = -1 ;
            }else{
                idx += 1 ;
                line = append(line,c) ;
            }
        }else{
            idx += 1 ;
            line = append(line,c) ;
        }
    }

    return string(line),nil ;
}

func (this *TypeSyslogDaemon) DoTcp(tcpConn *net.TCPConn) (error){
    var szRc int ;
    var err error ;

    printf("TCP-Accept.\n") ;
    buf := make([]byte,0x1) ;
    var fifo string ;
    for{
        szRc,err = tcpConn.Read(buf) ;
        if((err == nil) && (szRc == 1)){
            fifo,err = this.SyslogSplit(fifo + string(buf)) ;
            if(err != nil){
                return err ;
            }
        }else{
            this.SyslogSplit(fifo + "<999>") ;
            if(err == io.EOF){
                printf("recv(%d)[%s]\n",szRc,err) ;
                break ;
            }else{
                printf("recv(%d)[%s]\n",szRc,err) ;
                return err ;
            }
        }
    }
    return nil ;
}

func (this *TypeSyslogDaemon) SyslogDaemonNode(idx int,addrListen string) (error){
    netDial := "unix" ; _ = netDial ;
    addrDial := "/dev/log" ; _ = addrDial ;

    var addrFrom netip.AddrPort ; _ = addrFrom ;

    if(this.router == nil){
        this.Wait.Done() ;
        return errorf("router 未設定") ;
    }

    if(this.router.Err != nil){
        this.Wait.Done() ;
        return this.router.Err
    }

    if(addrListen != ""){
        printf("%d[%s]\n",idx,addrListen) ;
        if ui , err := url.Parse(addrListen) ; (err != nil){
            this.Wait.Done() ;
            return err ;
        }else{
            switch(ui.Scheme){
                case "unix":{
                    // netDial = "unix" ;
                    netDial = "unixgram" ;
                    addrDial = ui.Path ;
                }
                case "tcp","udp":{
                    netDial = ui.Scheme ;
                    addrDial = ui.Host ;
                }
                default:{
                    a := strings.Split(ui.Host,":") ;
                    printf("Other:Host[%s:%s]\n",a[0],a[1]) ;
                }
            }
        }
    }

    if((netDial == "unix") || (netDial == "unixgram")){
        if _ , err := os.Stat(addrDial) ; (err == nil){
            if(addrDial == "/dev/log"){
                os.Remove(addrDial) ;
            }
        }
    }

    if(netDial == "udp"){
        go func() error{
            // time.Sleep(this.SleepBegin * time.Second) ;
            if udpAddr, err := net.ResolveUDPAddr(netDial,addrDial) ; (err == nil){
                if udpConn,err := net.ListenUDP(netDial,udpAddr) ; (err == nil){
                    buf := make([]byte,0x1000) ;
                    printf("UDP-Listen.\n") ;
                    this.Wait.Done() ;
                    for {
                        szRc,addr,err := udpConn.ReadFromUDPAddrPort(buf) ; _ = szRc ; _ = addr ; _ = err ;
                        if(err == nil){
                            this.SyslogSplit(string(buf[:szRc]) + "<999>") ;
                        }
                    }
                }
                return err ;
            }else{
                this.Wait.Done() ;
                return err ;
            }
        }() ;
    }else if(netDial == "tcp"){
        go func() error{
            // time.Sleep(this.SleepBegin * time.Second) ;

            if tcpAddr, err := net.ResolveTCPAddr(netDial,addrDial) ; (err == nil){
                if tcpListener,err := net.ListenTCP(netDial,tcpAddr) ; (err == nil){
                    defer tcpListener.Close() ;
                    printf("TCP-Listen.\n") ;
                    this.Wait.Done() ;
                    for{
                        chanTcpConn := make(chan *net.TCPConn) ;
                        chanTcpErr := make(chan error) ;

                        go func() {
                            tcpConn, err := tcpListener.AcceptTCP() ;
                            if (err != nil) {
                                chanTcpErr <- err ;
                                return
                            }
                            chanTcpConn <- tcpConn
                        }()

                        select {
                            case tcpConn := <-chanTcpConn:{
                                go this.DoTcp(tcpConn) ;
                            }
                            case err := <-chanTcpErr:{
                                printf("err[%s]\n",err)
                            }
                        }

                        chanTcpConn = nil
                        chanTcpErr = nil
                    }
                }else{
                    this.Wait.Done() ;
                    return err ;
                }
            }else{
                this.Wait.Done() ;
                return err ;
            }
        }() ;
    }else if((netDial == "unix") || (netDial == "unixgram")){
        go func() error{
            // time.Sleep(this.SleepBegin * time.Second) ;
            if unixAddr, err := net.ResolveUnixAddr(netDial,addrDial) ; (err == nil){
                sockListen, err := net.ListenUnix("unix",unixAddr) ; _ = sockListen ;
                if(err == nil){
                    printf("UNIX-Listen.\n") ;
                    this.Wait.Done() ;
                    for{
                        unixConn, err := sockListen.Accept() ;
                        if(err == nil){
                            go func() (error){
                                buf := make([]byte,0x1000) ;
                                var szRc int ;
                                var fifo string ;
                                for {
                                    szRc,err = unixConn.Read(buf) ;
                                    if(err == nil){

                                        // printf("\nUnix[0x%x]\n%s\n",szRc,Hexdump(string(buf[:szRc]))) ;

                                        fifo,err = this.SyslogSplit(fifo + string(buf[:szRc])) ;
                                    }else{
                                        unixConn.Close() ;
                                        this.SyslogSplit(fifo + "<999>") ;
                                        if(err == io.EOF){
                                            break ;
                                        }else{
                                            printf("recv[%s]\n",err) ;
                                            return err ;
                                        }
                                    }
                                }
                                return nil ;
                            }() ;
                        }
                    }
                }else{
                    this.Wait.Done() ;
                    return err ;
                }
            }else{
                this.Wait.Done() ;
                return err ;
            }
        }() ;
    }
    return nil ;
}

func    Sleep(n int){
    time.Sleep((time.Duration)(n) * time.Second) ;
}

type TypeSyslogDaemon struct {
    router *SyslogRouter ;
    Wait    sync.WaitGroup ;
    SleepBegin  time.Duration ;
} ;

func (this *TypeSyslogDaemon) Init() (*TypeSyslogDaemon){
    this.SleepBegin = 0 ;
    return this ;
}

func SyslogDaemon(opts ... any) (error){

    T := TypeSyslogDaemon{} ;

    T.Init() ;

    addrListens := make([]string,0) ;

    for _,opt := range opts{
        t := sprintf("%T",opt) ;

        switch(t){
            case "*BerdyshFrameworkGoLang.SyslogRouter":{
                T.router = opt.(*SyslogRouter)
            }
            case "string":{
                if ui , err := url.Parse(opt.(string)) ; (err != nil){
                    return err ;
                }else{
                    switch(ui.Scheme){
                        case "tcp","udp","unix":{
                            // printf("Set[%s]\n",opt.(string)) ;
                            addrListens = append(addrListens,opt.(string)) ;
                        }
                        default:{
                            return errorf("%s",opt.(string)) ;
                        }
                    }
                }
            }
            case "[]string":{
                for _,addr := range(opt.([]string)){
                    if ui , err := url.Parse(addr) ; (err != nil){
                        return err ;
                    }else{
                        switch(ui.Scheme){
                            case "tcp","udp","unix":{
                                // printf("Set[%s]\n",addr) ;
                                addrListens = append(addrListens,addr) ;
                            }
                            default:{
                                return errorf("%s",opt.(string)) ;
                            }
                        }
                    }
                }
            }
            default:{
                return errorf("%s",t) ;
            }
        }
    }

    if(len(addrListens) == 0){
        if(true){
            addrListens = append(addrListens,"unix:///dev/log") ;
            addrListens = append(addrListens,"tcp://:514") ;
            addrListens = append(addrListens,"udp://:514") ;
        }
    }

    for idx,addrListen := range addrListens{
        printf("[%d][%s]\n",idx,addrListen) ;
    }

    for idx,addrListen := range addrListens{
        T.Wait.Add(1) ;
        func(){
            if err := T.SyslogDaemonNode(idx,addrListen) ; (err != nil){
                printf("%d:[%s]/err[%s]-1349\n",idx,addrListen,err) ;
            }
        }() ;
    }

    T.Wait.Wait() ;
    time.Sleep(20 * time.Millisecond) ;

    printf("Ready-2330.\n") ;

    return nil ;
}

const (
    LOG_LOCATION        = 0x10000 ;
    LOG_PERROR          = 32 ;
    LOG_NDELAY          = 8 ;
    LOG_ODELAY          = 4 ;
    LOG_CONS            = 2 ;
    LOG_PID             = 1 ;
)

type LoggerSyslog struct {
    inited      bool ;
    Prefix      string ;
    Flags       int ;
    Facility    syslog.Priority ;
    Addr        string ;
    Network     string ;

    Conn        net.Conn ;
    Wait        sync.WaitGroup ;
}

func NewSyslogOption(opts ... any) (*LoggerSyslog){
    ret := &LoggerSyslog{} ;
    for _,opt := range(opts){
        switch(sprintf("%T",opt)){
            case "*BerdyshFrameworkGoLang.LoggerSyslog":{
                ret = opt.(*LoggerSyslog) ;
                printf("A-SetAddr(%s)\n",ret.Addr) ;
            }
            case "BerdyshFrameworkGoLang.LoggerSyslog":{
                def := opt.(LoggerSyslog) ;
                ret = &def ;
                printf("B-SetAddr(%s)\n",ret.Addr) ;
            }
            default:{
                printf("!!!![%T]\n",opt) ;
            }
        }
    }

    ret.inited = true ;

    return ret ;
}

func (this *LoggerSyslog) Init(){
    this.inited = true ;
}

func NewSyslogClient(prefix string,flags int,facility syslog.Priority,opts ... any) (*LoggerSyslog,error){

    var err error ;

    var option *LoggerSyslog ;

    this := LoggerSyslog{} ;
    this.Init() ;
    this.Prefix      = prefix ;
    this.Flags       = flags ;
    this.Facility    = facility ;

    for _,opt := range(opts){
        switch(sprintf("%T",opt)){
            case "*BerdyshFrameworkGoLang.LoggerSyslog":{
                option = opt.(*LoggerSyslog) ; _ = option ;
                if(option.Addr != ""){
                    this.Addr = option.Addr ;
                }
            }
            default:{
                printf("[%T]\n",opt) ;
            }
        }
    }

    network := "unix" ;
    addr := "/dev/log" ; _ = addr ;

    if(this.Addr == ""){ this.Addr = "unix:///dev/log" ; }

    ui , err := url.Parse(this.Addr) ;
    if(err != nil){
        return &this,err ;
    }else{
        switch(ui.Scheme){
            case "unix","unixgram":{
                network = "unix" ;
                addr = ui.Path ;

                logTypes := make([]string,0) ;
                logTypes = append(logTypes,ui.Scheme) ;

                if(ui.Scheme != "unixgram"){ logTypes = append(logTypes,"unixgram") ; }
                if(ui.Scheme != "unix"){ logTypes = append(logTypes,"unix") ; }

                logPaths := make([]string,0) ;
                logPaths = append(logPaths,ui.Path) ;

                if(ui.Path != "/dev/log"){ logPaths = append(logPaths,"/dev/log") ; }

                logPaths = append(logPaths,"/var/run/syslog") ;
                logPaths = append(logPaths,"/var/run/log") ;

                for _, network := range logTypes {
                    for _, path := range logPaths {
                        if conn, err := net.Dial(network, path) ; (err == nil){
                            this.Conn = conn ;
                            this.Network = network ;
                        }
                    }
                }
            }
            case "tcp":{
                network = "tcp" ;
                addr = ui.Host ;
                if addrTCP,err := net.ResolveTCPAddr(network,addr) ; (err != nil){
                    return &this,err ;
                }else if conn, err := net.DialTCP(network,nil,addrTCP) ; (err == nil){
                    this.Conn = conn ;
                    this.Network = network ;
                    return &this,nil ;
                }else{
                    printf("err[%s]\n",err) ;
                }
            }
            case "udp":{
                network = "udp" ;
                addr = ui.Host ;
                if addrUDP,err := net.ResolveUDPAddr(network,addr) ; (err != nil){
                    return &this,err ;
                }else if conn, err := net.DialUDP(network,nil,addrUDP) ; (err == nil){
                    this.Conn = conn ;
                    this.Network = network ;
                    return &this,nil ;
                }else{
                    printf("err[%s]\n",err) ;
                }
            }
            default:{
            }
        }
    }

    return &this,nil ;
}

func (this *LoggerSyslog) Now(opts ... any) (string){
    var t time.Time ;
    var IsSet bool ;

    if(len(opts) >= 1){
        switch(sprintf("%T",opts[0])){
            case "time.Time":{
                t = opts[0].(time.Time) ;
                IsSet = true ;
            }
        }
    }

    if(! IsSet){
        t = time.Now() ;
    }

    return t.Format("Jan _2 15:04:05") ;

    return "-" ;
}

func (this *LoggerSyslog) Send(packet string) (error){

    if(this.Conn != nil){

        switch(this.Network){
            case "unix","udp":{
                packet += Chr(0) ;
            }
            case "tcp":{
                packet += "\n" ;
            }
        }

        if _,err := this.Conn.Write([]byte(packet)) ; (err != nil) {
            return err ;
        }else{
            return nil ;
        }
    }

    // printf("[%s][%s]\n",network,this.Addr) ;
    // printf("%s\n",packet) ;
    // printf("%s\n",Hexdump(packet)) ;

    return nil ;
}

func (this *LoggerSyslog) Syslog(severity syslog.Priority,format string,args ... any) (error){
    var packet  string ;
    if(this.inited != true){ return Errorf("Not Init.") ; }

    pri := (this.Facility | severity) ;

    pid := os.Getpid() ;

    mess := sprintf(format,args...) ;
    packet = sprintf("<%d>%s %s[%d]: %s",pri,this.Now(),this.Prefix,pid,mess) ;

    return this.Send(packet) ;

    return nil ;
}

func (this *LoggerSyslog) Alert(format string,args ... any) (error){
    return this.Syslog(LOG_ALERT,format,args...) ;
}

func (this *LoggerSyslog) Crit(format string,args ... any) (error){
    return this.Syslog(LOG_CRIT,format,args...) ;
}

func (this *LoggerSyslog) Debug(format string,args ... any) (error){
    return this.Syslog(LOG_DEBUG,format,args...) ;
}

func (this *LoggerSyslog) Emerg(format string,args ... any) (error){
    return this.Syslog(LOG_EMERG,format,args...) ;
}

func (this *LoggerSyslog) Err(format string,args ... any) (error){
    return this.Syslog(LOG_ERR,format,args...) ;
}

func (this *LoggerSyslog) Info(format string,args ... any) (error){
    return this.Syslog(LOG_INFO,format,args...) ;
}

func (this *LoggerSyslog) Notice(format string,args ... any) (error){
    return this.Syslog(LOG_NOTICE,format,args...) ;
}

func (this *LoggerSyslog) Warning(format string,args ... any) (error){
    return this.Syslog(LOG_WARNING,format,args...) ;
}

func (this *LoggerSyslog) Close(){
    if(this.Conn != nil){
        this.Conn.Close() ;
    }
}

type HandlerLocal struct {
    Id  string ;
    inited bool ;
    mu sync.Mutex ;
} ;

func (this *HandlerLocal) GetId() (string){ return this.Id ; }

func (this *HandlerLocal) Init(){
    this.inited = true ;
}

func (this *HandlerLocal) IsInited() (bool){
    return this.inited ;
}

func (this *HandlerLocal) EvRecv(rc *SyslogEntry){
    if(false){
        printf("[%s]\n",this.Id) ;
        printf("\n%s\n",Hexdump(rc.Message)) ;
    }else{
        printf("%03d:%s.%s:%s:\n",runtime.NumGoroutine(),SyslogFacility2str(rc.Facility),SyslogSeverity2str(rc.Severity),rc.Message) ;
    }
}

func TestSyslogServer(){

    var router *SyslogRouter = NewSyslogRouter() ;
    handler := HandlerLocal{Id: "HI"} ;
    handler2 := HandlerLocal{Id: "LO"} ;
    handler3 := HandlerLocal{Id: "Other"} ;
    handler4 := HandlerLocal{Id: "Error"} ;

    entry := NewSyslogEntry() ;

    router.Handle(entry,&handler3) ;
    entry.Severity = LOG_ERR ; router.Handle(entry,&handler4) ;

        entry = NewSyslogEntry() ;

        entry.Facility = LOG_LOCAL0 ; router.Handle(entry,&handler) ;
        entry.Facility = LOG_LOCAL1 ; router.Handle(entry,&handler) ;
        entry.Facility = LOG_LOCAL2 ; router.Handle(entry,&handler) ;
        entry.Facility = LOG_LOCAL3 ; router.Handle(entry,&handler) ;
        entry.Facility = LOG_LOCAL4 ; router.Handle(entry,&handler2) ;
        entry.Facility = LOG_LOCAL5 ; router.Handle(entry,&handler2) ;
        entry.Facility = LOG_LOCAL6 ; router.Handle(entry,&handler2) ;
        entry.Facility = LOG_LOCAL7 ; router.Handle(entry,&handler2) ;

        if(true){
            addrs := make([]string,0) ;
            addrs = append(addrs,"unix:///dev/log") ;
            addrs = append(addrs,"tcp://:514") ;
            addrs = append(addrs,"udp://:514") ;

            if err := SyslogDaemon(addrs,router) ; (err != nil){
                printf("err[%s]-1672.\n",err) ;
            }
        }else{
            if err := SyslogDaemon("unix:///dev/log","tcp://:514","udp://:514",router) ; (err != nil){
                printf("err[%s]-1672.\n",err) ;
            }
        }
    }


















