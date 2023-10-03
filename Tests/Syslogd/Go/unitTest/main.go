package main

import X "local/BerdyshFrameworkGoLang"

func case_0010() error {

    line := "<188>Oct  3 09:46:35 ident: X_3" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 188){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }
        if(rc.Timestamp != "Oct  3 09:46:35"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Tag != "ident"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.Message != "X_3"){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0020() error {

    line := "<189>Oct  3 01:08:39 hostname/127.0.0.1 foo bar baz" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Timestamp != "Oct  3 01:08:39"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Tag != "-"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.Hostname != "hostname/127.0.0.1"){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }
        if(rc.Message != "foo bar baz"){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}


func case_0030() error {

    line := "<188>2023-10-03T01:14:30Z hostname TAG[715]: tcp" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Timestamp != "2023-10-03T01:14:30Z"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != "hostname"){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }
        if(rc.Tag != "TAG"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != `715`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != "tcp"){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0040() error {

    line := "<188>Oct  3 01:14:30 TAG[715]: unix" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Timestamp != "Oct  3 01:14:30"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Tag != "TAG"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != `715`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != "unix"){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0050() error {

    line := "<188>Oct  3 01:14:30 TAG: unix" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Timestamp != "Oct  3 01:14:30"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Tag != "TAG"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != "-"){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != "unix"){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0060() error {

    line := "<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 34){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }
        if(rc.Timestamp != "Oct 11 22:14:15"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != "mymachine"){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }
        if(rc.Tag != "very.large.syslog.message.tag"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != "-"){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != `'su root' failed for lonvick on /dev/pts/8`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0070() error {

    line := "<30>Jun 23 13:17:42 127.0.0.1 java.lang.NullPointerException" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }
        if(rc.Timestamp != "Jun 23 13:17:42"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != "127.0.0.1"){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }
        if(rc.Tag != "-"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != "-"){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != `java.lang.NullPointerException`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0080() error {

    line := "<30>2006-01-02T15:04:05 localhost foo: Selected source 192.168.65.1" ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }
        if(rc.Timestamp != "2006-01-02T15:04:05"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != "localhost"){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }
        if(rc.Tag != "foo"){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }
        if(rc.ProcId != "-"){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }
        if(rc.Message != `Selected source 192.168.65.1`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }

    return X.Errorf("Success") ;
}

func case_0100() error {

    line := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 34){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC5424 != true){
            return X.Errorf("Failed:IsRFC5424(%v)",rc.IsRFC5424) ;
        }

        if(rc.Timestamp != "2003-10-11T22:14:15.003Z"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `mymachine.example.com`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.AppName != `su`){
            return X.Errorf("Failed:AppName(%s)",rc.AppName) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.MsgId != `ID47`){
            return X.Errorf("Failed:MsgId(%s)",rc.MsgId) ;
        }

        if(rc.StructuredData != `-`){
            return X.Errorf("Failed:StructuredData(%s)",rc.StructuredData) ;
        }

        if(rc.Message != `'su root' failed for lonvick on /dev/pts/8`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0110() error {

    line := `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 165){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC5424 != true){
            return X.Errorf("Failed:IsRFC5424(%v)",rc.IsRFC5424) ;
        }

        if(rc.Timestamp != "2003-08-24T05:14:15.000003-07:00"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `192.0.2.1`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.AppName != `myproc`){
            return X.Errorf("Failed:AppName(%s)",rc.AppName) ;
        }

        if(rc.ProcId != `8710`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.MsgId != `-`){
            return X.Errorf("Failed:MsgId(%s)",rc.MsgId) ;
        }

        if(rc.StructuredData != `-`){
            return X.Errorf("Failed:StructuredData(%s)",rc.StructuredData) ;
        }

        if(rc.Message != `%% It's time to make the do-nuts.`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0120() error {

    line := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry...` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 165){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC5424 != true){
            return X.Errorf("Failed:IsRFC5424(%v)",rc.IsRFC5424) ;
        }

        if(rc.Timestamp != "2003-10-11T22:14:15.003Z"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `mymachine.example.com`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.AppName != `evntslog`){
            return X.Errorf("Failed:AppName(%s)",rc.AppName) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.MsgId != `ID47`){
            return X.Errorf("Failed:MsgId(%s)",rc.MsgId) ;
        }

        if(rc.StructuredData != `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`){
            return X.Errorf("Failed:StructuredData(%s)",rc.StructuredData) ;
        }

        if(rc.Message != `An application event log entry...`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0130() error {

    line := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 165){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC5424 != true){
            return X.Errorf("Failed:IsRFC5424(%v)",rc.IsRFC5424) ;
        }

        if(rc.Timestamp != "2003-10-11T22:14:15.003Z"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `mymachine.example.com`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.AppName != `evntslog`){
            return X.Errorf("Failed:AppName(%s)",rc.AppName) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.MsgId != `ID47`){
            return X.Errorf("Failed:MsgId(%s)",rc.MsgId) ;
        }

        if(rc.StructuredData != `[exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`){
            return X.Errorf("Failed:StructuredData(%s)",rc.StructuredData) ;
        }

        if(rc.Message != ``){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0200() error {

    line := `<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 34){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "Oct 11 22:14:15"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `mymachine`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `very.large.syslog.message.tag`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.Message != `'su root' failed for lonvick on /dev/pts/8`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0210() error {

    line := `<30>Jun 23 13:17:42 chronyd[1119]: Selected source 192.168.65.1` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "Jun 23 13:17:42"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `-`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `chronyd`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `1119`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `Selected source 192.168.65.1`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0220() error {

    line := `<30>Jun 23 13:17:42 localhost Selected source 192.168.65.1` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "Jun 23 13:17:42"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `localhost`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `-`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `Selected source 192.168.65.1`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0230() error {

    line := `<30>Jun 23 13:17:42 localhost foo: Selected source 192.168.65.1`

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "Jun 23 13:17:42"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `localhost`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `foo`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `Selected source 192.168.65.1`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0240() error {

    line := `<30>2006-01-02T15:04:05 localhost foo: Selected source 192.168.65.1` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 30){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "2006-01-02T15:04:05"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `localhost`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `foo`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `Selected source 192.168.65.1`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0300() error {

    line := `<13>May  1 20:51:40 myhostname myprogram: ciao` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 13){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "May  1 20:51:40"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `myhostname`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `myprogram`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `ciao`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0310() error {

    line := `<13>May  1 20:51:40 myhostname myprogram[42]: ciao`

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 13){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "May  1 20:51:40"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `myhostname`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `myprogram`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `42`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `ciao`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0320() error {

    line := `<13>May  1 20:51:40 myprogram: ciao` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 13){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "May  1 20:51:40"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `-`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `myprogram`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `-`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `ciao`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func case_0330() error {

    line := `<78>May  1 20:51:02 myprog[153]: blah` ;

    if rc,err := X.ParseSyslogProtocol([]rune(line)) ; (err != nil){
        return err ;
    }else{
        if(rc.Pri != 78){
            return X.Errorf("Failed:Pri(%d)",rc.Pri) ;
        }

        if(rc.IsRFC3164 != true){
            return X.Errorf("Failed:IsRFC3164(%v)",rc.IsRFC3164) ;
        }

        if(rc.Timestamp != "May  1 20:51:02"){
            return X.Errorf("Failed:Timestamp(%s)",rc.Timestamp) ;
        }
        if(rc.Hostname != `-`){
            return X.Errorf("Failed:Hostname(%s)",rc.Hostname) ;
        }

        if(rc.Tag != `myprog`){
            return X.Errorf("Failed:Tag(%s)",rc.Tag) ;
        }

        if(rc.ProcId != `153`){
            return X.Errorf("Failed:ProcId(%s)",rc.ProcId) ;
        }

        if(rc.Message != `blah`){
            return X.Errorf("Failed:Message(%s)",rc.Message) ;
        }
    }
    return X.Errorf("Success") ;
}

func main(){
    X.Printf("St.\n")

    if err := case_0010() ; (err != nil){ X.Printf("0010:[%s]\n",err) }
    if err := case_0020() ; (err != nil){ X.Printf("0020:[%s]\n",err) }
    if err := case_0030() ; (err != nil){ X.Printf("0030:[%s]\n",err) }
    if err := case_0040() ; (err != nil){ X.Printf("0040:[%s]\n",err) }
    if err := case_0050() ; (err != nil){ X.Printf("0050:[%s]\n",err) }
    if err := case_0060() ; (err != nil){ X.Printf("0060:[%s]\n",err) }
    if err := case_0070() ; (err != nil){ X.Printf("0070:[%s]\n",err) }
    if err := case_0080() ; (err != nil){ X.Printf("0080:[%s]\n",err) }

    if err := case_0100() ; (err != nil){ X.Printf("0100:[%s]\n",err) }
    if err := case_0110() ; (err != nil){ X.Printf("0110:[%s]\n",err) }
    if err := case_0120() ; (err != nil){ X.Printf("0120:[%s]\n",err) }
    if err := case_0130() ; (err != nil){ X.Printf("0130:[%s]\n",err) }

    if err := case_0200() ; (err != nil){ X.Printf("0200:[%s]\n",err) }
    if err := case_0210() ; (err != nil){ X.Printf("0210:[%s]\n",err) }
    if err := case_0220() ; (err != nil){ X.Printf("0220:[%s]\n",err) }
    if err := case_0230() ; (err != nil){ X.Printf("0230:[%s]\n",err) }
    if err := case_0240() ; (err != nil){ X.Printf("0240:[%s]\n",err) }

    if err := case_0300() ; (err != nil){ X.Printf("0300:[%s]\n",err) }
    if err := case_0310() ; (err != nil){ X.Printf("0310:[%s]\n",err) }
    if err := case_0320() ; (err != nil){ X.Printf("0320:[%s]\n",err) }
    if err := case_0330() ; (err != nil){ X.Printf("0330:[%s]\n",err) }

    X.Printf("Fin.\n")
}







































