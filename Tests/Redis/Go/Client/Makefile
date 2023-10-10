GOROOT = /usr/local/go
GO = ${GOROOT}/bin/go

EXE = a.out

all: clean tidy build run

${EXE}: main.go
	${GO} build -o $@ $<

go.mod:
	echo "module main" > go.mod
	echo "replace local/BerdyshFrameworkGoLang => ../../../.." >> go.mod

get:
	${GO} get github.com/redis/go-redis/v9

tidy:   go.mod
	${GO} mod tidy

build: ${EXE}

run:    ${EXE}
	./${EXE}

clean:
	${RM} ${EXE} go.mod go.sum

