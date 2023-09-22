NAME = ExampleClient
EXE = ${NAME}.exe

GOROOT = /usr/local/go

GO = ${GOROOT}/bin/go

SRCS = main.go


all: clean tidy build run

run:    ${EXE}
	./${EXE}

build:  ${EXE}

${EXE}: ${SRCS}
	${GO} build -o ${EXE} ${SRCS}

go.mod: go.mod.base
	cp go.mod.base go.mod

tidy:   go.mod
	${GO} mod tidy

clean:
	${RM} ${EXE} go.mod

c:
	curl -X 'DELETE' 'https://berdysh.net/XX/' -d 'AAAAAAA'

curl:
	curl -X 'DELETE' 'https://berdysh.net/XX/' -H 'accept: application/json' -H 'Content-Type: application/json' -d 'AAAAAAA'

c2:
	curl -X 'POST' 'https://berdysh.net/' -H 'accept: application/json' -H 'Content-Type: application/json' -d 'AAAAAAA'

c3:
	curl -X 'POST' 'https://petstore.swagger.io/v2/user' -H 'accept: application/json' -H 'Content-Type: application/json' -d 'AAAAAAA'

