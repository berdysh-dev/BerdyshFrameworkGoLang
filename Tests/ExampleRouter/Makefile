NAME = ExampleRouter
TAG = router

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
	${RM} ${EXE} go.mod go.sum

Alpine: AlpineBuild AlpineRun

AlpineBuild:
	docker build -t ${TAG} -f DockerfileAlpine ../..

AlpineRun:
	docker run -a stdout -a stderr -p 9005:9005 ${TAG}
