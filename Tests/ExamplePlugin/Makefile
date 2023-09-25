NAME = ExamplePlugin
EXE = ${NAME}.exe

MAKE = make --no-print-directory

GOROOT = /usr/local/go

GO = ${GOROOT}/bin/go

SRCS = main.go

all: clean tidy build plugin run

run:    ${EXE}
	./${EXE}

build:  ${EXE}

plugin: mods/plugin.so

${EXE}: ${SRCS}
	${GO} build -o ${EXE} ${SRCS}

go.mod: go.mod.base
	cp go.mod.base go.mod

tidy:   go.mod
	${GO} mod tidy

mods/plugin.so:
	${MAKE} -C ./mods all

clean:
	${RM} ${EXE} go.mod
	${MAKE} -C ./mods clean

