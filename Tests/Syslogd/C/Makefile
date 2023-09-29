EXE = a.out

all: clean run

run:        ${EXE}
	@./${EXE}

${EXE}:
	@${CC} main.c -o $@

clean:
	@${RM} ${EXE}

