EXE = a.out
INC_SYSLOG_NG = /usr/include/syslog-ng
INC_GLIB = /usr/include/glib-2.0
INC_GLIB2 = /usr/lib64/glib-2.0/include/

all: clean run

run:        ${EXE}
	@./${EXE}

${EXE}:
	${CC} -I ${INC_SYSLOG_NG} -I ${INC_GLIB} -I ${INC_GLIB2} main.c -o $@ -lsyslog-ng

clean:
	@${RM} ${EXE}

