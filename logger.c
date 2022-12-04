#include <logger.h>

#define logerr(msg) logger_colorprint(31, msg, __FILE__, __LINE__)
#define loglog(msg) logger_colorprint(32, msg, __FILE__, __LINE__)

void logger_colorprint(char color, char *msg, const char file[], int line){
        printf("\033[%dm%s(%d):\033[m%s\n", color, file, line, msg);
}