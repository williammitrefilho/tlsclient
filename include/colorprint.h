#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define logerr() color_format(31, __FILE__, __LINE__)
#define logwarn() color_format(33, __FILE__, __LINE__)
#define loglog() color_format(32, __FILE__, __LINE__)

char *color_format(char color, const char file[], int line);
void init_logger();
void clean_logger_up();