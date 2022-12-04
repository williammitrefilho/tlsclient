#include <stdio.h>

#ifndef LOGGER_H

#define LOGGER_H
#define logerr(msg) logger_colorprint(31, msg, __FILE__, __LINE__)
#define loglog(msg) logger_colorprint(32, msg, __FILE__, __LINE__)

void logger_colorprint(char color, char *msg, const char file[], int line);

#endif