#include <colorprint.h>

int n_log_color_strings;
char *log_color_strings[128];

char *color_format(char color, const char file[], int line){
	
	char *colored_output = (char*)malloc(128);
	sprintf(colored_output, "\033[%dm%s(%d)\033[m:", color, file, line);
	log_color_strings[n_log_color_strings++] = colored_output;
	return colored_output;
}

void init_logger(){
	n_log_color_strings = 0;
}

void clean_logger_up(){
	
	printf("%s limpando %d logs...\n", logwarn(), n_log_color_strings); 
	for(int i = 0; i < n_log_color_strings; i++){
		free(log_color_strings[i]);
	}
}