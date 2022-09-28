#include <bxml_xmldefs.h>
#include <stdio.h>

int main(int argc, char *argv[]){
	
	if(argc < 2){
		
		printf("file?\n");
		return 1;
	}
	
	FILE *arq = fopen(argv[1], "rb");
	if(!arq){
		
		printf("erro ao abrir arquivo\n");
		return 1;
	}
	fseek(arq, 0, SEEK_END);
	int filesize = ftell(arq);
	unsigned char data[filesize];
	fseek(arq, 0, SEEK_SET);
	fread(data, 1, filesize, arq);
	printf("%s\n", data);
	XMLElementList *xml = parseData(data, filesize);
	if(!xml){
		
		printf("erro no parse\n");
		fclose(arq);
		return 1;
	}
	printf("parse OK: %d elements\n", xml->n_elements);
	for(int i = 0; i < xml->n_elements; i++){
		
		XMLElement *element = xml->elements[i];
		unsigned char name[element->tagNameLen+1];
		name[element->tagNameLen] = 0;
		memcpy(name, element->tagName, element->tagNameLen);
		printf("elemento %d: %s\n", i+1, name);
		for(int j = 0; j < element->n_attributes; j++){
			
			printf("atributo:%d (%s)\n", element->attributes[j]->name, element->attributes[j]->name);
		}
	}
	freeElementList(xml);
	fclose(arq);
	
	return 0;
}