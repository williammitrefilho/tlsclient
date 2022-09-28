#ifndef BXML_XMLDEFS_H

#define BXML_XMLDEFS_H

#define BXML_IS_OPEN_TAG 0x01
#define BXML_IS_TAG 0x02
#define BXML_IS_CLOSE_TAG 0x04
#define BXML_IS_TAG_ATTRIBUTE_NAME 0x08
#define BXML_IS_TAG_NAME 0x10
#define BXML_IS_TAG_DATA 0x20
#define BXML_IS_FIRST_HEADER 0x40
#define BXML_IS_TAG_ATTRIBUTE_VALUE 0x80

typedef struct {
    
    unsigned char flags;
    
    unsigned short initTagLen;
    unsigned short currentTagLen;
    unsigned short tagDataLen;
    unsigned short tagAttrNameLen;
    unsigned short tagAttrValLen;
    unsigned short currentTagNameLen;
    unsigned short dataLen;
    
    unsigned char nameDelimiter;
    unsigned char cursor[2];
    unsigned char content[256];
    unsigned char data[8192];
    
    unsigned char *pInitTag;
    unsigned char *pTagData;
    unsigned char *pTagName;
    unsigned char *pTagAttrName;
    unsigned char *pTagAttrVal;
} BXMLState;

typedef struct XMLElementAttribute{
    
    unsigned char *name;
    unsigned short nameLen;
    unsigned char *value;
    unsigned short valueLen;
    unsigned char hasValue;
} XMLElementAttribute;

typedef struct XMLElement{
    
    unsigned short tagNameLen;
    unsigned char *tagName;
    unsigned short dataLen;
    unsigned char *data;
    struct XMLElement *parent;
    XMLElementAttribute **attributes;
    unsigned short n_attributes;
    struct XMLElement **children;
    unsigned short n_children;    
} XMLElement;

typedef struct XMLElementList{
    
    XMLElement **elements;
    unsigned short n_elements;
} XMLElementList;

const unsigned char label_docZip[7];

unsigned short zeroContent(unsigned char *content, unsigned short len);
unsigned short initState(BXMLState *state);
unsigned short freeElement(XMLElement *pElement);
unsigned short freeElementList(XMLElementList *list);
void printData(unsigned char *data, unsigned short len);
XMLElementList* parseData(unsigned char *data, unsigned int data_len);
XMLElementAttribute** parseTag(unsigned char *data, unsigned short data_len, unsigned short *n_attribs);
XMLElement* findElement(XMLElementList *list, const unsigned char *name);
unsigned short findElements(XMLElementList *list, const unsigned char *name, XMLElement **elements, unsigned short *p_n_elements);
unsigned short getTextContent(XMLElement *element, unsigned char *pText);
int indexOfElement(XMLElementList *list, XMLElement *element);
unsigned short printTags(XMLElement *element, unsigned char *opInitTag, unsigned char *opEndTag, unsigned short *pInitTagLen, unsigned short *pEndTagLen);

#endif