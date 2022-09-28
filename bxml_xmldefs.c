// William Mitre Filho - 2022
// Uma ferramenta miniaturizada para parsing de XML.
#include <bxml_xmldefs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const unsigned char label_docZip[7] = "docZip";

unsigned short zeroContent(unsigned char *content, unsigned short len){

    for(int i = 0; i < len; i++){
        
        content[i] = 0;
    }
    return 0;
}

unsigned short initState(BXMLState *state){
    
    state->initTagLen = 0;
    state->currentTagLen = 0;
    state->tagDataLen = 0;
    state->tagAttrNameLen = 0;
    state->tagAttrValLen = 0;
    state->currentTagNameLen = 0;
    state->flags = 0;
    
    state->cursor[0] = 0x00;
    state->cursor[1] = 0x00;    
    state->nameDelimiter = 0x00;
    zeroContent(state->content, 128);
    zeroContent(state->data, 8192);
    
    state->pInitTag = 0;
    state->pTagData = 0;
    state->pTagName = 0;
    state->pTagAttrName = 0;
    state->pTagAttrVal = 0;
    
    return 0;
}

unsigned short freeElement(XMLElement *pElement){
    
    if(pElement->data){
        
        free(pElement->data);
    }
    if(pElement->tagName){
    
        free(pElement->tagName);    
    }
    for(int i = 0; i < pElement->n_attributes; i++){
        
        unsigned char label[pElement->attributes[i]->nameLen+1];
//        pElement->attributes[0]->name[pElement->attributes[0]->nameLen - 1] = 'q';
        memcpy(label, pElement->attributes[i]->name, pElement->attributes[0]->nameLen);
        label[pElement->attributes[i]->nameLen] = 0x00;

//        printf("freeing attrib %d(%d) (%s)(%d)...\n", pElement->attributes[i]->name, i+1, label, pElement->attributes[i]->nameLen);
        free(pElement->attributes[i]->name);
        if(pElement->attributes[i]->value){
            printf("freeing attrib %d value...\n", i+1);
            free(pElement->attributes[i]->value);
        }
    }
    free(pElement->attributes);
    if(pElement->children){
        
//        printf("freeing children(%d [%d])...\n", pElement->children, pElement->n_children);
        free(pElement->children);
    }
    free(pElement);
//    printf("freed.\n");
    return 0;
}

unsigned short freeElementList(XMLElementList *list){
    
    for(int i = 0; i < list->n_elements; i++){
        
        unsigned char label[list->elements[i]->attributes[0]->nameLen+1];
        memcpy(label, list->elements[i]->attributes[0]->name, list->elements[i]->attributes[0]->nameLen);
        label[list->elements[i]->attributes[0]->nameLen] = 0x00;
//        printf("freeing %d/%d(%s)...\n", i+1, list->n_elements, label);
        freeElement(list->elements[i]);
    }
//    printf("freed all\n");
    free(list);
    return 0;
}

void printData(unsigned char *data, unsigned short len){
    
    for(int i = 0; i < len; i++){
        
        printf("%c", data[i]);
    }
}

XMLElement* findElement(XMLElementList *list, const unsigned char *name){
    
    unsigned short name_len = 0;
    while(name[name_len] != 0x00 && name_len < 256){
        
        name_len++;
    }
    for(int i = 0; i < list->n_elements; i++){
        
        XMLElementAttribute *attr = list->elements[i]->attributes[0];
        if(attr->nameLen != name_len)
            continue;
        
        if(memcmp(attr->name, name, name_len) == 0){
            
            return list->elements[i];
        }
    }
    return 0;
}

unsigned short findElements(XMLElementList *list, const unsigned char *name, XMLElement **elements, unsigned short *p_n_elements){
    
    unsigned short name_len = 0, n_elements = 0;
    
    while(name[name_len] != 0x00 && name_len < 256){
        
        name_len++;
    }
    for(int i = 0; i < list->n_elements; i++){
        
        XMLElementAttribute *attr = list->elements[i]->attributes[0];
        if(attr->nameLen != name_len)
            continue;
        
        if(memcmp(attr->name, name, name_len) == 0){
            
            if(elements)
                elements[n_elements] = list->elements[i];
            n_elements++;
        }
    }
//    printf("%d\n", n_elements);
    if(p_n_elements)
        *p_n_elements = n_elements;
    
    return 0;
}

unsigned short printTags(XMLElement *element, unsigned char *opInitTag, unsigned char *opEndTag, unsigned short *pInitTagLen, unsigned short *pEndTagLen){
    
    unsigned char attrib[element->attributes[0]->nameLen+1];
    attrib[element->attributes[0]->nameLen] = 0x00;
    memcpy(attrib, element->attributes[0]->name, element->attributes[0]->nameLen);
    unsigned short initTagLen = 1 + element->attributes[0]->nameLen, endTagLen = initTagLen + 2;

    for(int j = 1; j < element->n_attributes; j++){
        
        unsigned char attrib1[element->attributes[0]->nameLen+1];
        attrib1[element->attributes[j]->nameLen] = 0x00;
        memcpy(attrib1, element->attributes[j]->name, element->attributes[j]->nameLen);
//            printf("    %s\n", attrib1);
        initTagLen += 1 + element->attributes[j]->nameLen + 2 + element->attributes[j]->valueLen + 1;
    }
    initTagLen ++;
    
    unsigned char tag[initTagLen], *ptag = tag, endTag[endTagLen], *pEndTag = endTag;
//    printf("(%d)initTagLen:%d\n", ptag, initTagLen);
    ptag[0] = '<';
    pEndTag[0] = '<';
    pEndTag[1] = '/';
    ptag++;
    pEndTag += 2;
    memcpy(ptag, element->attributes[0]->name, element->attributes[0]->nameLen);
    memcpy(pEndTag, element->attributes[0]->name, element->attributes[0]->nameLen);
    ptag += element->attributes[0]->nameLen;
    pEndTag += element->attributes[0]->nameLen;
    pEndTag[0] = '>';
//    pEndTag[1] = 0x00;
    pEndTag ++;
    pEndTag -= endTagLen;
    for(int j = 1; j < element->n_attributes; j++){
        
        ptag[0] = ' ';
        ptag++;
        memcpy(ptag, element->attributes[j]->name, element->attributes[j]->nameLen);
        ptag += element->attributes[j]->nameLen;
        ptag[0] = '=';
        ptag[1] = '"';
        ptag += 2;
        memcpy(ptag, element->attributes[j]->value, element->attributes[j]->valueLen);
        ptag += element->attributes[j]->valueLen;
        ptag[0] = '"';
        ptag++;
    }
    ptag[0] = '>';
    ptag ++;
//    printf("%d, %d\n", ptag, initTagLen);
    ptag -= initTagLen;
    
//    printf("%d:%s%s\n", ptag, ptag, endTag);
    if(pInitTagLen){
        
        *pInitTagLen = initTagLen;
    }
    if(pEndTagLen){
        
        *pEndTagLen = endTagLen;
    }
    if(opEndTag){
        
        memcpy(opEndTag, endTag, endTagLen);
    }
    if(opInitTag){
        
        memcpy(opInitTag, ptag, initTagLen);
    }
    return 0;    
}

int indexOfElement(XMLElementList *list, XMLElement *element){
    
    for(int i = 0; i < list->n_elements; i++){
        
        if(list->elements[i] == element)
            return i;
    }
    return -1;
}

unsigned short getTextContent(XMLElement *element, unsigned char *pText){
    
    unsigned short initTagLen = 0, endTagLen = 0;
    printTags(element, 0, 0, &initTagLen, &endTagLen);
    unsigned short txt_len = initTagLen + endTagLen + element->dataLen;
    if(element->n_children > 0){
        
        for(int i = 0; i < element->n_children; i++){
            
            txt_len += getTextContent(element->children[i], 0);
        }
    }
    unsigned char text[txt_len], *p_text = text, *p_text1 = text;
    p_text1 += txt_len - endTagLen;
    
    printTags(element, p_text, p_text1, &initTagLen, &endTagLen);
    p_text += initTagLen;
    if(element->dataLen){
        
        memcpy(p_text, element->data, element->dataLen);
        p_text += element->dataLen;
    }
    if(element->n_children > 0){
        
        for(int i = 0; i < element->n_children; i++){
            
            unsigned short len = getTextContent(element->children[i], p_text);
            p_text += len;
        }
    }
    if(pText){
        
        memcpy(pText, text, txt_len);
    }
//    printData(text, txt_len);printf("\n");
    return txt_len;
}

XMLElementAttribute** parseTag(unsigned char *data, unsigned short data_len, unsigned short *n_attribs){
    
    XMLElementAttribute *attributes[32], currentAttr = {0, 0, 0, 0, 0};
//    printf("allocated\n");
    unsigned char buffer[512], nameDelimiter = 0x00, c = 0x00, pc;
    unsigned short buffer_len = 0, n_attributes = 0, idx = 0;
    while(data[idx] != ' ' && idx < data_len){
        
        buffer[buffer_len] = data[idx];
        buffer_len++;
        idx++;
    }
    currentAttr.name = (unsigned char*)malloc(buffer_len);
    memcpy(currentAttr.name, buffer, buffer_len);
    currentAttr.nameLen= buffer_len;
//    printf("(%d)name:", n_attributes);printData(currentAttr.name, currentAttr.nameLen);printf("\n");
    attributes[n_attributes] = (XMLElementAttribute*)malloc(sizeof(XMLElementAttribute));
//    printf("attr set.\n");
    memcpy(attributes[n_attributes], &currentAttr, sizeof(XMLElementAttribute));
    n_attributes++;
    
    buffer_len = 0;
    currentAttr.name = 0;
    currentAttr.nameLen = 0;
    
    while((data[idx] == 0x20 || data[idx] == 0x09 || data[idx] == 0x0A || data[idx] == 0x0D)  && idx <  data_len){
        
        idx++;
    }
    
    while(idx < data_len){
        
        unsigned char hasValue = 0;
        while(data[idx] != ' ' && data[idx] != '=' && idx < data_len){
            
            buffer[buffer_len] = data[idx];
            idx++;
            buffer_len++;
        }
        if(data[idx] == '=')
            hasValue = 1;
        
        currentAttr.name = (unsigned char*)malloc(buffer_len);
        memcpy(currentAttr.name, buffer, buffer_len);
        currentAttr.nameLen = buffer_len;
        buffer_len = 0;
        
        if(!hasValue){
            
            while((data[idx] == 0x20 || data[idx] == 0x09 || data[idx] == 0x0A || data[idx] == 0x0D) && idx < data_len){
            
                idx++;
            }
            if(data[idx] != '='){
            
                attributes[n_attributes] = (XMLElementAttribute*)malloc(sizeof(XMLElementAttribute));
                memcpy(attributes[n_attributes], &currentAttr, sizeof(XMLElementAttribute));
                n_attributes++;
                currentAttr.name = 0;
                currentAttr.nameLen = 0;
                buffer_len = 0;
                continue;    
            }
            else{
                
                hasValue = 1;
            }
        }
        idx++;
        
        while((data[idx] == 0x20 || data[idx] == 0x09 || data[idx] == 0x0A || data[idx] == 0x0D) && idx <  data_len){
            
            idx++;
        }
        
        if(data[idx] == '"' || data[idx] == '\''){
            
            nameDelimiter = data[idx];
        }
        idx++;
        while(data[idx] != nameDelimiter && idx < data_len){
            
            buffer[buffer_len] = data[idx];
            buffer_len++;
            idx++;
        }
        nameDelimiter = 0x00;
        currentAttr.value = (unsigned char*)malloc(buffer_len);
        memcpy(currentAttr.value, buffer, buffer_len);
        currentAttr.valueLen = buffer_len;
//        printData(buffer, buffer_len);printf("\n");
        XMLElementAttribute *p_n_attr = (XMLElementAttribute*)malloc(sizeof(XMLElementAttribute));
        memcpy(p_n_attr, &currentAttr, sizeof(XMLElementAttribute));
        attributes[n_attributes] = p_n_attr;
        n_attributes++;
        currentAttr.name = 0;
        currentAttr.nameLen = 0;
        currentAttr.value = 0;
        currentAttr.valueLen = 0;
        buffer_len = 0;
        idx++;
        while((data[idx] == 0x20 || data[idx] == 0x09 || data[idx] == 0x0A || data[idx] == 0x0D) && idx <  data_len){
            
            idx++;
        }
    }
    
    XMLElementAttribute **attribs = (XMLElementAttribute**)malloc(n_attributes*sizeof(XMLElementAttribute*));
    memcpy(attribs, attributes, n_attributes*sizeof(XMLElementAttribute*));
    *n_attribs = n_attributes;
    
    return attribs;
}

XMLElementList* parseData(unsigned char *data, unsigned int data_len){
    
    XMLElement **elements = (XMLElement**)malloc(2048*sizeof(XMLElement*)), *refElement = 0, *element = 0;
    if(!elements){
        
        printf("erro aloc1\n");
        return 0;
    }
    unsigned short n_elements = 0;

    BXMLState xmlState;
    initState(&xmlState);
    unsigned char c = 0x00, pc = 0x00;
    unsigned int begin = 0, end = 0, idx = 0;
    if(data[0] != '<')
        return 0;
    
    if(data[1] == '?'){
        
        for(int i = 0; i < data_len; i++){
            
            pc = c;
            c = data[idx++];
            if(c == '>' && pc == '?'){
                
    //            printf("end init\n");
                break;
            }
        }
    }
    c = 0x00;
    pc = 0x00;
    for(int i = idx; i < data_len; i++){
        
        pc = c;
        c = data[idx++];
        if(xmlState.flags & BXML_IS_TAG_NAME){
            
//            printf("(%c%c %02X %02X)", pc, c, xmlState.flags, xmlState.nameDelimiter);
            if(!xmlState.nameDelimiter){
                
                if(c == '"' || c == '\''){
                    
                    xmlState.nameDelimiter = c;
                }
                else if(c == '>'){
//                    printf("[tag]");
//                    return 1;
                    if(xmlState.flags & BXML_IS_OPEN_TAG){
                                               
//                        printData(xmlState.content, xmlState.currentTagNameLen);printf("\n");
                        refElement = element;
//                        printf("tag(%d) allocating...\n", refElement); 
                        element = (XMLElement*)malloc(sizeof(XMLElement));
//                        printf("callocated\n");
                        element->n_children = 0;
                        element->children = 0;
                        element->tagName = 0;
                        element->tagNameLen = xmlState.currentTagNameLen;
                        element->data = 0;
                        element->dataLen = 0;
//                        printf("tag parsing...\n");
                        
                        element->attributes = parseTag(xmlState.content, xmlState.currentTagNameLen, &element->n_attributes);
//                        if(xmlState.currentTagNameLen > 150)
//                            printf("statelen: %d\n", xmlState.currentTagNameLen);
//                        printf("tag parsed\n");
                        if(element->tagNameLen){
                            
                            element->tagName = (unsigned char*)malloc(element->tagNameLen);
                            if(!element->tagName){
                                
                                printf("erro aloc2\n");
                                return 0;
                            }
                            memcpy(element->tagName, xmlState.content, element->tagNameLen);
                        }
                        else{
                             
                            element->tagName = 0;
                        }
                        element->parent = refElement;
//                        printf("parent:%d\n", element->parent);
                        if(element->parent){
                        
//                            printf("hasParent\n");                       
                            XMLElement **chd = (XMLElement**)malloc((element->parent->n_children+1)*sizeof(XMLElement*));
                            if(!chd){
                                
                                printf("erro aloc3\n");
                                return 0;
                            }
                            if(element->parent->children){
                                
                                for(int j = 0; j < element->parent->n_children; j++){
                                    
                                    chd[j] = element->parent->children[j];
//                                    memcpy(chd, element->parent->children, element->parent->n_children*sizeof(XMLElement*));
                                }
                                free(element->parent->children);                               
                            }
                            chd[element->parent->n_children++] = element;
                            element->parent->children = chd;
//                            printf("%d chd\n", element->parent->n_children);
                        }
                        
                        elements[n_elements++] = element;
                        zeroContent(xmlState.content, xmlState.currentTagNameLen);
                        xmlState.currentTagNameLen = 0;
                        
//                        printf("zeroc\n");
                        
                        if(pc == '/'){
                            
                            element->data = 0;
                            element->dataLen = 0;
//                            printf("end tag name:%s \ndata:\n%s\n", xmlState.content, xmlState.data);
                            refElement = element->parent;
                            element = element->parent;
                        }    
                    }
                    else{
                        
//                        printf("end tag name:%s \ndata:\n%s\n", xmlState.content, xmlState.data);  
//                        printf("dataLen: %d\n", xmlState.dataLen);
                        element->dataLen = xmlState.dataLen;
                        if(element->dataLen){
                            
                            element->data = (unsigned char*)malloc(element->dataLen);
                            if(!element->data){
                                
                                printf("erro aloc4\n");
                                return 0;
                            }
                            memcpy(element->data, xmlState.data, element->dataLen);
                        }
                        else{
                            
                            element->data = 0;
                        }
//                        printf("ctag(%d %d) ", refElement, element->parent);
//                        printData(xmlState.content, 5);
//                        printf("\n");
                        refElement = element->parent;
                        element = element->parent;
//                        printf("cctag(%d) ", refElement);
//                        printData(xmlState.content, xmlState.currentTagNameLen);
//                        printf("\n");
                    }
                    zeroContent(xmlState.data, 8192);
                    xmlState.dataLen = 0;
                    xmlState.currentTagNameLen = 0;
                    xmlState.flags = 0;  
                }
            }
            else{
                
                if(c == xmlState.nameDelimiter){
                    
                    xmlState.nameDelimiter = 0x00;
                }
            }
            
            if(xmlState.currentTagNameLen < 255)
                xmlState.content[xmlState.currentTagNameLen] = c;
            
            xmlState.currentTagNameLen++;
        }
        else if(pc == '<'){
            
            if(c != '/'){
                
//                printf("begin tag ini: ", xmlState.content);
                zeroContent(xmlState.content, 256);
                xmlState.flags = BXML_IS_TAG_NAME | BXML_IS_OPEN_TAG;
                xmlState.currentTagNameLen = 1;
                xmlState.content[0] = c;
            }
            else{
                
//                printf("begin tag fin: ");
                zeroContent(xmlState.content, 256);
                xmlState.flags = BXML_IS_TAG_NAME | BXML_IS_CLOSE_TAG;
                xmlState.currentTagNameLen = 0;
                if(xmlState.dataLen < 8192){
                    
                    xmlState.dataLen--;
                    xmlState.data[xmlState.dataLen] = 0x00;
                }
            }
        }
        else{
            
            if(xmlState.dataLen < 8191)
                xmlState.data[xmlState.dataLen] = c;
            
            xmlState.dataLen++;
        }
    }
    XMLElementList *list = (XMLElementList*)malloc(sizeof(XMLElementList));
    list->n_elements = n_elements;
    list->elements = (XMLElement**)malloc(n_elements*sizeof(XMLElement*));
    for(int i = 0; i < n_elements; i++){
        
        list->elements[i] = elements[i];
    }
    free(elements);
    
    return list;  
}