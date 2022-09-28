#include <ber_entity.h>
#include <stdlib.h>
#include <string.h>

BerEntityList* ber_decode(unsigned char *data, unsigned short data_len, unsigned char use_data){
    
    if(!data_len || !data) {
        
        return 0;
    }
    BerEntity **entities = (BerEntity**)malloc(16*sizeof(BerEntity*));
    unsigned short n_entities = 0;
    unsigned short idx = 0;
    unsigned char *pData = data;
    
    while(idx < data_len && n_entities < 16){
        
        BerEntity *entity = (BerEntity*)malloc(sizeof(BerEntity));
        entity->parent = 0;
        entity->type = data[idx++];
        entity->dataLen = data[idx++];
        if(entity->dataLen & 0x80){
            
            unsigned short llen = entity->dataLen & 0x7F;
            entity->dataLen = 0;
            for(int i = 0; i < llen; i++){
                
                entity->dataLen <<= 8;
                entity->dataLen |= data[idx++];
            }
        }
        pData = data;
        pData += idx;
        if(!use_data){
            
            entity->pData = (unsigned char*)malloc(entity->dataLen);
            memcpy(entity->pData, pData, entity->dataLen);
            entity->allocMemory = 1;
        }
        else{
            
            entity->pData = pData;
            entity->allocMemory = 0;
        }
        entity->children = 0;
        if(entity->type &0x20){
            
            entity->children = ber_decode(entity->pData, entity->dataLen, 1);
            for(int i = 0; i < entity->children->n_entities; i++){
            
                entity->children->entities[i]->parent = entity;
            }
        }
        else{
            
            entity->children = 0;
        }
        
//        printf("%d, %d, %d\n", idx, entity->dataLen, data_len);
        entities[n_entities++] = entity;
        
        idx += entity->dataLen;
    }
    BerEntity **entities2 = (BerEntity**)malloc(n_entities*sizeof(BerEntity*));
    memcpy(entities2, entities, n_entities*sizeof(BerEntity*));
    
    BerEntityList *eList = (BerEntityList*)malloc(sizeof(BerEntityList));
    eList->n_entities = n_entities;
    eList->entities = entities2;
    
    free(entities);
    
    return eList;    
}

unsigned short free_entity(BerEntity *subject){
    
    BerEntity *ref = subject;
        
    while(subject->children){
        
        ref = subject;
        while(ref->children){
            
            ref = ref->children->entities[0];
        }
        if(ref->allocMemory){
            
            free(ref->pData);
        }
        ref = ref->parent;
        free(ref->children->entities[0]);
        ref->children->n_entities--;
        for(int i = 0;  i < ref->children->n_entities; i++){
            
            ref->children->entities[i] = ref->children->entities[i+1];
        }
        if(ref->children->n_entities == 0){
        
            free(ref->children);
            ref->children = 0;    
        }
    }
    if(subject->allocMemory){
        
        free(subject->pData);
        free(subject);
    }
    
    return 0;
}

unsigned short free_entity_list(BerEntityList *list){
    
    for(int i = 0; i < list->n_entities; i++){
            
        free_entity(list->entities[i]);
    }
    free(list);
    return 0;
}

BerEntity* copy_ber_entity(BerEntity *entity){
    
    unsigned short tlen = entity->dataLen + 4;
    unsigned char encoded[tlen], *penc = encoded;
    encoded[0] = entity->type;
    encoded[1] = 0x82;
    encoded[2] = entity->dataLen >> 8;
    encoded[3] = entity->dataLen & 0xFF;
    penc += 4;
    memcpy(penc, entity->pData, entity->dataLen);
    BerEntityList *l_copied = ber_decode(encoded, tlen, 0);
    BerEntity *copied = l_copied->entities[0];
    free(l_copied->entities);
    free(l_copied);
    
    return copied;
}