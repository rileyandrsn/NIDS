#include <json-c/json.h>
#include <stdio.h>

int main(){
    FILE *fp;
    char buffer[1024];

    struct json_object *parsed_json;
    struct json_object *rule;
    struct json_object *name;

    fp = fopen("/Users/rileyanderson/Documents/GitHub/NIDS/config/rules.json","r");
    if(!fp){
        printf("err");
    }
    fread(buffer,1024,1,fp);
    fclose(fp);
    parsed_json = json_tokener_parse(buffer);
    int len = json_object_array_length(parsed_json);
    for(int i = 0; i<len; i++){
        rule = json_object_array_get_idx(parsed_json, i);
        printf("\nRule: %s\n",json_object_get_string(rule));
    }
    json_object_object_get_ex(rule,"name",&name);
    printf("%s",json_object_get_string(name));

}

