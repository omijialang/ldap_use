#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "get_domain_info.h"

extern win_ad_cond ad;

int init_ad_cond(const char *key, const char *value){/*{{{*/

    char buf[1024];
    char **p;

    if(!key || !value)
        return -1;

    if(!strcmp(key, "ad_uri") && !ad.ad_uri){
        /* if in Linux we can use asprintf() instead */
        strcpy(buf, LDAP_PREFIX);
        strcat(buf, value);

        if((ad.ad_uri = strdup(buf)) == NULL)
            return -1;
    }else if(!strcmp(key, "ad_manager") && !ad.ad_manager){

        if((ad.ad_manager = strdup(value)) == NULL)
            return -1;
    }else if(!strcmp(key, "ad_passwd") && !ad.ad_passwd){
    
        if((ad.ad_passwd = strdup(value)) == NULL)
            return -1;
    }else if(!strcmp(key, "ad_org_unitS")){
        p = ad.ad_org_unitS;
        while(*p) p++;
        if((*p = strdup(value)) == NULL)
            return -1;
    }else if(!strcmp(key, "ad_gflag")){
        if(!ad.ad_gflag)
            ad.ad_gflag = 1;
    }else if(!strcmp(key, "ad_get_udir")){
        if(!ad.ad_get_udir)
            ad.ad_get_udir = 1;
    }else if(!strcmp(key, "ad_encrypt")){
        ad.ad_encrypt = 1;
    }

    return 0;
}/*}}}*/

static FILE *get_config_fp(const char *path, const char *mode){/*{{{*/
	
	FILE *fp;
	if((fp = fopen(path, mode)) == NULL)
		return NULL;
	return fp;
}/*}}}*/

int get_cond_from_file(const char *path){/*{{{*/
	
	FILE *conf_fp;
	char line[1024];
	char *p, *end;
	int sec_ad, is_domain;

    if(!path || !path[0])
        return -1;

	sec_ad = is_domain = 0;

	if((conf_fp = get_config_fp(path, "r")) == NULL)
		return -1;

	while(fgets(line, 1024, conf_fp) != NULL){
		p = line;
		end = &line[strlen(line) - 1];

		/* remove all space in line head and tail */
		while(isspace(*p))
			p++;
		while(isspace(*(end - 1)))
			end--;
		*end = 0;

		if(*p != '#'){   // remove '#' comment in line head
			if(*p == '['){
				p++;
				if(strstr(p, "domain") && strchr(p,']'))
					sec_ad = is_domain = 1;      // in [domain] section
				else
					is_domain = 0;
			}else
				if(is_domain){
					if(!strncasecmp("AD_NAME=", p, 8)){
                        if(init_ad_cond("ad_uri", p + 8))
                            return -1;
                    }else if(!strncasecmp("AD_USER=", p, 8)){
                        if(init_ad_cond("ad_manager", p + 8))
                            return -1;
					}else if(!strncasecmp("AD_PASSWD=", p, 10)){
                        if(init_ad_cond("ad_passwd", p + 10))
                            return -1;
					}else if(!strncasecmp("AD_OU=", p, 6)){
                        if(init_ad_cond("ad_org_unitS", p + 6))
                            return -1;
					}else if(!strncasecmp("AD_GET_UDIR=", p, 12)){
                        if(!strncasecmp("yes", p + 12, 3))
                            init_ad_cond("ad_get_udir", (char *)24);
					}else if(!strncasecmp("AD_GFLAG=", p, 9)){
                        if(!strncasecmp("yes", p + 9, 3))
                            init_ad_cond("ad_gflag", (char *)24);
				    }
                }
		}
		if(sec_ad == 1 && is_domain == 0)
			break;
	}
	if(!sec_ad)
		return -1;
	
	return 0;
}/*}}}*/
