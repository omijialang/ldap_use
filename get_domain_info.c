#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>

#include "get_domain_info.h"

#define GET_ACCOUNT_CN 1
#define GET_GROUP_CN 2
#define ATTR "sAMAccountName"
//static char *attr_cn[] = {"cn", "whenCreated", NULL};
//static char *attr_cn[] = {"grouptype", "cn", NULL};
static char *attr_cn[] = {"grouptype", ATTR, NULL};

static int get_udir_dn_with_dc(char *udir_dn, const char *dc_s){

    return sprintf(udir_dn, "cn=users,%s", dc_s);
}

static int get_dc_with_ad_cond(win_ad_cond *cond, char *dc_s){/*{{{*/
   
    char ch[1024] = {0};
    char *p;

    strcpy(ch, cond->ad_uri);

    /* cut "ldap://" from ad_uri */
    p = strtok(ch + 7, ".");

    sprintf(dc_s, "dc=%s", p);

    while(p = strtok(NULL, "."))
        sprintf(dc_s, "%s,dc=%s", dc_s, p);
    
    return 0;
}/*}}}*/

static int get_dn_with_ad_cond(win_ad_cond *cond, int *offset, char *dn, const char *dc_s){/*{{{*/
    
    char *p = cond->ad_org_unitS[*offset];

    if(!p)
        return 0;
    
    (*offset)++;
    sprintf(dn, "ou=%s,%s", p, dc_s);

    return 1;
}/*}}}*/

static int is_ascii_str(const char *buf){/*{{{*/

    int i;

    for(i = 0; buf[i]; i++){
        if(!isascii(buf[i]) || isspace(buf[i]))
//        if(!isascii(buf[i]))
            return 0;
    }

    return 1;
}/*}}}*/

static LDAP *ldap_connect(const char *ServerURI, const char *ServerName, const char *ServerPwd){/*{{{*/

    int ret;
    LDAP *ld;

/*  ret = ldap_initialize(&ld, ServerURI, SSL_OFF, NULL); */
/*  Because ServerURI is ldap://... */
    ld = ldap_init(ServerURI + 7, LDAP_PORT);
    if(ld == NULL){

        err("%s\n", ldap_err2string(ret));
        return NULL;
    }   
       
    ret = ldap_simple_bind_s(ld, ServerName, ServerPwd);
    if(ret != LDAP_SUCCESS){

        err("%s\n", ldap_err2string(ret));
        return NULL;
    }   

    dbg("ldap_simple_bind_s Success\n"); 

    return ld; 
}/*}}}*/

static int ldap_get_info_recurrence(LDAP *ld, const char* baseDN, int gflag){/*{{{*/

    LDAPMessage *DC_Messages, *message;
    BerElement *ber;
    /* maybe 256 is to small but I think it is enough. */
    char cn_tmp[256];
    char *attrs;
    int attrs_n;
    char **values;
    int ret;
    int i;
    
//    puts(baseDN + 8);
	ret = ldap_search_ext_s(ld, baseDN, LDAP_SCOPE_SUBTREE, NULL, attr_cn, 0, 
                NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &DC_Messages);

    if(ret != LDAP_SUCCESS){

        err("%s\n", ldap_err2string(ret));
		return -1;
	}

    dbg("ldap_search_ext_s Success\n");
    dbg("Entry_n ## %d\n", ldap_count_entries(ld, DC_Messages));

	for(message = ldap_first_entry(ld, DC_Messages); 
        message != NULL; 
        message = ldap_next_entry(ld, message)){
		
        dbg("#########################################\n");
        attrs_n = 0;
        *cn_tmp = 0;
		for(attrs = ldap_first_attribute(ld, message, &ber); 
            attrs != NULL; 
            attrs = ldap_next_attribute(ld, message, ber)){
            
			if(values = ldap_get_values(ld, message, attrs)){

                for(i = 0; values[i]; i++){
                    if(is_ascii_str(values[i]) && !strcmp(ATTR, attrs))
                        strcpy(cn_tmp, values[i]);
                }
				ldap_value_free(values);
			}
			ldap_memfree(attrs);
            attrs_n++;
		}

        /* group? account? */
        if(*cn_tmp)
            if(gflag == GET_GROUP_CN){
                if(attrs_n == 2)
                    puts(cn_tmp);
            }else{
                if(attrs_n == 1)
                    puts(cn_tmp);
            }

		if(ber != NULL){
			ber_free(ber,0);
		}
        dbg("#########################################\n\n");
	}
    ldap_msgfree(DC_Messages);

	return 0;
}/*}}}*/

static int ldap_get_all_group(LDAP *ld, const char* baseDN){/*{{{*/

    return ldap_get_info_recurrence(ld, baseDN, GET_GROUP_CN); 
}/*}}}*/

static int ldap_get_all_account(LDAP *ld, const char* baseDN){/*{{{*/
    
    return ldap_get_info_recurrence(ld, baseDN, GET_ACCOUNT_CN); 
}/*}}}*/

int get_domain_info(win_ad_cond *cond){/*{{{*/

    LDAP *ld;
    int protocol_version, oldprotocol_version;
    int ret;
    int offset;
    char dc_s[1024];
    char dn[1024];
    char udir_dn[1024];

    if((ld = ldap_connect(cond->ad_uri, cond->ad_manager, cond->ad_passwd)) == NULL){

		err("ldap_connect failed!\n");
        return -1;
	}

    ldap_get_option(ld, LDAP_OPT_PROTOCOL_VERSION, &oldprotocol_version);
    info("LDAP_OPT_PROTOCOL_VERSION ## %d\n", oldprotocol_version);

#if 0
    protocol_version = 3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol_version);

    ldap_get_option(ld, LDAP_OPT_PROTOCOL_VERSION, &oldprotocol_version);
    printf("LDAP_OPT_PROTOCOL_VERSION ## %d\n", oldprotocol_version);
    
	ret = ldap_search_ext_s(ld, "ou=go,dc=zxh,dc=ceresdata,dc=com", LDAP_SCOPE_ONELEVEL, NULL, NULL, 0, 
                NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &res);
    if(ret != LDAP_SUCCESS){
    
        puts(ldap_err2string(ret));
        exit(24);
    }
#endif

    get_dc_with_ad_cond(cond, dc_s);

    if(cond->ad_get_udir){
        get_udir_dn_with_dc(udir_dn, dc_s);
        if(cond->ad_gflag){
            if(ldap_get_all_group(ld, udir_dn))
                err("dn ## %s ## %s\n", udir_dn, "ldap_get_all_account failed!\n");
        }else{
            if(ldap_get_all_account(ld, udir_dn))
                err("dn ## %s ## %s\n", udir_dn, "ldap_get_all_account failed!\n");
        }
    }

    offset = 0;
    while(get_dn_with_ad_cond(cond, &offset, dn, dc_s)){
        
        if(cond->ad_gflag){
            if(ldap_get_all_group(ld, dn))
                err("dn ## %s ## %s\n", dn, "ldap_get_all_account failed!\n");
        }else{
            if(ldap_get_all_account(ld, dn))
                err("dn ## %s ## %s\n", dn, "ldap_get_all_account failed!\n");
        }
    }

	return 0;
}/*}}}*/
