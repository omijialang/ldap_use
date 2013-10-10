#ifndef __GET_DOMAIN_INFO_H_
#define __GET_DOMAIN_INFO_H_

#include <stdio.h>

#ifndef __STRING
#define __STRING(x) # x
#endif

#ifndef __STRINGSTRING
#define __STRINGSTRING(x) __STRING(x)
#endif

#define __LINESTR__ __STRINGSTRING(__LINE__)
#define __location__ __FILE__ " ##" __LINESTR__

//#define LHL_ENABLE_LOGGING
//#define LHL_ENABLE_DBG

void log_to_null(const char *, ...);
void record_with_location(const char *, const char *, const char *, ...);

#define log_to_record(fmt, arg...) \
    record_with_location(__location__, __func__, fmt, ## arg)

#ifdef LHL_ENABLE_LOGGING
#   ifdef LHL_ENABLE_DBG
#       define dbg(fmt, arg...) log_to_record(fmt, ## arg)
#   else
#       define dbg(fmt, arg...) log_to_null(fmt, ## arg)
#   endif
#   define info(fmt, arg...) log_to_record(fmt, ## arg)
#else
#   define dbg(fmt, arg...) log_to_null(fmt, ## arg)
#   define info(fmt, arg...) log_to_null(fmt, ## arg)
#endif


#define err(fmt, arg...) \
    do{                  \
        fprintf(stderr, "Error :"); \
        fprintf(stderr, fmt, ## arg);   \
    }while(0)

#define AD_OU_MAX 1024
#define LDAP_PREFIX "ldap://"
#define AD_CONF_FILE "/var/automap.conf"

typedef struct _ldap_cond{

    /* get AD_domain's group cn */
    int ad_gflag:1;
    /* get cn which in AD/Users dir */
    int ad_get_udir:1;
    /* encrypt passwd and write it in conf_file(default or user specify)*/
    int ad_encrypt:1;
    char *ad_uri;
    char *ad_manager;
    char *ad_passwd;
    /* recurrence get all cn from AD/$OU dir */
    char *ad_org_unitS[AD_OU_MAX];
}win_ad_cond;

#endif
