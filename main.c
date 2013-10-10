#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include "get_domain_info.h"

int get_stdin_passwd;
char *conf_filepath;
win_ad_cond ad;

void log_to_null(const char *fmt, ...){}

void record_with_location(const char *location, const char *func, const char *fmt, ...){/*{{{*/

    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "%s %s: ", location, func);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}/*}}}*/

void usage(void){/*{{{*/

    printf("Usage: \n"
           "\t-d ad_name\t domain name\n" 
           "\t-u ad_manager\t domain's manager account\n" 
           "\t-p ad_passwd\t domain's manager account password\n"
           "\t\t\t if ad_passwd is '-' cmd will read stdin to get password\n"
           "\t-f conf_file\t specify config file's path. it will instead the\n"
           "\t\t\t the default /tmp/domain.conf. if any option above are specified \n"
           "\t\t\t will override the corresponding field in conf_file\n");
}/*}}}*/

void free_ad_cond(void){/*{{{*/

    char **p;

    if(ad.ad_uri)
        free(ad.ad_uri);
    if(ad.ad_manager)
        free(ad.ad_manager);
    if(ad.ad_passwd)
        free(ad.ad_passwd);

    p = ad.ad_org_unitS;
    while(*p){
        free(*p);
        p++;
    }
}/*}}}*/

int isvalid_ad_cond(void){/*{{{*/

    if(ad.ad_get_udir || ad.ad_org_unitS[0])
        return (ad.ad_uri && ad.ad_manager && ad.ad_passwd);
    return 0;
}/*}}}*/

void dump_ad_cond(void){/*{{{*/

    char **p;

    if(ad.ad_uri && ad.ad_manager && ad.ad_passwd)
        dbg("\n\tad_uri ## %s ##\n"
            "\tad_manager ## %s ##\n"
            "\tad_passwd ## %s ##\n", ad.ad_uri, ad.ad_manager, ad.ad_passwd);
    
    p = ad.ad_org_unitS;
    while(*p){
        dbg("\n\tad_ou ## %s ##\n", *p);
        p++;
    }
    dbg("\n\tad.ad_gflag ## %s ##\n", ad.ad_gflag ? "Yes" : "No");
    dbg("\n\tad.ad_get_udir ## %s ##\n", ad.ad_get_udir ? "Yes" : "No");
    dbg("\n\tad.ad_encrypt ## %s ##\n", ad.ad_encrypt ? "Yes" : "No");
}/*}}}*/

#if 1
int opt_parse(int argc, char **argv, char *optstr){/*{{{*/

    char c;

    opterr = 0;
    while((c = getopt(argc, argv, optstr)) != -1){
        switch(c){
            case 'd':
                if(init_ad_cond("ad_uri", optarg))
                    goto ERR_ARGS;
                break;
            case 'u':
                if(init_ad_cond("ad_manager", optarg))
                    goto ERR_ARGS;
                break;
            case 'p':
                if(!strcmp(optarg, "-"))
                    get_stdin_passwd = 1;
                else
                    if(init_ad_cond("ad_passwd", optarg))
                        goto ERR_ARGS;
                break;
            case 'f':
                if((conf_filepath = strdup(optarg)) == NULL)
                    goto ERR_ARGS;
                break;
            case 'o':
                if(init_ad_cond("ad_org_unitS", optarg))
                    goto ERR_ARGS;
                break;
            case 'c':
                init_ad_cond("ad_get_udir", (char *)24);
                break;
            case 'g':
                init_ad_cond("ad_gflag", (char *)24);
                break;
            case 's':
                init_ad_cond("ad_encrypt", (char *)24);
                break;
#if 0
            case 'n':
                printf("option ## %c ", c);
                printf("optarg ## %s ##\n", optarg);
                break;
#endif
            default :
                goto ERR_ARGS;
        }    
    }

    return 0;

ERR_ARGS:
    usage();
    free_ad_cond();
    if(conf_filepath)
        free(conf_filepath);
    return -1;
}/*}}}*/
#endif

int get_real_passwd(){/*{{{*/

    int n;
    char buf[1024];
    char *passwd;
    struct termios term_attrs;
    
    tcgetattr(STDIN_FILENO, &term_attrs);
    term_attrs.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_attrs);
    
    write(STDOUT_FILENO, "Password :", 10);
    if((n = read(STDIN_FILENO, buf, 1024)) < 1)
        return -1;
    buf[n - 1] = 0;

    if((passwd = strdup(buf)) == NULL)
        return -1;

    if(ad.ad_passwd)
        free(ad.ad_passwd);
    ad.ad_passwd = passwd;

    term_attrs.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term_attrs);
    
    write(STDOUT_FILENO, "\n", 1);
    return 0;
}/*}}}*/

int main(int argc, char *argv[]){
    
    int i = 0;

    if(opt_parse(argc, argv, "d:f:u:p:n:o:csg")){
        fprintf(stderr, "bad cmdline arguments. please retry!\n");
        exit(2);
    }
    
    if(get_stdin_passwd)
        get_real_passwd(); 

    if(!conf_filepath)
        conf_filepath = AD_CONF_FILE;

    if(get_cond_from_file(conf_filepath) && !isvalid_ad_cond()){
        fprintf(stderr, "initialize from file failed. please retry!\n");
        exit(1);
    }

    if(!isvalid_ad_cond()){
        fprintf(stderr, "can't get fully informations to connect WIN_AD.\n"
                        "please specify it again on cmdline or conf_file and retry!\n");
        exit(2);
    }
    get_domain_info(&ad);

    dump_ad_cond();
    free_ad_cond();

    return 0;
}
