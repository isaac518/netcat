#include<stdio.h>
#include"md5.h"
#include<time.h>
#include<string.h>
#include<unistd.h>

int main(int argc, char * argv[])
{   
    char buf[64];
    unsigned char res[16];
    int siglen;
    time_t t;
    int i;
    
    siglen=strlen(argv[1]);
    strncpy(buf,argv[1],siglen);
    t=time(NULL);
    sprintf(buf+siglen,"%d",t);
    //printf("%s\n",buf);
    memset(res,0,sizeof(res));
    __md5_buffer(buf,strlen(buf),res);
    
    /* compatible with md5sum program
    for (i=0;i<16;i++)
        printf("%x",res[i]);
    putchar('\n');
    */
    write(STDOUT_FILENO,res,16);
    
    return 0;
}
