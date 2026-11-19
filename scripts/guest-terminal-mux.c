#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

/* One unprivileged process per PTY; serial is only a framed transport.
 * No command strings are evaluated by this broker. Window input goes to its
 * PTY, including the terminal driver's normal foreground-job signals. */
#define LIMIT 64
#define QUEUE 65536
#define CREDIT 65536
#define PREFIX "\036CDMUX "
struct session { unsigned id; int fd; pid_t pid; size_t used; unsigned credit; char input[QUEUE]; };
static struct session sessions[LIMIT];

static void frame(char kind, unsigned id, const unsigned char *data, size_t len) {
    static const char hex[]="0123456789abcdef";
    printf(PREFIX "%c %u ", kind, id);
    for(size_t i=0;i<len;i++){putchar(hex[data[i]>>4]);putchar(hex[data[i]&15]);}
    putchar('\n');fflush(stdout);
}
static void close_session(struct session *s) {
    if(!s->id)return;
    kill(-s->pid,SIGHUP);close(s->fd);frame('X',s->id,NULL,0);
    memset(s,0,sizeof(*s));
}
static void open_session(struct session *s,unsigned id,unsigned cols,unsigned rows) {
    int master=posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC);
    if(master<0||grantpt(master)||unlockpt(master)){if(master>=0)close(master);return;}
    char name[128];if(ptsname_r(master,name,sizeof(name))){close(master);return;}
    struct winsize size={.ws_row=(unsigned short)rows,.ws_col=(unsigned short)cols};ioctl(master,TIOCSWINSZ,&size);
    pid_t pid=fork();
    if(pid<0){close(master);return;}
    if(pid==0){
        if(setsid()<0)_exit(126);
        int slave=open(name,O_RDWR);
        if(slave<0||ioctl(slave,TIOCSCTTY,0)<0)_exit(126);
        for(int i=0;i<3;i++)if(dup2(slave,i)<0)_exit(126);
        if(slave>2)close(slave);
        close(master);
        for(int i=0;i<LIMIT;i++)if(sessions[i].id)close(sessions[i].fd);
        signal(SIGPIPE,SIG_DFL);signal(SIGHUP,SIG_DFL);
        setenv("TERM","xterm-256color",1);
        chdir("/home/guest");
        execl("/bin/sh","sh","-i",(char *)NULL);_exit(127);
    }
    fcntl(master,F_SETFL,O_NONBLOCK);
    *s=(struct session){.id=id,.fd=master,.pid=pid,.credit=CREDIT};frame('O',id,NULL,0);
}
static int unhex(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static void command(char *line) {
    if(strncmp(line,PREFIX,sizeof(PREFIX)-1))return;
    char kind=line[sizeof(PREFIX)-1];char *start=line+sizeof(PREFIX)+1;
    if(start[-1]!=' '||!isdigit((unsigned char)*start))return;
    char *end;unsigned long id=strtoul(start,&end,10);
    if(!id||id>2147483647||(*end&&*end!=' '))return;
    struct session *s=NULL,*empty=NULL;
    for(int i=0;i<LIMIT;i++){if(sessions[i].id==id)s=&sessions[i];else if(!sessions[i].id&&!empty)empty=&sessions[i];}
    if(kind=='O'){
        unsigned cols,rows;char extra;
        if(sscanf(end," %u %u %c",&cols,&rows,&extra)!=2||cols<20||cols>320||rows<4||rows>120)return;
        if(!s&&empty){open_session(empty,(unsigned)id,cols,rows);if(!empty->id)frame('E',(unsigned)id,(unsigned char *)"Could not open guest PTY",23);}
        else if(!s) {
            frame('E',(unsigned)id,(unsigned char *)"Terminal limit reached",22);
        }
        return;
    }
    if(!s)return;
    if(kind=='C'&&!*end){close_session(s);return;}
    if(kind=='S'){
        unsigned cols,rows;char extra;
        if(sscanf(end," %u %u %c",&cols,&rows,&extra)!=2||cols<20||cols>320||rows<4||rows>120)return;
        struct winsize size={.ws_row=(unsigned short)rows,.ws_col=(unsigned short)cols};
        ioctl(s->fd,TIOCSWINSZ,&size);return;
    }
    if(kind=='A'){
        unsigned amount;char extra;
        if(sscanf(end," %u %c",&amount,&extra)==1&&amount>0&&amount<=CREDIT&&amount<=CREDIT-s->credit)s->credit+=amount;
        return;
    }
    if(kind!='I'||*end!=' ')return;
    char *hex=end+1;size_t len=strlen(hex);
    if(len%2||len/2>QUEUE-s->used)return;
    for(size_t i=0;i<len;i++)if(unhex(hex[i])<0)return;
    for(size_t i=0;i<len;i+=2)s->input[s->used++]=(char)(unhex(hex[i])*16+unhex(hex[i+1]));
}
int main(void) {
    if(getuid()!=1000||getgid()!=1000)return 126;
    struct termios raw;if(tcgetattr(0,&raw))return 126;
    cfmakeraw(&raw);if(tcsetattr(0,TCSANOW,&raw))return 126;
    signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IOFBF,8192);
    puts(PREFIX "R 2");fflush(stdout);
    static char line[32768];size_t used=0;int discard=0;
    for(;;){
        struct pollfd fds[LIMIT+1];fds[0]=(struct pollfd){.fd=0,.events=POLLIN};
        for(int i=0;i<LIMIT;i++)fds[i+1]=(struct pollfd){.fd=sessions[i].id&&(sessions[i].credit||sessions[i].used)?sessions[i].fd:-1,.events=(sessions[i].credit?POLLIN:0)|(sessions[i].used?POLLOUT:0)};
        if(poll(fds,LIMIT+1,-1)<0){if(errno==EINTR)continue;return 1;}
        if(fds[0].revents&POLLIN){
            char bytes[2048];ssize_t n=read(0,bytes,sizeof(bytes));if(n<=0)return 0;
            for(ssize_t i=0;i<n;i++){
                if(bytes[i]=='\n'){if(!discard){line[used]=0;command(line);}used=0;discard=0;}
                else if(!discard){if(used<sizeof(line)-1)line[used++]=bytes[i];else{used=0;discard=1;}}
            }
        }
        for(int i=0;i<LIMIT;i++){
            struct session *s=&sessions[i];if(!s->id||fds[i+1].fd!=s->fd)continue;
            if(fds[i+1].revents&POLLOUT){ssize_t n=write(s->fd,s->input,s->used);if(n>0){s->used-=(size_t)n;memmove(s->input,s->input+n,s->used);}}
            if(s->credit&&(fds[i+1].revents&(POLLIN|POLLHUP|POLLERR))){
                unsigned char data[1024];ssize_t n=read(s->fd,data,s->credit<sizeof(data)?s->credit:sizeof(data));
                if(n>0){s->credit-=(unsigned)n;frame('D',s->id,data,(size_t)n);}
                else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EINTR))close_session(s);
            }
        }
        while(waitpid(-1,NULL,WNOHANG)>0){}
    }
}
