// 2017.04.03
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <iconv.h>
#include <errno.h>

#include <time.h>

#define TRUE 1
#define FAULT 0

#define HTTP_PORT 80
#define MAX_BUFFER 1024 
//#define MAX_BUFFER 10000 

#define W_CHAR_SIZE 2
#define WD_CHAR_SIZE 8

// ///////////////////////////////////////////////////////////////////////////
// Connect Host Sample
// ///////////////////////////////////////////////////////////////////////////
// GET /include/paper_list.php?page=0&PY=2016&SEC=01&SD=20161213&PD=P1 HTTP/1.1\r\n
// Host: dbplus.mk.co.kr\r\n
// Accept-Encoding: text/html, deflate\r\n
// Accept: text/html\r\n
// Accept-Language: ko-kr\r\n
// ///////////////////////////////////////////////////////////////////////////
/* *************************
#define MKNEWS_HOST "dbplus.mk.co.kr"
#define MKNEWS_GET "GET %s HTTP/1.1\r\nHost: dbplus.mk.co.kr\r\nAccept-Encoding: text/html, deflate\r\nAccept: text/html\r\nAccept-Language: ko-kr\r\n\r"
* *************************/
#define MKNEWS_HOST "dart.fss.or.kr"
#define MKNEWS_GET "GET %s HTTP/1.1\r\nHost: dart.fss.or.kr\r\nAccept-Encoding: text/html, deflate\r\nAccept: text/html\r\nAccept-Language: ko-kr\r\n\r"

struct _visit
{
  char *hypertext;
  int is_visit;
  struct _visit *next;
};

int init_list(struct _visit **node)
{
  (*node)=(struct _visit *)malloc(sizeof(struct _visit));
  if((*node)==NULL)
  {
    perror("struct _visit (*node) memory alloc error");
    free((*node));
    return FAULT;
  }
  (*node)->is_visit=TRUE;
  (*node)->next=NULL;
  return TRUE;
}

int insert_node(struct _visit **node, char *href_buffer, int href_size)
{ 
  struct _visit *pIdxCtl, *plist;
  pIdxCtl=(*node);
  
  while(pIdxCtl->next!=NULL)
  { 
    if(strcmp(pIdxCtl->next->hypertext,href_buffer)==0) return FAULT;
    pIdxCtl=pIdxCtl->next;
  }
  
  plist=(struct _visit *)malloc(sizeof(struct _visit));
  if(plist==NULL)
  { 
    perror("struct _visit plist memory alloc error");
    free(plist);
    return FAULT;
  }
  plist->hypertext=(char *)malloc(href_size+1);
  if(plist->hypertext==NULL)
  { 
    perror("plist->hypertext memory alloc error");
    free(plist->hypertext);
    free(plist);
    return FAULT;
  }
  memset(plist->hypertext,0x00,href_size+1);
  if((memcpy(plist->hypertext,href_buffer,href_size))==NULL)
  { 
    perror("plist->hypertext memory copy error");
    free(plist->hypertext);
    free(plist);
    return FAULT;
  }
  plist->is_visit=FAULT;
  plist->next=NULL;
  pIdxCtl->next=plist;
  return TRUE;
}

void print_list(struct _visit *node)
{ 
  struct _visit *pIdxCtl;
  pIdxCtl=node->next;
  
  while(pIdxCtl->next)
  { 
    printf("check point ... node\n\t[HyperText: %s]",pIdxCtl->hypertext);
    printf("\n\t[WebPage Visited Flag: %d]\n",pIdxCtl->is_visit);
    pIdxCtl=pIdxCtl->next;
  }
  printf("check point ... node\n\t[HyperText: %s]",pIdxCtl->hypertext);
  printf("\n\t[WebPage Visited Flag: %d]\n",pIdxCtl->is_visit);
}

void delete_all_list(struct _visit *node)
{
  struct _visit *pIdxCtl, *ptrDel;
  pIdxCtl=node->next;
  while(pIdxCtl)
  { 
    ptrDel=pIdxCtl;
    pIdxCtl=pIdxCtl->next;
    free(ptrDel->hypertext);
    free(ptrDel);
  }
}

void DeleteChar(char *str, char delchar)
{
  unsigned int idx=0;
  unsigned int delcnt=0;

  while(*(str+idx))
  {
    if(*(str+idx)==delchar)
    {
      delcnt++;
      idx++;
      continue;
    }
    *(str+idx-delcnt) = *(str+idx);
    idx++;
  }

  while(*(str+idx-delcnt))
  {
    *(str+idx-delcnt) = 0x00;
    idx++;
  }
}

void DeleteString(char *str, char *delstr)
{
  unsigned int idx=0;
  unsigned int delcnt=0;
  unsigned int delcntdur=0;

  while(*(str+idx))
  {
    while(*(str+idx)==*(delstr+delcnt))
    {
      delcnt++;
      idx++;
    }
    if(*(delstr+delcnt)==0x00) delcntdur+=delcnt;
    else
    {
      idx-=delcnt;
      idx++;
    }
    *(str+idx-delcntdur)=*(str+idx);
    delcnt=0;
  }
  *(str+idx-delcntdur) = 0x00;
}

int connect_server(char *hostname, int hostport)
{
  int socket_fd;
  struct sockaddr_in name;
  struct hostent *hostinfo;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  name.sin_family = AF_INET;
  hostinfo = gethostbyname(hostname);

  if(hostinfo == NULL) return 1;
  else name.sin_addr = *((struct in_addr *)hostinfo->h_addr);
  name.sin_port = htons(hostport);

  // Connect to web server.
  if(connect(socket_fd, (struct sockaddr *)&name, sizeof(struct sockaddr)) == -1)
  {
    perror("connect");
    return 1;
  }
  return socket_fd;
}

unsigned int parseHexToDecByHtml(const char *str)
{
  unsigned int val = 0;
  char c;

  while(c = *str++)
  {
    if(c == 10 || c == 13) continue;
    val <<= 4;

    if(c >= '0' && c <= '9')
    {
      val += c & 0x0F;
      continue;
    }

    c &= 0xDF;
    if(c >= 'A' && c <='F')
    {
      val += (c &0x07) + 9;
      continue;
    }

    errno = EINVAL;
    return 0;
  }

  return val;
}

/*
* 알아서 가져와.
*/
int ParseByHtml(int fd, char **vptr)
{
  char hc, c, *ptr;
  unsigned int dec = 0;
  int n, def = 1, end = 3, base = MAX_BUFFER, rc;
  int cur = 0, max = 0, del = 0;

//ptr = malloc(1);
//memset(ptr, 0x00, 1);
//max = 1;
//printf("check point ...%s\n\n", (*vptr));
//fflush(stdout);

  n = def;
  for (;;)
  {
    rc = read(fd, &c, n);
    if(rc == 1)
    {
printf("%c",c);
fflush(stdout);
      cur += 1;
      if(cur >= max)
      {
        max += base;
        (*vptr) = realloc((*vptr),max);
        memset((*vptr)+cur,0x00,base);
      }
      *((*vptr)+cur-1) = c;

      hc=c;
      hc &= 0xDF;
      if( (c >= '0' && c <= '9') || (hc >= 'A' && hc <='F') )
      {
        del += 1;
        dec <<= 4;
        if(c >= '0' && c <= '9')
          dec += c & 0x0F;
        else if(hc >= 'A' && hc <='F')
          dec += (hc &0x07) + 9;
        continue;
      }

//if((c == 13 && dec > 8000 && dec < 9000) || c == 13 && dec == 0)
//{
//printf("\ncheck point ...\n[2:%d:%c]\n[1:%d:%c]\n[0:%d:%c]",
//  *((*vptr)-(del+2)+cur), *((*vptr)-(del+2)+cur),
//  *((*vptr)-(del+1)+cur), *((*vptr)-(del+1)+cur),
//  c, c);
//fflush(stdout);
//}
      if(c == 13 && *((*vptr)-(del+2)+cur) == 10)
      {
//printf("\n\ncheck point ...%s\n\n",(*vptr));
//fflush(stdout);
        if(dec>0) n=dec;
        else if(dec==0) n=end;
        //(*vptr) -= del;
        

        if(cur+n >= max)
        {
printf("\n\ncheck point ... realloc[cur:%d][n:%d][%s]\n\n",
cur, n, (*vptr));
fflush(stdout);
          max += (base+n);
          (*vptr) = realloc((*vptr),max);
          memset((*vptr)-(del+2)+cur,0x00,(base+n+2));
        }
        read(fd, (*vptr)-(del+2)+cur, n);
        cur += (n);
        n=def;
      }
      else
      {
        n=def;
      }
      del = 0;
      dec = 0;
    }
    else if (rc == 0) break;
  }
  return cur;
}

ssize_t readn(int fd, void *vptr, size_t n)
{
  size_t nleft;
  size_t nread;
  char *ptr;

  ptr = vptr;
  nleft = n;
  while(nleft > 0)
  {
    if((nread = read(fd, ptr, nleft)) < 0)
    {
      if(errno == EINTR)
        nread = 0; // and call read() again
      else
        return (-1);
    }
    else if(nread == 0)
      break; // EOF
    nleft -= nread;
    ptr += nread;
  }
  return (n - nleft); // return >= 0
}

ssize_t readline(int fd, void *vptr, size_t maxlen)
{
  ssize_t n, rc;
  char c, *ptr;

  ptr = vptr;
  for (n = 1; n < maxlen; n++) {
    again:
      if ( (rc = read(fd, &c, 1)) == 1) {
        *ptr++ = c;
        if ( c == 10 ) break;
      } else if (rc == 0) {
          *ptr = 0;
          return (n - 1);
      } else {
          if (errno == EINTR)
            goto again;
          return (-1);
      }
    }
  *ptr = 0;
  return (n);
}

ssize_t readlinebyhtml(int fd, void *vptr, size_t maxlen)
{
  ssize_t n, rc;
  char c, *ptr;

  ptr = vptr;
  for (n = 1; n < maxlen; n++) {
    again:
      if ( (rc = read(fd, &c, 1)) == 1) {
        if ( c == 13 ) {
          n--;
          continue;
        }
        *ptr++ = c;
      } else if (rc == 0) {
          *ptr = 0;
          return (n - 1);
      } else {
          if (errno == EINTR)
            goto again;
          return (-1);
      }
    }
  *ptr = 0;
  return (n);
}

int http_readwrite(char *hostname, int hostport, char **readmsg, int *readmsg_usesize, int *readmsg_maxsize, char *writemsg, int writemsg_usesize)
{
  int socket_fd;
  ssize_t number_characters_read,number_characters_write;
  char *store_buffer, *html_buffer;
  int store_size, html_size;

  if((socket_fd=connect_server(hostname, hostport))<=1) return 1;

  // Retrieve the server's home page.
  // Send the HTTP GET command for the home page.
  number_characters_write=write(socket_fd, writemsg, writemsg_usesize);
  if(number_characters_write<=0)
  {
    perror("socket_fd write error");
    close(socket_fd);
    return 1;
  }

  store_buffer=writemsg;
  if(writemsg_usesize>=MAX_BUFFER) store_size=MAX_BUFFER;
  else store_size=writemsg_usesize;

  number_characters_read=ParseByHtml(socket_fd, &(*readmsg));
  //printf("check point ...[%d]%s",number_characters_read,(*readmsg));
  //fflush(stdout);
  //exit(0);
  return (0);

  while(1)
  {
    memset(store_buffer,0x00,store_size);
    number_characters_read=readline(socket_fd,store_buffer,store_size);
printf("check point .H.[%d]%s",number_characters_read,store_buffer);
fflush(stdout);
    if(number_characters_read<=0)
    {
      close(socket_fd);
      if(number_characters_read==-1)
      {
        perror("socket_fd read error");
        return 1;
      }
      break; //end of socket
    }
    else if(number_characters_read>2 && number_characters_read<7)
    {
      html_size = parseHexToDecByHtml(store_buffer);
      html_buffer = (char *)malloc(html_size);
printf("check point 1N.[%d]\n",html_size);
fflush(stdout);
      memset(html_buffer,0x00,html_size);

      memset(store_buffer,0x00,store_size);
      read(socket_fd,store_buffer,2);
printf("check point 2N.%s",store_buffer);
fflush(stdout);
      break;
    }
  }

  while(1)
  {
    memset(html_buffer,0x00,html_size);
    number_characters_read=readn(socket_fd,html_buffer,html_size);
printf("check point .B.[%d]%s",number_characters_read,html_buffer);
fflush(stdout);
    if(number_characters_read<=0)
    {
      close(socket_fd);
      if(number_characters_read==-1)
      {
        perror("socket_fd read error");
        return 1;
      }
      break; //end of socket
    }

    if(((*readmsg_usesize)+number_characters_read)>=(*readmsg_maxsize))
    {
      (*readmsg_maxsize)+=html_size;
      (*readmsg)=realloc((*readmsg),(*readmsg_maxsize));
      if((*readmsg)==NULL)
      {
        perror("conf_file memory alloc error");
        free((*readmsg));
        close(socket_fd);
        return 1;
      }
      memset((*readmsg)+(*readmsg_usesize),0x00,html_size);
    }

    memcpy((*readmsg)+(*readmsg_usesize),store_buffer,number_characters_read);
    (*readmsg_usesize)+=number_characters_read;
    break;
  }

  // Receive the HTTP ACK for the home page.
  while(1)
  {
    memset(store_buffer,0x00,store_size);
    number_characters_read=readline(socket_fd,store_buffer,store_size);
printf("check point .C.[%d]%s",number_characters_read,store_buffer);
fflush(stdout);
    if(number_characters_read<=0)
    {
      close(socket_fd);
      if(number_characters_read==-1)
      {
        perror("socket_fd read error");
        return 1;
      }
      break; //end of socket
    }
    else if(number_characters_read>1 && number_characters_read<6)
    {
printf("check point .n.[%d]%s",parseHexToDecByHtml(store_buffer),store_buffer);
fflush(stdout);
    }

    if(((*readmsg_usesize)+number_characters_read)>=(*readmsg_maxsize))
    {
      (*readmsg_maxsize)+=store_size;
      (*readmsg)=realloc((*readmsg),(*readmsg_maxsize));
      if((*readmsg)==NULL)
      {
        perror("conf_file memory alloc error");
        free((*readmsg));
        close(socket_fd);
        return 1;
      }
      memset((*readmsg)+(*readmsg_usesize),0x00,store_size);
    }

    memcpy((*readmsg)+(*readmsg_usesize),store_buffer,number_characters_read);
    (*readmsg_usesize)+=number_characters_read;
  }
  return 0;
}

int euckrtoutf8(char *instring, char **outstring)
{
  iconv_t cd;
  char w_ch;
  char inbuf[W_CHAR_SIZE], outbuf[WD_CHAR_SIZE];
  char *ptrin, *ptrout, *pstrhead, *pstrtail;
  int outstring_idx=0, sizecpy=0;
  size_t sizein, sizeout, sizeconv;

  if(*instring=='\0') return 1;

  cd=iconv_open("UTF-8","EUC-KR");
  if(cd==(iconv_t) -1)
  {
    /* Something went wrong.  */
    if (errno == EINVAL)
      error (0, 0, "conversion from EUC-KR to UTF-8 not available");
    else perror ("iconv_open");

    /* Terminate the output string.  */
    *outstring = '\0';

    return 1;
  }

  w_ch=*instring;

  while(w_ch!='\0')
  {
    if(w_ch<0x80)
    {
      instring++;
      *((*outstring)+outstring_idx)=w_ch;
      outstring_idx+=1;

      w_ch=*instring;
    }
    else if(w_ch<0x800)
    {
      instring++;
      inbuf[0]=w_ch;

      w_ch=*instring;
      instring++;
      inbuf[1]=w_ch;

      //printf("check point ... -2-1\n\n[%x][%x][%s]\n",
      //  inbuf[0],inbuf[1],inbuf);

      w_ch=*instring;

      ptrin=inbuf;
      ptrout=outbuf;
      sizein=W_CHAR_SIZE;
      sizeout=WD_CHAR_SIZE;

      sizeconv=iconv(cd,&ptrin,&sizein,&ptrout,&sizeout);
      if (sizeconv==(size_t) -1)
      { 
        // Not everything went right.  It might only be
        // an unfinished byte sequence at the end of the
        // buffer.  Or it is a real problem.
        if (errno == EINVAL)  
        // This is harmless.  Simply move the unused
        // bytes to the beginning of the buffer so that
        // they can be used in the next round.
          perror("errno EINVAL. iconv error");
        else
        { 
          // It is a real problem.  Maybe we ran out of
          // space in the output buffer or we have invalid
          // input.  In any case back the file pointer to
          // the position of the last processed byte.
          perror("etc. iconv error");
          break;
        }
      }
      sizecpy=WD_CHAR_SIZE-sizeout;

      //printf("check point ... -2-2:[R:%d]\n\n[%s][I:%d][O:%d][L:%d]\n",
      //  sizeconv, outbuf, sizein, sizeout, strlen(outbuf));
      memcpy(((*outstring)+outstring_idx),outbuf,sizecpy);
      outstring_idx+=sizecpy;
    }
    else
    { 
      printf("\n\nUnknow Condition Logic Loop...\n\n");
      instring++;
      w_ch=*instring;
      
    }
  }
  *((*outstring)+outstring_idx)=w_ch;

  if(iconv_close(cd)!=0)
  {
    perror("iconv_close error");
    return 1;
  }
  return 0;
}

int main(int argc, char *argv[]) 
{
  int socket_fd, fd;
  struct sockaddr_in name;
  struct hostent *hostinfo;
  struct _visit *pvisit, *plist, *pIdxCtl, *is_visited;

  char *store_buffer, *getmsg_buffer;
  char *pMem, *memory_buffer, *pTagStore;
  char *search_excption, *search_tag, *search_tag_head, *search_tag_tail,
       *href_head, *href_tail, *href_mid_head, *href_mid_tail;
  int iMaxMemSize, number_memory_size, number_tag_size, 
      href_size, href_mid_size, flag_text;

  time_t timer;
  struct tm *tinfo;

  getmsg_buffer=(char *)malloc(MAX_BUFFER);
  if(getmsg_buffer==NULL)
  {
    perror("getmsg_buffer memory alloc error");
    free(getmsg_buffer);
    return 1;
  }
  memset(getmsg_buffer,0x00,MAX_BUFFER);

  store_buffer=(char *)malloc(MAX_BUFFER);
  if(store_buffer==NULL)
  {
    perror("store_buffer memory alloc error");
    free(store_buffer);
    return 1;
  }
  memset(store_buffer,0x00,MAX_BUFFER);

  //strcpy(getmsg_buffer,
  //  "/include/paper_list.php?page=0&PY=2016&SEC=01&SD=20161213&PD=P1");
  switch(argc)
  {
    case 3:
      sprintf(getmsg_buffer,
        "/include/paper_list.php?page=0&PY=%s&SEC=01&SD=%s&PD=P1",
        argv[1],argv[2]);
      sprintf(store_buffer,"/home/pi/Project/log/mknewspaper_%s.html",
        argv[2]);
      break;
    default:
      timer=time(NULL);
      tinfo=localtime(&timer);
      sprintf(getmsg_buffer,
//        "/dsaf001/main.do?rcpNo=20161129000214");
        "/dsaf001/main.do?rcpNo=20170227000188");
      sprintf(store_buffer,
        "/home/pi/Project/log/dartpage_%04d%02d%02d.html",
        tinfo->tm_year+1900,tinfo->tm_mon+1,tinfo->tm_mday);
      break;
  }
  fd=open(store_buffer,O_WRONLY|O_CREAT|O_EXCL,0644);
  if(fd==-1)
  {
    perror("fd_store_file");
    return -1;
  }

  // Retrieve the server's home page.
  // Send the HTTP GET command for the home page.
  memset(store_buffer,0x00,MAX_BUFFER);
  sprintf(store_buffer,MKNEWS_GET,getmsg_buffer);

  // Receive the HTTP ACK for the home page.
  pMem=NULL;
  pMem=(char *)malloc(1);
  if(pMem==NULL)
  {
    perror("struct _visit pMem memory alloc error");
    free(pMem);
    return 1;
  }
  memset(pMem,0x00,1);

  iMaxMemSize=1;
  number_memory_size=0;

  http_readwrite(MKNEWS_HOST, HTTP_PORT, &pMem, &number_memory_size, &iMaxMemSize, store_buffer, strlen(store_buffer));
  printf("check point ...%s",pMem);
  fflush(stdout);

  exit(0);
  number_tag_size=iMaxMemSize;
  pTagStore=NULL;
  pTagStore=realloc(pTagStore,number_tag_size);
  if(pTagStore==NULL)
  {
    perror("TagStore memory alloc error");
    free(pTagStore);
    return 1;
  }

  pvisit=NULL;
  if((init_list(&pvisit))==FAULT) exit(0);

  memory_buffer=pMem;
  do
  {
    search_tag=NULL;
    search_tag_head=NULL;
    search_tag_tail=NULL;

    if((search_tag_head=strstr(memory_buffer,"<a href"))==NULL) break;
    search_tag=search_tag_head;
    search_tag_tail=strstr(search_tag,"</a>");
    search_excption=strstr(search_tag,"</td>");

    if(search_tag_head!=NULL && search_tag_tail!=NULL)
    {
      memory_buffer=search_tag_tail;
      memset(pTagStore,0x00,number_tag_size);

      if(search_tag_tail<search_excption)
        strncpy(pTagStore,search_tag_head,search_tag_tail-search_tag_head);
      else
      {
        memory_buffer=search_excption;
        strncpy(pTagStore,search_tag_head,search_excption-search_tag_head);
      }
      //printf("check point ... 01\n\n%s\n",pTagStore);

      href_head=pTagStore+9;
      href_tail=strstr(href_head,"'");
      href_size=href_tail-href_head;
      memset(store_buffer,0x00,MAX_BUFFER);
      strncpy(store_buffer,href_head,href_size);
      //printf("check point ... 02\n\n%s\n",store_buffer);

      insert_node(&pvisit, store_buffer, href_size);
    }

    memory_buffer++;
  } while(*memory_buffer) ;

  //printf("check point ... 03\n\n");
  //print_list(pvisit);

  is_visited=pvisit->next;
  while(1)
  {
    if(is_visited->next != NULL)
    {
      plist=is_visited->next;
      is_visited=is_visited->next;
    }
    else break;

    memset(store_buffer,0x00,MAX_BUFFER);
    memset(getmsg_buffer,0x00,MAX_BUFFER);
    if((strstr(plist->hypertext,"?page="))!=NULL)
    {
      // ?page=1&PY=2016&SEC=01&SD=20161213&PD=P1
      sprintf(getmsg_buffer,"/include/paper_list.php%s",plist->hypertext);
      sprintf(store_buffer,MKNEWS_GET,getmsg_buffer);
      plist->is_visit=TRUE;
      //printf("check point .... page\n\n[%s]\n",plist->hypertext);
    }
    else if((strstr(plist->hypertext,"http://"))!=NULL)
    {
      plist->is_visit=TRUE;
      continue;
    }
    else if((strstr(plist->hypertext,"/include/paper_list.php"))!=NULL)
    {
      // /include/paper_list.php?PY=2016&SEC=01&SD=20161213&PD=P4
      sprintf(store_buffer,MKNEWS_GET,plist->hypertext);
      plist->is_visit=TRUE;
      //printf("check point .... include\n\n[%s]\n",plist->hypertext);
    }

    memset(pMem,0x00,iMaxMemSize);
    number_memory_size=0;

    //printf("check point ... Visit\n\n%s\n\n",store_buffer);
    http_readwrite(MKNEWS_HOST, HTTP_PORT, &pMem, &number_memory_size, &iMaxMemSize, store_buffer, strlen(store_buffer));

    if(iMaxMemSize>number_tag_size)
    {
      number_tag_size=iMaxMemSize;
      pTagStore=realloc(pTagStore,number_tag_size);
      if(pTagStore==NULL)
      { 
        perror("TagStore memory alloc error");
        free(pTagStore);
        return 1;
      }
    }

    memory_buffer=pMem;
    do
    { 
      search_tag=NULL;
      search_tag_head=NULL;
      search_tag_tail=NULL;
    
      if((search_tag_head=strstr(memory_buffer,"<a href"))==NULL) break;
      search_tag=search_tag_head;
      search_tag_tail=strstr(search_tag,"</a>");
      search_excption=strstr(search_tag,"</td>");
    
      if(search_tag_head!=NULL && search_tag_tail!=NULL)
      { 
        memory_buffer=search_tag_tail;
        memset(pTagStore,0x00,number_tag_size);

        if(search_tag_tail<search_excption)
          strncpy(pTagStore,search_tag_head,search_tag_tail-search_tag_head);
        else
        { 
          memory_buffer=search_excption;
          strncpy(pTagStore,search_tag_head,search_excption-search_tag_head);
        }
        //printf("check point ... 04\n\n%s\n",pTagStore);
      
        href_head=pTagStore+9;
        href_tail=strstr(href_head,"'");
        href_size=href_tail-href_head;
        memset(store_buffer,0x00,MAX_BUFFER);
        strncpy(store_buffer,href_head,href_size);
        //printf("check point ... 05\n\n%s\n",store_buffer);

        insert_node(&pvisit, store_buffer, href_size);
      }
    
      memory_buffer++;
    } while(*memory_buffer) ;
  }

  //printf("check point ... 06\n\n");
  //print_list(pvisit);
  pIdxCtl=pvisit->next;

  memset(store_buffer,0x00,MAX_BUFFER);
  switch(argc)
  {
    case 3:
      sprintf(store_buffer,"/home/pi/Project/log/mknewspaper_%s.html",argv[2]);
      break;
    default:
      sprintf(store_buffer,
        "/home/pi/Project/log/mknewspaper_%04d%02d%02d.html",
        tinfo->tm_year+1900,tinfo->tm_mon+1,tinfo->tm_mday);
      break;
  }

  while(pIdxCtl->next)
  {
    plist=pIdxCtl;
    if((strstr(plist->hypertext,"http://"))!=NULL)
    {
      // 01234567890123456789012345
      // http://dbplus.mk.co.kr/index.php?MM=V
      memset(store_buffer,0x00,MAX_BUFFER);
      sprintf(store_buffer,MKNEWS_GET,(plist->hypertext)+22);
    }
    else
    {
      pIdxCtl=pIdxCtl->next;
      continue;
    }

    memset(pMem,0x00,iMaxMemSize);
    number_memory_size=0;
    //printf("check point ... Visit\n\n%s\n\n",store_buffer);

    http_readwrite(MKNEWS_HOST, HTTP_PORT, &pMem, &number_memory_size, &iMaxMemSize, store_buffer, strlen(store_buffer));

    write(fd,pMem,number_memory_size);
    DeleteChar(pMem,9);
    DeleteChar(pMem,10);
    DeleteChar(pMem,13);

    if((iMaxMemSize*4)>number_tag_size)
    { 
      number_tag_size=(iMaxMemSize*4);
      pTagStore=realloc(pTagStore,number_tag_size);
      if(pTagStore==NULL)
      { 
        perror("TagStore memory alloc error");
        free(pTagStore);
        return 1;
      }
    }
    memset(pTagStore,0x00,number_tag_size);

    euckrtoutf8(pMem, &pTagStore);
    //printf("check point ... 01[%d]\n\n%s\n",rtn, pTagStore);

    search_tag=NULL;
    search_tag_head=NULL;

    // NewsPaper Parsing: Title Main
    if((search_tag_head=strstr(pTagStore,"'head_tit'>"))!=NULL)
    {
      search_tag=search_tag_head;

      href_head=NULL;
      href_tail=NULL;
      href_size=0;

      // 012345678901234567890123
      // 'head_tit'>
      href_head=search_tag+11;
      href_tail=strstr(href_head,"</span>");
      href_size=href_tail-href_head;
      memset(pMem,0x00,iMaxMemSize);
      strncpy(pMem,href_head,href_size);
      //printf("check point ... 02\n\n[%s]\n",pMem);
      DeleteString(pMem,"<br>");
      printf("\n%s%c",pMem,13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: Title Subs
      if((search_tag_head=strstr(search_tag,"'sub_tit'>"))!=NULL)
      {
        search_tag=search_tag_head;

        href_head=NULL;
        href_tail=NULL;
        href_size=0;

        // 01234567890123456789012
        // 'sub_tit'>
        href_head=search_tag+10;
        href_tail=strstr(href_head,"</span>");
        href_size=href_tail-href_head;
        memset(pMem,0x00,iMaxMemSize);
        strncpy(pMem,href_head,href_size);
        //printf("check point ... 02\n\n\t[%s]\n",pMem);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);
      }
      else printf("%c",13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: News Writing Time 1st.
      if((search_tag_head=strstr(search_tag,"'sm_tit'>"))!=NULL)
      {
        search_tag=search_tag_head;

        href_head=NULL;
        href_tail=NULL;
        href_size=0;

        // 01234567890123456789012
        // 'sm_tit'>
        href_head=search_tag+9;
        href_tail=strstr(href_head,"</span>");
        href_size=href_tail-href_head;
        memset(pMem,0x00,iMaxMemSize);
        strncpy(pMem,href_head,href_size);
        //printf("check point ... 02\n\n\t[%s]\n",pMem);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);
      }
      else printf("%c",13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: News Writing Time 2st.
      if((search_tag_head=strstr(search_tag,"'sm_num'>"))!=NULL)
      {
        search_tag=search_tag_head;

        href_head=NULL;
        href_tail=NULL;
        href_size=0;

        // 01234567890123456789012
        // 'sm_num'>
        href_head=search_tag+9;
        href_tail=strstr(href_head,"</span>");
        href_size=href_tail-href_head;
        memset(pMem,0x00,iMaxMemSize);
        strncpy(pMem,href_head,href_size);
        //printf("check point ... 02\n\n\t[%s]\n",pMem);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);
      }
      else printf("%c",13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: News Writing Time 3st.
      if((search_tag_head=strstr(search_tag,"'sm_tit'>"))!=NULL)
      {
        search_tag=search_tag_head;

        href_head=NULL;
        href_tail=NULL;
        href_size=0;

        // 01234567890123456789012
        // 'sm_tit'>
        href_head=search_tag+9;
        href_tail=strstr(href_head,"</span>");
        href_size=href_tail-href_head;
        memset(pMem,0x00,iMaxMemSize);
        strncpy(pMem,href_head,href_size);
        //printf("check point ... 02\n\n\t[%s]\n",pMem);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);
      }
      else printf("%c",13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: News Writing Time 4st.
      if((search_tag_head=strstr(search_tag,"'sm_num'>"))!=NULL)
      {
        search_tag=search_tag_head;

        href_head=NULL;
        href_tail=NULL;
        href_size=0;

        // 01234567890123456789012
        // 'sm_num'>
        href_head=search_tag+9;
        href_tail=strstr(href_head,"</span>");
        href_size=href_tail-href_head;
        memset(pMem,0x00,iMaxMemSize);
        strncpy(pMem,href_head,href_size);
        //printf("check point ... 02\n\n\t[%s]\n",pMem);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);
      }
      else printf("%c",13);

      // 01234567
      // </span>
      search_tag=href_tail+7;
      search_tag_head=NULL;

      // NewsPaper Parsing: Main Text 1st.
      if((search_tag_head=strstr(search_tag,"'read_txt'>"))!=NULL)
      {
        href_head=NULL;
        href_tail=NULL;
        href_mid_head=NULL;
        href_mid_tail=NULL;
        href_size=0;
        href_mid_size=0;

        // 01234567890123456789012
        // 'read_txt'>
        search_tag=search_tag_head+11;
        href_head=search_tag;
        flag_text=1;

        while(flag_text)
        {
          search_tag_head=strstr(search_tag,"<div ");
          search_tag_tail=strstr(search_tag,"</div>");

          if(search_tag_head<search_tag_tail)
          {
            if(flag_text==1) href_mid_tail=search_tag_head;
            //  012345
            // '<div '
            search_tag=search_tag_head+5;
            flag_text+=1;
          }
          else if(search_tag_head>search_tag_tail)
          {
            //  0123456
            // '</div>'
            search_tag=search_tag_tail+6;
            flag_text-=1;
            if(flag_text==1) href_mid_head=search_tag_tail+6;
          }
        }
        //  0123456
        // '</div>'
        href_tail=search_tag-6;
        memset(pMem,0x00,iMaxMemSize);
        if(href_mid_head!=NULL && href_mid_tail!=NULL)
        {
          href_mid_size=href_mid_tail-href_head;
          strncpy(pMem,href_head,href_mid_size);

          href_size=href_tail-href_mid_head;
          strncpy(pMem+href_mid_size,href_mid_head,href_size);
        }
        else
        {
          href_size=href_tail-href_head;
          strncpy(pMem,href_head,href_size);
        }
        //printf("check point ... 02\n\n\t[%s][%d]\n",pMem, href_size);
        DeleteString(pMem,"<br>");
        printf("%s%c",pMem,13);


        // 01234567
        // </div>
        search_tag=href_tail+6;
        search_tag_head=NULL;

        // NewsPaper Parsing: Main Text 2st.
        if((search_tag_head=strstr(search_tag,"'read_txt'>"))!=NULL)
        {
          href_head=NULL;
          href_tail=NULL;
          href_mid_head=NULL;
          href_mid_tail=NULL;
          href_size=0;
          href_mid_size=0;

          // 01234567890123456789012
          // 'read_txt'>
          search_tag=search_tag_head+11;
          href_head=search_tag;
          flag_text=1;

          while(flag_text)
          {
            search_tag_head=strstr(search_tag,"<div ");
            search_tag_tail=strstr(search_tag,"</div>");

            if(search_tag_head<search_tag_tail)
            {
              if(flag_text==1) href_mid_tail=search_tag_head;
              //  012345
              // '<div '
              search_tag=search_tag_head+5;
              flag_text+=1;
            }
            else if(search_tag_head>search_tag_tail)
            {
              //  0123456
              // '</div>'
              search_tag=search_tag_tail+6;
              flag_text-=1;
              if(flag_text==1) href_mid_head=search_tag_tail+6;
            }
          }
          //  0123456
          // '</div>'
          href_tail=search_tag-6;
          memset(pMem,0x00,iMaxMemSize);
          if(href_mid_head!=NULL && href_mid_tail!=NULL)
          {
            href_mid_size=href_mid_tail-href_head;
            strncpy(pMem,href_head,href_mid_size);

            href_size=href_tail-href_mid_head;
            strncpy(pMem+href_mid_size,href_mid_head,href_size);
          }
          else
          {
            href_size=href_tail-href_head;
            strncpy(pMem,href_head,href_size);
          }
          //printf("check point ... 02\n\n\t[%s][%d]\n",pMem, href_size);
          DeleteString(pMem,"<br>");
          printf("%s%c",pMem,13);
        }
        else printf("%c",13);
      }
    }
    pIdxCtl=pIdxCtl->next;
  }
  free(pMem);
  free(pTagStore);
  free(store_buffer);
  delete_all_list(pvisit);
}
