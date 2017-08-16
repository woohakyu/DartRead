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

#include <libxml/xmlreader.h>

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
struct _dart_api
{
  char *crp_cls;
  char *crp_nm;
  char *crp_cd;
  char *rpt_nm;
  char *rcp_no;
  char *flr_nm;
  char *rcp_dt;
  char *rmk;
};

struct _list_dart_api
{
  char *crp_cls;
  char *crp_nm;
  char *crp_cd;
  char *rpt_nm;
  char *rcp_no;
  char *flr_nm;
  char *rcp_dt;
  char *rmk;
  struct _list_dart_api *next;
};

int setvalue(void **p, void *v, unsigned int l)
{
  void *prtn;

  printf("check point ... setvalue.1[%s][%d]\n",v,l);
  (*p) =(char *) malloc(l+1);
  if((*p) == NULL )
  {
    perror("func setvalue: memory alloc error");
    free((*p));
    return FAULT;
  }
  memset((*p), 0x00, l+1);
  prtn = memcpy((*p), v, l);

  printf("check point ... setvalue.2[%s][%s]\n",prtn,(*p));
  if(prtn == NULL) return FAULT;
  else return TRUE;
}

int init_list(struct _list_dart_api **node)
{
  (*node) = (struct _list_dart_api *) malloc(sizeof(struct _list_dart_api));
  if((*node) == NULL)
  {
    perror("struct _list (*node) memory alloc error");
    free((*node));
    return FAULT;
  }
  (*node)->next = NULL;
  return TRUE;
}

int insert_node(struct _list_dart_api **node, struct _dart_api *ptr)
{
  struct _list_dart_api *pIdxCtl, *plist;
  pIdxCtl = (*node);

  //while((*node)->next != NULL) {(*node) = (*node)->next;printf("check point ...insert_node.01 while\n");}
  while(pIdxCtl->next != NULL) {pIdxCtl = pIdxCtl->next;printf("check point ...insert_node.01 while\n");}

  plist = (struct _list_dart_api *)malloc(sizeof(struct _list_dart_api));
  if(plist == NULL)
  {
    perror("struct _list plist memory alloc error");
    free(plist);
    return FAULT;
  }

  // after func point modify.
  plist->crp_cls = malloc(strlen(ptr->crp_cls)+1);
  memset(plist->crp_cls, 0x00, strlen(ptr->crp_cls)+1);
  memcpy(plist->crp_cls, ptr->crp_cls, strlen(ptr->crp_cls));

  plist->crp_nm = malloc(strlen(ptr->crp_nm)+1);
  memset(plist->crp_nm, 0x00, strlen(ptr->crp_nm)+1);
  memcpy(plist->crp_nm, ptr->crp_nm, strlen(ptr->crp_nm));

  plist->crp_cd = malloc(strlen(ptr->crp_cd)+1);
  memset(plist->crp_cd, 0x00, strlen(ptr->crp_cd)+1);
  memcpy(plist->crp_cd, ptr->crp_cd, strlen(ptr->crp_cd));

  plist->rpt_nm = malloc(strlen(ptr->rpt_nm)+1);
  memset(plist->rpt_nm, 0x00, strlen(ptr->rpt_nm)+1);
  memcpy(plist->rpt_nm, ptr->rpt_nm, strlen(ptr->rpt_nm));

  plist->rcp_no = malloc(strlen(ptr->rcp_no)+1);
  memset(plist->rcp_no, 0x00, strlen(ptr->rcp_no)+1);
  memcpy(plist->rcp_no, ptr->rcp_no, strlen(ptr->rcp_no));

  plist->flr_nm = malloc(strlen(ptr->flr_nm)+1);
  memset(plist->flr_nm, 0x00, strlen(ptr->flr_nm)+1);
  memcpy(plist->flr_nm, ptr->flr_nm, strlen(ptr->flr_nm));

  plist->rcp_dt = malloc(strlen(ptr->rcp_dt)+1);
  memset(plist->rcp_dt, 0x00, strlen(ptr->rcp_dt)+1);
  memcpy(plist->rcp_dt, ptr->rcp_dt, strlen(ptr->rcp_dt));

  plist->rmk = malloc(strlen(ptr->rmk)+1);
  memset(plist->rmk, 0x00, strlen(ptr->rmk)+1);
  memcpy(plist->rmk, ptr->rmk, strlen(ptr->rmk));

  plist->next=NULL;
  //(*node)->next=plist;
  (pIdxCtl)->next=plist;

  return TRUE;
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

int SetValue(char **ps, char *pv, int *ns)
{
  int nv, nc, nb;

  nc = (*ns);
  nv = 0;
  while(*(pv + nv)) nv += 1;
  
  if(nv >= (*ns))
  {
    (*ns) += nb;
    (*ps) = realloc((*ps), (*ns));
    memset((*ps) + nc, 0x00, nb);
  }

  if(memcpy((*ps),pv,nv)) return (*ns);
  return 0;
}

/*
* 알아서 가져와.
*/
int ParseByHtml(int fd, char **vptr, int *pmax)
{
  char c;
  unsigned int dec = 0;
  int base, rc, cur = 0, is_a_num = 0, is_a_txt = 0;

  base = MAX_BUFFER;
  for(;;)
  {
    rc = read(fd, &c, 1);
    if(rc == 1)
    {
      if(cur >= (*pmax))
      {
        (*pmax) += base;
        (*vptr) = realloc((*vptr),(*pmax));
        memset((*vptr)+cur,0x00,base);
      }
      *((*vptr)+(cur++)) = c;

      if(c == 13 || c == 10)
      {
        if(is_a_txt == is_a_num && is_a_num > 0)
        {
          rc = read(fd, &c, 1); // is read ascii '10';; dummy clear
          if(dec > 0)
          {
            base = dec;
            if(cur+dec >= (*pmax))
            {
              (*pmax) += base;
              (*vptr) = realloc((*vptr),(*pmax));
              memset((*vptr)+cur,0x00,base);
            }
            rc = readn(fd, (*vptr)+cur-3-is_a_num, base);
            base = MAX_BUFFER;
            cur += (rc-3-is_a_num);
          }
          else if(dec == 0)
          {
            memset((*vptr)+cur-3-is_a_num, 0x00, (*pmax)-(cur-3-is_a_num));
            break;
          }
        }

        is_a_num = 0;
        is_a_txt = 0;
        dec = 0;
        continue;
      }

      is_a_txt += 1;

      if((c >= '0' && c <= '9') ||
        (c >= 'A' && c <='F') || (c >= 'a' && c <='f'))
      {
        is_a_num += 1;

        dec <<= 4;
        if(c >= '0' && c <= '9')
        {
          dec += c & 0x0F;
        }
        else if((c >= 'A' && c <='F') || (c >= 'a' && c <='f'))
        {
          if(c >= 'a' && c <='f') c &= 0xDF;
          dec += (c & 0x07) + 9;
        }
        continue;
      }

      is_a_num = 0;
      dec = 0;
    }
  }

  return cur;
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

int GetDartApi(char **readmsg, int *readmsg_usesize)
{
  int socket_fd;
  ssize_t number_characters_read,number_characters_write;
  //char *store_buffer, *html_buffer;
  //int store_size, html_size;

  char *HOSTNAME = "dart.fss.or.kr";
  int HOSTPORT = 80;
  
  char ReqURL[1000];
  char ReqWrite[1000];

  char *DARTAUTHKEY = "d58011d7473b0d0f7bf602538ed3f17918fed9c9";
  char *crp_cd = "009540";
  char *end_dt = "20170515";
  char *start_dt = "20170515";
  char *fin_rpt = "";
  char *dsp_tp = "";
  char *bsn_tp = "";
  char *sort = "";
  char *series = "";
  char *page_no = "";
  char *page_set = "";

  sprintf(ReqURL,"/api/search.xml?auth=%s",DARTAUTHKEY);
  if(strlen(crp_cd)>=0)
    sprintf(ReqURL,"%s&crp_cd=%s",ReqURL,crp_cd);
  if(strlen(end_dt)>=0)
    sprintf(ReqURL,"%s&end_dt=%s",ReqURL,end_dt);
  if(strlen(start_dt)>=0)
    sprintf(ReqURL,"%s&start_dt=%s",ReqURL,start_dt);
  if(strlen(fin_rpt)>=0)
    sprintf(ReqURL,"%s&fin_rpt=%s",ReqURL,fin_rpt);
  if(strlen(dsp_tp)>=0)
    sprintf(ReqURL,"%s&dsp_tp=%s",ReqURL,dsp_tp);
  if(strlen(bsn_tp)>=0)
    sprintf(ReqURL,"%s&bsn_tp=%s",ReqURL,bsn_tp);
  if(strlen(sort)>=0)
    sprintf(ReqURL,"%s&sort=%s",ReqURL,sort);
  if(strlen(series)>=0)
    sprintf(ReqURL,"%s&series=%s",ReqURL,series);
  if(strlen(page_no)>=0)
    sprintf(ReqURL,"%s&page_no=%s",ReqURL,page_no);
  if(strlen(page_set)>=0)
    sprintf(ReqURL,"%s&page_set=%s",ReqURL,page_set);

  sprintf(ReqWrite,"GET %s HTTP/1.1\r\nHost: dart.fss.or.kr\r\nAccept-Encoding: text/html, deflate\r\nAccept: text/html\r\nAccept-Language: ko-kr\r\n\r",ReqURL);

  if((socket_fd=connect_server(HOSTNAME, HOSTPORT))<=1) return 1;

  // Retrieve the server's home page.
  // Send the HTTP GET command for the home page.
  number_characters_write=write(socket_fd, ReqWrite, strlen(ReqWrite));
  if(number_characters_write<=0)
  {
    perror("socket_fd write error");
    close(socket_fd);
    return 1;
  }

  number_characters_read=ParseByHtml(socket_fd, &(*readmsg), readmsg_usesize);
  close(socket_fd);
  return number_characters_read;
}

void parseStory(struct _dart_api **stVal, xmlDocPtr doc, xmlNodePtr cur)
{
  xmlChar *key;
  int size, rtn;

  cur = cur->xmlChildrenNode;
  (*stVal) = (struct _dart_api *)malloc(sizeof(struct _dart_api));
  if((*stVal) == NULL)
  {
    perror("_dart_result memory alloc error");
    free(stVal);
  }

  while(cur != NULL)
  {
    if(!xmlStrcmp(cur->name, (const xmlChar *) "crp_cls"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->crp_cls),(char *)key, size);
      (*stVal)->crp_cls = malloc(size + 1);
      memset((*stVal)->crp_cls, 0x00, size + 1);
      memcpy((*stVal)->crp_cls, key, size);
      //printf("crp_cls: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "crp_nm"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->crp_nm),(char *)key, size);
      (*stVal)->crp_nm = malloc(size + 1);
      memset((*stVal)->crp_nm, 0x00, size + 1);
      memcpy((*stVal)->crp_nm, key, size);
      //printf("crp_nm: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "crp_cd"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->crp_cd),(char *)key, size);
      (*stVal)->crp_cd = malloc(size + 1);
      memset((*stVal)->crp_cd, 0x00, size + 1);
      memcpy((*stVal)->crp_cd, key, size);
      //printf("crp_cd: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "rpt_nm"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->rpt_nm),(char *)key, size);
      (*stVal)->rpt_nm = malloc(size + 1);
      memset((*stVal)->rpt_nm, 0x00, size + 1);
      memcpy((*stVal)->rpt_nm, key, size);
      //printf("rpt_nm: [%d]%s\n", size,key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "rcp_no"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->rcp_no),(char *)key, size);
      (*stVal)->rcp_no = malloc(size + 1);
      memset((*stVal)->rcp_no, 0x00, size + 1);
      memcpy((*stVal)->rcp_no, key, size);
      //printf("rcp_no: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "flr_nm"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->flr_nm),(char *)key, size);
      (*stVal)->flr_nm = malloc(size + 1);
      memset((*stVal)->flr_nm, 0x00, size + 1);
      memcpy((*stVal)->flr_nm, key, size);
      //printf("flr_nm: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "rcp_dt"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->rcp_dt),(char *)key, size);
      (*stVal)->rcp_dt = malloc(size + 1);
      memset((*stVal)->rcp_dt, 0x00, size + 1);
      memcpy((*stVal)->rcp_dt, key, size);
      //printf("rcp_dt: [%d]%s\n", size, key);
      xmlFree(key);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar *) "rmk"))
    {
      key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
      size = xmlStrlen(key);
      //rtn = setvalue((void *)&((*stVal)->rmk),(char *)key, size);
      (*stVal)->rmk = malloc(size + 1);
      memset((*stVal)->rmk, 0x00, size + 1);
      memcpy((*stVal)->rmk, key, size);
      //printf("rmk: [%d]%s\n", size, key);
      xmlFree(key);
    }
    cur = cur->next;
  }
  return;
}

static void parseDoc(struct _list_dart_api **node, char *buffer, int size)
{
  xmlDocPtr doc;
  xmlNodePtr cur;
  xmlChar *key;

  struct _dart_api *stVal;

  doc = xmlParseMemory(buffer, size);
  if(doc == NULL)
  {
    fprintf(stderr,"Document not parsed successfully. \n");
    return;
  }

  cur = xmlDocGetRootElement(doc);
  if(cur == NULL)
  {
    fprintf(stderr,"empty document\n");
    xmlFreeDoc(doc);
    return;
  }

  if(xmlStrcmp(cur->name, (const xmlChar *) "result"))
  {
    fprintf(stderr,"document of the wrong type, root node != result");
    xmlFreeDoc(doc);
    return;
  }
  cur = cur->xmlChildrenNode;
  if(!xmlStrcmp(cur->name, (const xmlChar *) "err_code"))
  {
    key = xmlNodeListGetString(doc, cur->xmlChildrenNode,1);
    if(strcmp(key,"000")!=0) return;
  }
/*
  err_code
  err_msg
  page_set
  total_count
  total_page
*/

  while(cur != NULL)
  {
    if((!xmlStrcmp(cur->name, (const xmlChar *) "list")))
    {
      parseStory(&stVal, doc, cur);
      insert_node(node, stVal);

      printf("check point ... parseDoc.1[%s][%s]\n"
        ,stVal->crp_cls, stVal->crp_nm);

      printf("check point ... parseDoc..\n");
      printf("check point ... parseDoc.2[%s][%s]\n",
        (*node)->crp_cls,
        (*node)->crp_nm
      );

      free(stVal->crp_cls);
      free(stVal->crp_nm);
      free(stVal->crp_cd);
      free(stVal->rpt_nm);
      free(stVal->rcp_no);
      free(stVal->flr_nm);
      free(stVal->rcp_dt);
      free(stVal->rmk);
      free(stVal);

      printf("check point ... parseDoc.3[%s][%s]\n"
        ,(*node)->crp_cls
        ,(*node)->crp_nm
      );
    }
    cur = cur->next;
  }
  xmlFreeDoc(doc);
  return;
}

int main(int argc, char *argv[]) 
{
  int fd, socket_fd;
  char *store_buffer, *getmsg_buffer;
  char *pMem, *memory_buffer, *pTagStore;
  int iMaxMemSize, iUseMemSize, number_tag_size;

  time_t timer;
  struct tm *tinfo;
  int ret;
  char *cfind;

  struct _list_dart_api *node, *stCurDart;
  char ReqWrite[MAX_BUFFER];

  char *HOSTNAME = "dart.fss.or.kr";
  int HOSTPORT = 80;
  char *chkPoint, *chkPoint1;
  char rcpno[64], dcmno[64], eleId[64], offset[64], length[64], dtd[64], Addr[1024];

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
      sprintf(store_buffer,"/home/oracle/Project/log/mknewspaper_%s.html",
        argv[2]);
      break;
    default:
      timer=time(NULL);
      tinfo=localtime(&timer);
      sprintf(getmsg_buffer,
        "/api/search.xml?auth=d58011d7473b0d0f7bf602538ed3f17918fed9c9&crp_cd=009540&start_dt=20170515&end_dt=20170515");
//        "/dsaf001/main.do?rcpNo=20170227000188");
//        "/dsaf001/main.do?rcpNo=20170515004618");
//        "/report/viewer.do?rcpNo=20170515004618&dcmNo=5655216&eleId=13&offset=639142&length=161656&dtd=dart3.xsd");
      sprintf(store_buffer,
        "/home/oracle/Project/log/dartpage_%04d%02d%02d.html",
        tinfo->tm_year+1900,tinfo->tm_mon+1,tinfo->tm_mday);
      break;
  }
  fd=open(store_buffer,O_WRONLY|O_CREAT|O_APPEND,0644);
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
  iUseMemSize=0;

  iUseMemSize=GetDartApi(&pMem, &iMaxMemSize);
  printf("\n%s\n",pMem);

  number_tag_size = 0;
  while(*(pMem+number_tag_size)!='<') number_tag_size += 1;

  init_list(&node);
  

  parseDoc(&node, pMem+number_tag_size, iUseMemSize-number_tag_size);

/*
  printf("check point ... node1:[%s][%s]\n", 
    node->rpt_nm, node->rcp_no);
  printf("check point ... node2:[%s][%s]\n", 
    node->next->rpt_nm, node->next->rcp_no);
  printf("check point ... node3:[%s][%s]\n", 
    node->next->next->rpt_nm, node->next->next->rcp_no);
*/

  stCurDart = node->next;

  ret = 1;
  while(stCurDart != NULL)
  {
    //printf("check point ... node%d:[%s][%s][%d]\n", 
    //  ret, stCurDart->rpt_nm, stCurDart->rcp_no, strlen(stCurDart->crp_cd));
    //ret += 1;

    sprintf(ReqWrite,"GET http://dart.fss.or.kr/dsaf001/main.do?rcpNo=%s HTTP/1.1\r\nHost: dart.fss.or.kr\r\nAccept-Encoding: text/html, deflate\r\nAccept: text/html\r\nAccept-Language: ko-kr\r\n\r",
      stCurDart->rcp_no);

    if((socket_fd=connect_server(HOSTNAME, HOSTPORT))<=1) return 1;

    // Retrieve the server's home page.
    // Send the HTTP GET command for the home page.
    ret=write(socket_fd, ReqWrite, strlen(ReqWrite));
    if(ret<=0)
    {
      perror("socket_fd write error");
      close(socket_fd);
      return 1;
    }

    memset(pMem,0x00,iMaxMemSize);
    iUseMemSize=ParseByHtml(socket_fd, &pMem, &iMaxMemSize);

    chkPoint = NULL;
    chkPoint = strstr(pMem, " 연결재무제표");

    if(chkPoint == NULL ) {stCurDart = stCurDart->next;continue;}
    chkPoint = strstr(chkPoint, "viewDoc");

    chkPoint = strstr(chkPoint, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(rcpno, 0x00, 64);
    memcpy(rcpno, chkPoint+1, chkPoint1-chkPoint-1);

    chkPoint = strstr(chkPoint1+1, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(dcmno, 0x00, 64);
    memcpy(dcmno, chkPoint+1, chkPoint1-chkPoint-1);

    chkPoint = strstr(chkPoint1+1, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(eleId, 0x00, 64);
    memcpy(eleId, chkPoint+1, chkPoint1-chkPoint-1);

    chkPoint = strstr(chkPoint1+1, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(offset, 0x00, 64);
    memcpy(offset, chkPoint+1, chkPoint1-chkPoint-1);

    chkPoint = strstr(chkPoint1+1, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(length, 0x00, 64);
    memcpy(length, chkPoint+1, chkPoint1-chkPoint-1);

    chkPoint = strstr(chkPoint1+1, "'");
    chkPoint1 = strstr(chkPoint+1, "'");
    memset(dtd, 0x00, 64);
    memcpy(dtd, chkPoint+1, chkPoint1-chkPoint-1);
    //char rcpno[64], dcmno[64], eleId[64], offset[64], length[64], dtd[64];
    //viewDoc('20170515004618', '5655216', '13', '639142', '161656', 'dart3.xsd');}
    printf("check point ...\n\n%s\n\n", rcpno ); 
    printf("check point ...\n\n%s\n\n", dcmno ); 
    printf("check point ...\n\n%s\n\n", eleId ); 
    printf("check point ...\n\n%s\n\n", offset ); 
    printf("check point ...\n\n%s\n\n", length ); 
    printf("check point ...\n\n%s\n\n", dtd ); 

    memset(Addr, 0x00, 1024);
    sprintf(Addr,"/report/viewer.do");
    sprintf(Addr,"%s?rcpNo=%s",Addr, rcpno);
    sprintf(Addr,"%s&dcmNo=%s",Addr, dcmno);
    if(eleId != NULL)
      sprintf(Addr,"%s&eleId=%s",Addr, eleId);
    if(offset != NULL)
      sprintf(Addr,"%s&offset=%s",Addr, offset);
    if(length != NULL)
      sprintf(Addr,"%s&length=%s",Addr, length);
    sprintf(Addr,"%s&dtd=%s",Addr, dtd);

    printf("check point ...\n\n%s\n\n", Addr ); 
    close(socket_fd);

    stCurDart = stCurDart->next;
  }
}
