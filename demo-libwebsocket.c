//#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <termios.h>
#include <sys/resource.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <iconv.h>
#include <semaphore.h>
#include <libwebsockets.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#define cticonfig "/opt/robot.conf"

#define MAXFILES 8
#define TTS_MAX_SIZE 900  //300���� yhy2019-08-26 ������300����
#define MAX_HZ_SIZE  240  //ʶ������80����
#define MAX_VOICE_LEN 240000          //��λshort //yhy2019-08-16: maxvoice 8s==>30s
#define MAX_VOICE_LEN_BASE64 645000   //>= MAX_VOICE_LEN*2/3*4


#define MAX_URLBODY_SIZE 2000000
#define V_FRAMESIZE       6400
#define MAX_PAYLOAD_SIZE  V_FRAMESIZE*2
#define SHA256_BLOCK_SIZE 32
#define MAX_THREADS 16
#define MAX_INDEX 2000


typedef struct session_data {
    int  index;
    int  id;
    int  len;
    int  count;
    int  connection_flag;
    struct lws *wsi;
    char appid[32];
    char hz[MAX_HZ_SIZE];
    char lanparam[256];
    char data[MAX_VOICE_LEN_BASE64];
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
}SESSION_DATA;

SESSION_DATA client_userdata[MAX_THREADS+1];
static sem_t m_hEvent[MAX_THREADS+1];
char urlaudio[MAX_THREADS+1][MAX_URLBODY_SIZE];
static struct lws_context *context = NULL;
static struct lws_context_creation_info ctx_info = { 0 };
char b64audio[MAX_THREADS+1][MAX_VOICE_LEN_BASE64];
static struct lws_client_connect_info conn_info[MAX_THREADS+1];
static char   _server_address[MAX_THREADS+1][128];
static pthread_mutex_t conn_locks[MAX_THREADS+1];
static char xfappid[MAX_THREADS][128],xfapikey[MAX_THREADS][128],xfparam[MAX_THREADS][160];
static char xfhost[MAX_THREADS][128];
static int  lanid[MAX_THREADS];

int interrupted=0,call_delay=500,ali_tts_wav=0;
int asr_threads=1,send_asrevent=0;

typedef struct AsrResult
{
    int index;
    int state;
    char uuid[64];
    char text[MAX_HZ_SIZE];
} ASRRESULT;
static ASRRESULT asr[MAX_INDEX];


typedef struct nodet
{
    int  index;
    int  size;
    char *buff;
    struct nodet * next;
    char telno[32];
    char taskid[32];
    char userid[64];

    char callid[64];//uckefu 2019-10-04����
    char orgi[64];//uckefu 2019-10-04����
    char extid[64];//uckefu 2019-10-04����


    char uuid[64];
    char filename[128];
} node_t;

#define  AV_BASE64_SIZE(x)   (((x)+2) / 3 * 4 + 1)
char *base64_encode(char *out, int out_size,  char*in2, int in_size)
{
    static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ret, *dst;
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_size;
    const uint8_t*in=(uint8_t*)in2;

    if (in_size >= UINT_MAX / 4 ||
        out_size < AV_BASE64_SIZE(in_size))
        return NULL;
    ret = dst = out;
    while (bytes_remaining) {
        i_bits = (i_bits << 8) + *in++;
        bytes_remaining--;
        i_shift += 8;

        do {
            *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
            i_shift -= 6;
        } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
    }
    while ((dst - ret) & 3)
        *dst++ = '=';
    *dst = '\0';

    return ret;
}

int GetPrivateProfileString(const char*set,const char*cmd,const char*def,char*res,int para_len,const char*filename)
{
    FILE 	*fp=NULL;
    char	tmp[500];
    char 	line_str[500];
    int 	i,len;

    strcpy(res,def);
    fp=fopen(filename,"r");
    if(fp==NULL){printf("open %s fail",filename);	return 0;}
    while (fgets(line_str, 256, fp))
    {
        len=strlen(line_str);
        for(i=0;i<len;i++)
        {
            if(line_str[i]=='\r'){line_str[i]=0; break;}
            if(line_str[i]=='\n'){line_str[i]=0; break;}
        }
        len=strlen(line_str);
        if(line_str[0]=='#' || len<3) continue;
        strcpy(tmp,line_str);
        for(i=0; i<len;i++)
        {
            if(tmp[i]=='=') break;
        }
        tmp[i]='\0';
        if(strcmp(cmd,tmp)==0)
        {
            i++;
            strcpy(res,line_str+i);
            break;
        }
    }

    fclose(fp);
    return 0;

}

//int  printf_win32(char *szFormat, ...)
//{
//    static int count;
//    char szBuffer[8192];
//    va_list pArguments;
//
//    count++;
//    memset(szBuffer, 0, 2048);
////    va_start(pArguments, szFormat);
//    vsnprintf(szBuffer, 2000, szFormat, pArguments);
////    va_end(pArguments);
//
////    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Robot:%s\n", szBuffer);
//    return 0;
//}

int hmac256(char*data,char*key,char*b64,int outsize)
{
    HMAC_CTX ctx;
    char* result;
    unsigned int len = SHA256_BLOCK_SIZE;
    result = (char*)malloc(sizeof(char) * len);
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, (unsigned char*)key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (unsigned char*)data, strlen(data));
    HMAC_Final(&ctx, (unsigned char*)result, &len);
    HMAC_CTX_cleanup(&ctx);
    base64_encode(b64, outsize,result, SHA256_BLOCK_SIZE);
    free(result);
    return 0;
}

int URLEncode(const char* str,char* result, const int resultSize)
{
    int i;
    int j = 0;//for result index
    char ch;

    if ((str==NULL) || (result==NULL) || (resultSize<=0)) {
        return 0;
    }

    for ( i=0; j<resultSize; i++) {
        ch = str[i];
        if(ch=='\0') break;
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) {
            result[j++] = ch;
        } else if (ch == ' ') {
            sprintf(result+j, "%%20");
            j += 3;
            //result[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result[j++] = ch;
        } else {
            if (j+3 < resultSize) {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            } else {
                break;
            }
        }
    }
    result[j] = '\0';
    return j;
}

void ws_client_init();
int  ws_client_set_ssl(const char* ca_filepath,  const char* server_cert_filepath, const char*server_private_key_filepath,  int is_support_ssl);
int  ws_client_create();
int  ws_client_connect(char*address,int port,const char*uri,SESSION_DATA *userdata,int is_ssl_support);
int  ws_client_run(int wait_time);
void ws_client_destroy();
int  ws_client_isconnected(SESSION_DATA *data);

int ws_client_callback( struct lws *wsi,  enum lws_callback_reasons reason, void *user, void *in, size_t len )
{
    int size,close,state;
    char b64[V_FRAMESIZE+64],*msg,*buf;
    SESSION_DATA *data = (SESSION_DATA *) user;
    if(reason==LWS_CALLBACK_PROTOCOL_INIT){lwsl_notice( "init server ok!\n" );return 0;}
    if(data==NULL) return 0;
    if(data->id<0 ||data->id>=MAX_THREADS) return 0;

    switch ( reason ) {
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
            //lwsl_notice( "Connected to server ok!\n" );
            printf("connected to server ok");
            break;

        case LWS_CALLBACK_CLIENT_ESTABLISHED:   // ���ӵ����������Ļص�

            printf("ws established");
            pthread_mutex_lock(&conn_locks[data->id]);
            data->connection_flag=2;
            pthread_mutex_unlock(&conn_locks[data->id]);
            printf( "Connected to server ws ok!,id=%d\n",data->id);
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:       // ���յ����������ݺ��Ļص�������Ϊin���䳤��Ϊlen
        {

            printf("ws receive data");
            char  *p,*p2;
            close=0;
            buf=(char *) in;

            printf("\n ws receive data %s", buf);
            if(strstr(buf,"\"status\":2")) close=1;
            p=buf;
            while(1)
            {
                p=strstr(p,"\"w\":\"");
                if(p)
                {
                    p=p+5;
                    p2=strstr(p,"\"}");
                    if(p2)
                    {
                        *p2=0;
                        if(strlen(data->hz)+strlen(p)<MAX_HZ_SIZE)
                            strcat(data->hz,p);
                        else
                            break;
                        p=p2+2;
                    }
                    else
                        break;
                }
                else
                {
                    //printf( "Rx:index=%d,%s\n", data->index,buf);
                    break;
                }
            }
            if(close)
            {
                printf( "asrend id=%d,index=[%d] hz=[%s]\n",data->id,data->index,data->hz);
                //�ͻ��˻ػ�������������Ҫ�ر����ӣ�������֤���������˵Ĵ�����Ϊwebsocket������1000�������ͻ��˿���û���ṩ�ر�ʱ���������Ľӿڡ���������ע��������# ������
                lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL,(unsigned char *)"asrok", 5);
                lws_set_timeout(wsi, 32, LWS_TO_KILL_ASYNC);
            }
        }
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:     // ���˿ͻ��˿��Է�������ʱ�Ļص�
            if(data->count>=data->len)
            {
                break;
            }
            memset( data->buf, 0, sizeof( data->buf ));
            msg = (char *) &data->buf[ LWS_PRE ];
            if (data->count==0)
            {
                // ǰ��LWS_PRE���ֽڱ�������LWS
                printf( "Tx:alllen=%d,pos=%d,first\n", data->len,data->count);
                memcpy(b64,data->data,V_FRAMESIZE);
                b64[V_FRAMESIZE]=0;
                data->count=V_FRAMESIZE;
                size=sprintf( msg, "{\"common\": {\"app_id\":\"%s\"},\"business\":%s,\"data\":{\"status\":0,\"format\":\"audio/L16;rate=8000\",\"audio\":\"%s\",\"encoding\":\"raw\"}}",
                              data->appid,data->lanparam,b64);
                lws_write( wsi, &data->buf[ LWS_PRE ], size, LWS_WRITE_TEXT );
            }
            else
            {
                state=1;
                size=V_FRAMESIZE;
                if(data->count+V_FRAMESIZE>=data->len)
                {
                    state=2;
                    size=data->len-data->count;
                }
                memcpy(b64,data->data+data->count,size);
                b64[size]=0;
                data->count=data->count+size;
                size= sprintf(msg, "{\"data\":{\"status\":%d,\"format\":\"audio/L16;rate=8000\",\"audio\":\"%s\",\"encoding\":\"raw\"}}",
                              state,b64);
                lws_write( wsi, &data->buf[ LWS_PRE ], size, LWS_WRITE_TEXT );
            }
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("LWS_CALLBACK_CLIENT_CONNECTION_ERROR id=%d\n",data->id);
            lws_set_timeout(wsi, 32, LWS_TO_KILL_ASYNC);
            data->hz[0]='E';
            data->hz[1]=0;
            //sem_post(&m_hEvent[data->id]);
            break;
            return -1;


        case LWS_CALLBACK_CLOSED:
        case LWS_CALLBACK_CLIENT_CLOSED:
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            pthread_mutex_lock(&conn_locks[data->id]);
            if(data->connection_flag)
            {
                data->connection_flag=0;
                data->wsi=NULL;
            }
            pthread_mutex_unlock(&conn_locks[data->id]);
            printf("LWS_CALLBACK_CLOSED2,id=%d\n",data->id);
            sem_post(&m_hEvent[data->id]);
            return -1;
            break;

        default:
            //lwsl_notice("reason=%d",reason);
            break;
    }

    return 0;
}
int ws_client_isconnected(SESSION_DATA *data)
{
    int connection_flag,id;
    if(data==NULL) return 0;
    id=data->id;
    if(id<0 || id>=MAX_THREADS) return 0;
    pthread_mutex_lock(&conn_locks[id]);
    connection_flag=data->connection_flag;
    pthread_mutex_unlock(&conn_locks[id]);
    return connection_flag;
}
struct lws_protocols protocols[] = {
        {
                //Э�����ƣ�Э���ص������ջ�������С
                "ws", ws_client_callback, sizeof(SESSION_DATA), 0,
        },
        {
                NULL, NULL,   0 // ����һ��Ԫ�ع̶�Ϊ�˸�ʽ
        }
};
void ws_client_init()
{
    int i;
    ctx_info.port = CONTEXT_PORT_NO_LISTEN;
    ctx_info.iface = NULL;
    ctx_info.protocols = protocols;
    // ctx_info.gid = -1;
    // ctx_info.uid = -1;
    for(i=0;i<MAX_THREADS;i++)
    {
        pthread_mutex_init(&conn_locks[i], NULL);
        if (sem_init(&m_hEvent[i], 0, 0))
        {
            printf("CreateEvent m_hEvent fail");
        }
    }
}
int ws_client_set_ssl(const char* ca_filepath,  const char* server_cert_filepath,const char*server_private_key_filepath,int is_support_ssl)
{
    if(!is_support_ssl)
    {
        ctx_info.ssl_ca_filepath = NULL;
        ctx_info.ssl_cert_filepath = NULL;
        ctx_info.ssl_private_key_filepath = NULL;
        printf("no ssl \n");
    }
    else
    {
        ctx_info.ssl_ca_filepath = ca_filepath;
        ctx_info.ssl_cert_filepath = server_cert_filepath;
        ctx_info.ssl_private_key_filepath = server_private_key_filepath;
        ctx_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        //ctx_info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;

        printf("add ssl \n");
    }
    return is_support_ssl;
}
int ws_client_create()
{
//    return 0;
    context = lws_create_context( &ctx_info );
    if(!context)  return -1;
    return 0;
}
int Sleep(int t)
{
    struct timeval delay;
    delay.tv_sec = 0;
    delay.tv_usec = t*1000; // 1ms
    select(0, NULL, NULL, NULL, &delay);
    return 0;
}

int ws_client_connect(char*address,int port,const char*uri,SESSION_DATA *userdata,int is_ssl_support)
{
    struct lws*wsi;
    int id=userdata->id;

    printf("id %d", id);
    if(id<0||id>MAX_THREADS) return -2;
    strcpy(_server_address[id],address);
    memset(&conn_info[id],0,sizeof(struct lws_client_connect_info));
    conn_info[id].context = context;
    conn_info[id].address = _server_address[id];
    conn_info[id].port = port;
    if(!is_ssl_support)
        conn_info[id].ssl_connection = 0;
    else
        conn_info[id].ssl_connection = 1;
    conn_info[id].host = _server_address[id];
    conn_info[id].origin = _server_address[id];
    conn_info[id].protocol = protocols[ 0 ].name;
    if(uri==NULL||uri[0]==0)
        conn_info[id].path = "/";
    else
        conn_info[id].path = uri;
    conn_info[id].userdata = userdata;
    printf("\n");
    printf("dadda %s %d %s  %s \n %s", conn_info[id].address, conn_info[id].port, conn_info[id].path, conn_info[id].host, conn_info[id].protocol);
    Sleep(1000);
    wsi = lws_client_connect_via_info( &conn_info[id] );
    if(!wsi)  return -1;
    printf("\n");
    printf("ok");
    pthread_mutex_lock(&conn_locks[userdata->id]);
    userdata->connection_flag=1;
    userdata->wsi=wsi;
    pthread_mutex_unlock(&conn_locks[userdata->id]);
    return 0;
}
int ws_client_run(int wait_time)
{
    lws_service( context, wait_time );
    //lws_callback_on_writable( wsi );
    return 0;
}
void ws_client_destroy()
{
    int i;
    printf("ws_client_destroy start.\n");
    lws_context_destroy(context);

    for(i=0;i<MAX_THREADS;i++)
    {
        pthread_mutex_destroy(&conn_locks[i]);
    }
    printf("ws_client_destroy end.\n");
    for(i=0;i<MAX_THREADS;i++)
    {
        sem_destroy(&m_hEvent[i]);
    }
    printf("ws_client_destroy end ok.\n");
}

int use_asr = 64;


// 初始化websocket
void * ThreadLibWebSocket(void *arg)
{
    int i;
    if ((use_asr & 64)==0) return 0;
    ws_client_init();
    ws_client_set_ssl(NULL,NULL,NULL,0);
    i = ws_client_create();
    printf("ThreadLibWebSocket %d ws_client_create.\n", i);
    while(interrupted==0) ws_client_run(1000);
    ws_client_destroy();
    printf("ThreadLibWebSocket end.\n");
    return 0;
}


static char XFwsAppid[MAX_THREADS][64];
static char XFwsApiKey[MAX_THREADS][64];
static char XFwsApiSecret[MAX_THREADS][64];
static char XFwsParam[MAX_THREADS][128];
static char wsurl[MAX_THREADS][2048];

struct yc_esl_mutex {
    pthread_mutex_t mutex;
};
typedef struct yc_esl_mutex yc_esl_mutex_t;

#define YC_ESL_DECLARE(type) type
static yc_esl_mutex_t *gMutex=NULL,*Mutex1=NULL,*Mutex2=NULL,*Mutex3=NULL,*Mutex4=NULL;

typedef enum {
    YC_ESL_SUCCESS,
    YC_ESL_FAIL,
    YC_ESL_BREAK,
    YC_ESL_DISCONNECTED,
    YC_ESL_GENERR
} yc_esl_status_t;
YC_ESL_DECLARE(yc_esl_status_t) yc_esl_mutex_create(yc_esl_mutex_t **mutex){
yc_esl_status_t status = YC_ESL_FAIL;
#ifndef WIN32
pthread_mutexattr_t attr;
#endif
yc_esl_mutex_t *check = NULL;

check = (yc_esl_mutex_t *)malloc(sizeof(**mutex));
if (!check)
goto done;
#ifdef WIN32
InitializeCriticalSection(&check->mutex);
#else
if (pthread_mutexattr_init(&attr)) {
free(check);
goto done;
}

if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE))
goto fail;

if (pthread_mutex_init(&check->mutex, &attr))
goto fail;

goto success;

fail:
pthread_mutexattr_destroy(&attr);
free(check);
goto done;

success:
#endif
*mutex = check;
status = YC_ESL_SUCCESS;

done:
//cti_log(1,"yc_esl_mutex_create status=%d",status);
return status;
}

YC_ESL_DECLARE(yc_esl_status_t) yc_esl_mutex_destroy(yc_esl_mutex_t **mutex)
{
yc_esl_mutex_t *mp = *mutex;
*mutex = NULL;
if (!mp) {
return YC_ESL_FAIL;
}
#ifdef WIN32
DeleteCriticalSection(&mp->mutex);
#else
if (pthread_mutex_destroy(&mp->mutex))
return YC_ESL_FAIL;
#endif
free(mp);
return YC_ESL_SUCCESS;
}

YC_ESL_DECLARE(yc_esl_status_t) yc_esl_mutex_lock(yc_esl_mutex_t *mutex)
{
#ifdef WIN32
EnterCriticalSection(&mutex->mutex);
#else
if (pthread_mutex_lock(&mutex->mutex))
return YC_ESL_FAIL;
#endif
return YC_ESL_SUCCESS;
}

YC_ESL_DECLARE(yc_esl_status_t) yc_esl_mutex_trylock(yc_esl_mutex_t *mutex)
{
#ifdef WIN32
if (!TryEnterCriticalSection(&mutex->mutex))
		return YC_ESL_FAIL;
#else
if (pthread_mutex_trylock(&mutex->mutex))
return YC_ESL_FAIL;
#endif
return YC_ESL_SUCCESS;
}

YC_ESL_DECLARE(yc_esl_status_t) yc_esl_mutex_unlock(yc_esl_mutex_t *mutex)
{
#ifdef WIN32
LeaveCriticalSection(&mutex->mutex);
#else
if (pthread_mutex_unlock(&mutex->mutex))
return YC_ESL_FAIL;
#endif
return YC_ESL_SUCCESS;
}

int Init_Lock()
{
    yc_esl_mutex_create(&gMutex);
    return 0;
}

void P()
{
    static int boot;
    if(boot==0)	{boot=1;Init_Lock();}
    yc_esl_mutex_lock(gMutex);
}
void V()
{
    yc_esl_mutex_unlock(gMutex);
}

int xunfei_asr_wsapi(int id,int index, char*asrtext, char *audiodata, int content_len)
{
    char authorization[256],authorization_origin[256];
    char urlencode1[256],tmp[1024];
    char date_time[32],b64[256],signature_origin[256];
    time_t unix_timestamp=0;
    struct timespec ts;
    int s,voicelen;
    SESSION_DATA *userdata;
    static int boot[MAX_THREADS];
    static int _boot;
    static char _XFwsURL[64],_XFwsAppid[64],_XFwsApiKey[64],_XFwsApiSecret[64],_XFwsParam[128];
    if(_boot==0)
    {
        _boot=1;
        GetPrivateProfileString("SET", "XFwsURL", "iat-api.xfyun.cn", _XFwsURL, 60, cticonfig);
        GetPrivateProfileString("SET", "XFWSAPPID", "5d1cb048", _XFwsAppid, 64, cticonfig);
        GetPrivateProfileString("SET", "XFWSAPIKEY", "683332bd4da7bea8beee98a09a3a159e", _XFwsApiKey, 64, cticonfig);
        GetPrivateProfileString("SET", "XFWSAPISECRET", "0bc41ff0eb70ac62816f6b590f59ada2",_XFwsApiSecret, 64, cticonfig);
        GetPrivateProfileString("SET", "XFWSPARAM", "{\"language\":\"zh_cn\",\"domain\":\"iat\",\"accent\":\"mandarin\"}",_XFwsParam, 120, cticonfig);
    }
    userdata =&client_userdata[id];

    if (boot[id] == 0)
    {
        boot[id] = 1;
        sprintf(tmp,"XFWSAPPID%d",id);
        GetPrivateProfileString("SET", tmp, _XFwsAppid, XFwsAppid[id], 64, cticonfig);
        sprintf(tmp,"XFWSAPIKEY%d",id);
        GetPrivateProfileString("SET", tmp, _XFwsApiKey, XFwsApiKey[id], 64, cticonfig);
        sprintf(tmp,"XFWSAPISECRET%d",id);
        GetPrivateProfileString("SET", tmp, _XFwsApiSecret, XFwsApiSecret[id], 64, cticonfig);
        sprintf(tmp,"XFWSPARAM%d",id);
        GetPrivateProfileString("SET", tmp, _XFwsParam,XFwsParam[id], 120, cticonfig);//sms16k scene	string	��	�龰ģʽ������ʹ���ȴʹ��ܣ�����ָ��scene=main��	main//yhy2019-05-20 vad_eos=1 �ᵼ������ʶ��ֻʶ����ǰ���� �� ��ɶ��
        if(strstr(XFwsParam[id],"mandarin"))  lanid[id]=1;
        if(strstr(XFwsParam[id],"cantonese")) lanid[id]=2;//����
        if(strstr(XFwsParam[id],"en_us"))     lanid[id]=3;//en
        memset(&client_userdata[id],0,sizeof(SESSION_DATA));

        printf(XFwsAppid[id]);
        printf(XFwsParam[id]);
        printf(userdata->appid);
        printf(userdata->id);
        userdata->id=id;
        strcpy(userdata->appid,XFwsAppid[id]);
        strcpy(userdata->lanparam,XFwsParam[id]);
        printf("XFwsParam[%d]=%s,lanid=%d",id, XFwsParam[id],lanid[id]);
    }

//    return 0;
    voicelen=content_len;
    if(voicelen>MAX_VOICE_LEN*2) voicelen=MAX_VOICE_LEN*2;
    voicelen=voicelen/6*6;//ȥ��������λ,��֤6��������

    printf("asr start id=%d,index=%d.voiceinlen=%d,len=%d,lanid=%d!",id,index,content_len,voicelen,lanid[id]);
    if(ws_client_isconnected(userdata)>0)
    {
        printf("asr ws state fail id=%d,index=%d!",id,index);

        return -2;
    }

    userdata->index=index;
    userdata->len=voicelen/3*4;//1������beforeEncode.length()��3������������ô����Ϊ (beforeEncode.length()/3)*4
    userdata->count=0;
    userdata->hz[0]=0;
    //MAX_VOICE_LEN_BASE64
    //memcpy(userdata->data,audiodata,voicelen);// (beforeEncode.length()/3)*4
    base64_encode(userdata->data, MAX_VOICE_LEN_BASE64,audiodata,voicelen);
    unix_timestamp = time(NULL);
    strftime(date_time, sizeof(date_time), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&unix_timestamp));
    sprintf(signature_origin,"host: %s\ndate: %s\nGET /v2/iat HTTP/1.1",_XFwsURL,date_time);
    memset(b64,0,sizeof(b64));
    hmac256(signature_origin, XFwsApiSecret[id], b64, sizeof(b64));
    sprintf(authorization_origin,"api_key=\"%s\", algorithm=\"hmac-sha256\", headers=\"host date request-line\", signature=\"%s\"",
            XFwsApiKey[id],b64);
    memset(authorization,0,sizeof(authorization));
    base64_encode(authorization, sizeof(authorization),authorization_origin, strlen(authorization_origin));
    URLEncode(date_time,urlencode1, sizeof(urlencode1));
    sprintf(wsurl[id],"/v2/iat?authorization=%s&date=%s&host=%s",authorization,urlencode1,_XFwsURL);


    printf("  \n %c %c\",10,10");
    printf(_XFwsURL);

    char data[4];
    GetPrivateProfileString("SET",  "WSPORT", "80", data,  64, cticonfig);
    int port = atoi(data);
    printf("\n %d", port);
    if(ws_client_connect(_XFwsURL,port,wsurl[id],userdata,0)<0)
    {
        printf("asr ws_client_connect fail id=%d,index=%d!",id,index);
        return -1;
    }

    ts.tv_sec=time(NULL)+5;//5s timeout
    ts.tv_nsec=0;
    while(1)
    {
        s=sem_trywait(&m_hEvent[id]);
        if(s==-1) break;
    }
    while ((s = sem_timedwait(&m_hEvent[id], &ts)) == -1 && errno == EINTR) continue;
    if (s == -1)
    {
        printf("asr sem timeout id=%d,index=%d!",id,index); //yhy2019-10-01   ��ʱҪ�Ͽ�����
        if(ws_client_isconnected(userdata)>0 && userdata->wsi)
        {
            pthread_mutex_lock(&conn_locks[id]);
            userdata->connection_flag=0;
            userdata->wsi=NULL;
            pthread_mutex_unlock(&conn_locks[id]);
        }
        return 2;
    }
    strcpy(asrtext,userdata->hz);
    printf("asr end id=%d,index=%d.result=%s,voiceinlen=%d,len=%d,lanid=%d!",id,index,asrtext,content_len,voicelen,lanid[id]);
    if(asrtext[0]=='E') return -3;
    return 0;
}


void * ThreadAsrHttp(void* arg)
{
    node_t *buf;
    int  id,i;
    char* buffer = "abc";
    char tmp[4096],info[1024];
//    FILE*fp;

//    int gg = sizeof(node_t);
    if (buf == NULL)
    {

        printf("\n shenmeqingk ");
        int gg = sizeof(node_t);
        buf = malloc(gg);

        printf(buffer);
        buf->buff = buffer;

//        buf = (node_t *)malloc(sizeof(node_t));
        printf("null ggg tid=%d", gg);
        xunfei_asr_wsapi(id, id, tmp, buf->buff, 1);
        return 0;
    }


    buf->size = 3;
    i = xunfei_asr_wsapi(id, id, tmp, buf->buff, 3);
//    P();
//    asr_threads--;
//    V();
//    printf_win32("ThreadAsrHttp run tid=%d,end", id);
    return 0;
}


int init_asr()
{
    char tmp[1280];
    long index;
    pthread_t threadid;
    memset(asr, 0, sizeof(asr));

    asr_threads = atoi("1");
    if (asr_threads < 1) asr_threads = 1;
    if (asr_threads > MAX_THREADS) asr_threads = MAX_THREADS;

//    index=0;
//    if(pthread_create(&threadid, NULL, ThreadFsEvent,(void*) index) != 0)
        printf("Create thread ThreadFsEvent error!");
    if (pthread_create(&threadid, NULL, ThreadLibWebSocket, NULL) != 0)
        printf("Create thread ThreadLibWebSocket error!");
//
    for (index = 0; index < asr_threads; index++)
    {
        if(pthread_create(&threadid, NULL, ThreadAsrHttp,(void*) index) != 0) printf("Create thread ThreadAsrHttp error id=%ld!",index);
        printf("11111");
        Sleep(100);
    }
    return 0;
}




//static int channel_state[MAX_INDEX],pos;

int main() {
//    printf("Hello, World!\n");
    char tmp[1024];
//    GetPrivateProfileString();
    GetPrivateProfileString("SET", "YCASR_URL", "127.0.0.1", tmp, 64, cticonfig);
    GetPrivateProfileString("SET", "connect_data", "127.0.0.1", tmp, 5, cticonfig);
//    printf(tmp);
    printf("xingpan");
    init_asr();
    printf("end");
    Sleep(1000);

}
