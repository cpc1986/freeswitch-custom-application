// mini 版本 myrobot，可进行学习， 自定义freeswitch application
// 通过media bug 来对channel进行监听，实时获取音频流 20ms， 160 samples

#include <switch.h>
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
#include <iconv.h>  
#include <semaphore.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/epoll.h> 
#include <arpa/inet.h>

/*! Syntax of the API call. */
#define ROBOT_SYNTAX "<uuid> <stop|wavefilename.wav|http://xxxx>"

/*! Number of expected parameters in api call. */
#define ROBOT_PARAMS 2

#define ROBOT_EVENT_ASR "myrobot::asr"

static switch_bool_t robot_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type);

#define MAX_VOICE_LEN 240000
#define MAX_VOICE_LEN_BASE64 645000  
int use_asr = 8,use_tts=2,use_cache=0,use_url=0;
#define MAXFILES 8
#define TTS_MAX_SIZE 900  
#define MAX_HZ_SIZE  240
typedef struct robot_session_info {	
	int index;
	int filetime;
	int fileplaytime;
	int nostoptime;
	int asrtimeout;
	int asr;
	int play, pos;
	int sos, eos, ec, count;
	int eos_silence_threshold;	
	int final_timeout_ms;
	int silence_threshold;
	int harmonic;
	int monitor;
	int lanid;
	switch_core_session_t *session; 		
	char taskid[32];
	char groupid[32];
	char telno[32];
	char userid[64];
	char callid[64];
	char orgi[64];
	char extid[64];
	char uuid[64];
	char uuidbak[64];
	char recordfilename[128];	
	char para1[256];
	char para2[256];
	char para3[256];
	char filename[TTS_MAX_SIZE];
	short buffer[MAX_VOICE_LEN];
} robot_session_info_t;

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

//定义shutdown module方法， free 掉malloc 堆内存
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_vmd_shutdown);

// 定义加载模块时，读取配置文件，初始化变量等
SWITCH_MODULE_LOAD_FUNCTION(mod_vmd_load);
SWITCH_MODULE_DEFINITION(mod_vmd, mod_vmd_load, mod_vmd_shutdown, NULL);

// 定义自定义application， 这样在dialplan中 可以 <action application="myrobot" data="" />
SWITCH_STANDARD_APP(robot_start_function);


SWITCH_MODULE_LOAD_FUNCTION(mod_vmd_load)
{
	char tmp[256];
	// 有配置文件，可以进行读取
	FILE* fp;	
	char line_str[1024],*p;
	int i,len;
	// 使用app_interface 进行 add app
	switch_application_interface_t *app_interface;

	if (switch_event_reserve_subclass(ROBOT_EVENT_ASR) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Robot Couldn't register subclass %s!\n", ROBOT_EVENT_ASR);
		return SWITCH_STATUS_TERM;
	}
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Robot enabled,monitor=%d,use_asr=%d,use_tts=%d\n",1,use_asr,2);

	// 为此模块增加app，调用名称即为 myrobot
	SWITCH_ADD_APP(app_interface, "myrobot", "myrobot", "ai robot", robot_start_function, "[stop|restart|start|wavefilename.wav]", SAF_NONE);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}


SWITCH_STANDARD_APP(robot_start_function)
{
	switch_media_bug_t *bug;
	switch_status_t status;
	switch_channel_t *channel;
	robot_session_info_t *robot_info;

	if (session == NULL)
		return;
	// 通过sesion 获取channel
	channel = switch_core_session_get_channel(session);

	// 根据channel 可以获取channel 上绑定的变量 variable

	/* Is this channel already set? */
	bug = (switch_media_bug_t *) switch_channel_get_private(channel, "_robot_");
	/* If yes */
	if (bug != NULL) 
	{
		/* We have already started */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Robot Cannot run 2 at once on the same channel!\n");
		return;
	}
	// 初始化变量， 一定记得要 free掉
	robot_info = (robot_session_info_t *)malloc(sizeof(robot_session_info_t)); 
	if(robot_info==NULL) return;
	robot_info->session = session; 
	strcpy(robot_info->uuid, switch_core_session_get_uuid(robot_info->session));

	// 重中之重， 为session 增加media bug， 绑定回调函数 robot_callback
	status = switch_core_media_bug_add(session, "vmd", NULL, robot_callback, robot_info, 0, SMBF_READ_REPLACE, &bug);

	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Robot Failure hooking to stream\n");
		return;
	}
	switch_channel_set_private(channel, "_robot_", bug);
}


SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_vmd_shutdown)
{
	int i;
	// free 掉
	switch_event_free_subclass(ROBOT_EVENT_ASR);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "myapplication disabled\n");
	return SWITCH_STATUS_SUCCESS;
}


static switch_bool_t process_close(robot_session_info_t *rh)
{
	switch_channel_t *channel;			
	char info[2048], result[2048];
	int send=1;			
	rh->uuid[0] = 0;	
	rh->index = -1;	
	channel = switch_core_session_get_channel(rh->session);
	switch_channel_set_private(channel, "_robot_", NULL);
	free(rh);
	return SWITCH_TRUE;
}

static switch_bool_t robot_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	robot_session_info_t *robot_info;
//	switch_codec_t *read_codec;
	switch_frame_t *frame;

	robot_info = (robot_session_info_t *) user_data;
	if (robot_info == NULL) {
		return SWITCH_FALSE;
	}

	switch (type) {

	case SWITCH_ABC_TYPE_INIT:
		break;

	case SWITCH_ABC_TYPE_READ_REPLACE:
		if(robot_info->uuid[0]==0) break;
		frame = switch_core_media_bug_get_read_replace_frame(bug);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "received data\n");
		break;
	
	case SWITCH_ABC_TYPE_CLOSE:
		process_close(robot_info);
		break;
	default:
		break;
	}

	return SWITCH_TRUE;
}
