#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <microhttpd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ERROR404 "<html><head><title>File not found</title></head><body>File not found</body></html>\n\n"
#define PAGEOK "<html><head><title>OK</title></head><body>OK</body></html>\n\n"

#define MAXNAMESIZE     20
#define MAXANSWERSIZE   512
#define POSTBUFFERSIZE  512
#define GET             0
#define POST            1

pid_t ffmpeg = 0;
time_t lastbark;
int terminate = 0;

int port;
char path[1024];
char sdev[1024];
int useWD;
int hasRTC;
int standalone;

struct connection_info_struct {
	int connectiontype;
	char *answerstring;
	struct MHD_PostProcessor *postprocessor;
};

/**
 * Generate 200 page
 */
static int
ok_page (struct MHD_Connection *connection){
	int ret;
	struct MHD_Response *response;

	/* unsupported HTTP method */
	response = MHD_create_response_from_buffer (strlen (PAGEOK), (void *) PAGEOK, MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/html");
	MHD_destroy_response (response);
	return ret;
}

/**
 * Handler used to generate a 404 reply.
 * @param connection connection to use
 */
static int
not_found_page (struct MHD_Connection *connection){
	int ret;
	struct MHD_Response *response;

	/* unsupported HTTP method */
	response = MHD_create_response_from_buffer (strlen (ERROR404), (void *) ERROR404, MHD_RESPMEM_PERSISTENT);
	if (response == NULL) return MHD_NO;
	ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/html");
	MHD_destroy_response (response);
	return ret;
}

static int
send_page (struct MHD_Connection *connection, const char *page){
	int ret;
	struct MHD_Response *response;

	response = MHD_create_response_from_buffer (strlen (page), (void *) page, MHD_RESPMEM_PERSISTENT);
	if (!response)
		return MHD_NO;

	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);

	return ret;
}

static int
isfsro(){
	struct statvfs stat;
	if (statvfs(path, &stat) != 0) return -1;
	if (stat.f_flag & ST_RDONLY) return 1;
	return 0;
}

static void
remountfs (int writable){
	if (writable && isfsro() && standalone)
		mount(sdev, path, "ext4", MS_MGC_VAL | MS_REMOUNT | MS_SYNCHRONOUS, NULL);
	else if (writable && isfsro())
		mount (sdev, path, "ext4", MS_MGC_VAL | MS_REMOUNT, NULL);
	else if (!writable && !isfsro()){
		sync();
		mount (sdev, path, "ext4", MS_MGC_VAL | MS_REMOUNT | MS_RDONLY, NULL);
	}
}

static int
stop (struct MHD_Connection *connection){
	char emsg[1024];
	struct MHD_Response *response;
	int ret;

	if (ffmpeg == 0)
		snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"not started\" />");
	else {
		int status;
		pid_t pid = waitpid(ffmpeg, &status, WNOHANG);
		if (pid == 0){
			kill(ffmpeg, SIGTERM);
			waitpid(ffmpeg, NULL, 0);
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"terminated\" />");
		} else if (pid < 0)
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"error\" />");
		else
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"terminated\" />");
		ffmpeg = 0;
	}

	remountfs(0);

	response = MHD_create_response_from_buffer (strlen (emsg), emsg, MHD_RESPMEM_MUST_COPY);
	if (response == NULL)
		return MHD_NO;
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/xml");
	MHD_destroy_response (response);
	return ret;
}

static int
check (struct MHD_Connection *connection){
	char emsg[1024];
	struct MHD_Response *response;
	int ret;

	lastbark = time(NULL);

	if (ffmpeg == 0)
		snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"not started\" />");
	else {
		int status;
		pid_t pid = waitpid(ffmpeg, &status, WNOHANG);
		if (pid == 0)
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"running\" />");
		else if (pid < 0)
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"error\" />");
		else
			snprintf(emsg, sizeof(emsg), "<ffmpeg status=\"terminated\" />");
	}

	response = MHD_create_response_from_buffer (strlen (emsg), emsg, MHD_RESPMEM_MUST_COPY);
	if (response == NULL) return MHD_NO;
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/xml");
	MHD_destroy_response (response);
	return ret;
}

static ssize_t
file_reader (void *cls, uint64_t pos, char *buf, size_t max){
	FILE *file = cls;
	(void) fseek (file, pos, SEEK_SET);
	return fread (buf, 1, max, file);
}

static void
file_free_callback (void *cls){
	FILE *file = cls;
	fclose (file);
}

int compar(const struct dirent **pa, const struct dirent **pb){
        struct dirent a, b;
        a = **pa; b = **pb;
	struct stat ainfo, binfo;
	stat(a.d_name, &ainfo);
	stat(b.d_name, &binfo);
	if (ainfo.st_mtime == binfo.st_mtime) return 0;
	else if (ainfo.st_mtime < binfo.st_mtime) return 1;
	return -1;
}

int filter(const struct dirent *d){
	struct dirent a = *d;
	struct stat ainfo;
	stat(a.d_name, &ainfo);
	if(S_ISREG(ainfo.st_mode)) return 1;
	return 0;
}

struct file_data {
	struct dirent **protected;
	int p;
	int rp;
	struct dirent **unprotected;
	int np;
	int rnp;
};

static void
file_data_free_callback (void *cls){
	struct file_data *data = cls;
	if (data != NULL && data->protected != NULL){
		while (data->p > 0){
			data->p--;
			free(data->protected[data->p]);
		}
		free(data->protected);
	}
	if (data != NULL && data->unprotected != NULL){
		while (data->np > 0){
			data->np--;
			free(data->unprotected[data->np]);
		}
		free(data->unprotected);
	}
	if (data != NULL) free(data);
}

static ssize_t
list_respgen (void *cls, uint64_t pos, char *buf, size_t max){
	struct file_data *data = cls;
	if (pos == 0)
		return snprintf(buf, max, "<files>\n");
	else if (data->rp < data->p){
		data->rp++;
		return snprintf (buf, max, "<file name=\"%s\" protected=\"1\"/>\n", data->protected[data->rp -1]->d_name);
	} else if (data->rnp < data->np){
		data->rnp++;
		return snprintf (buf, max, "<file name=\"%s\" protected=\"0\"/>\n", data->unprotected[data->rnp -1]->d_name);
	} else if (data->rnp == data->np || pos == 8){ // note: 8 characters in "<files>\n"
		data->rnp++;
		return snprintf (buf, max, "</files>\n");
	}

	return MHD_CONTENT_READER_END_OF_STREAM;
}

static int
list (struct MHD_Connection *connection){
	struct MHD_Response *response;
	int ret;
	struct file_data *data = malloc(sizeof(struct file_data));

	chdir(path);
	data->np = scandir(".", &data->unprotected, *filter, *compar);
	chdir("protected");
	data->p = scandir(".", &data->protected, *filter, *compar);
	chdir(path);

	data->rnp = 0;
	data->rp = 0;

	response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN, 32 * 1024, &list_respgen, data, &file_data_free_callback);
	if (response == NULL) return MHD_NO;
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);

	return ret;
}

static int
iterate_post (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size){
	struct connection_info_struct *con_info = coninfo_cls;

	char pfilename[1024];
	snprintf(pfilename, 1023, "protected/%s", data);
	char response[100];
	int fsro = isfsro();

	if (strcmp(key,"protect") == 0){
		if (fsro) remountfs(1);
		if (rename(data, pfilename) == 0)
			snprintf(response,100,"protected\n");
		else snprintf(response,100,"protect error\n");
		if (fsro) remountfs(0);
	} else if (strcmp(key,"unprotect") == 0){
		if (fsro) remountfs(1);
		if (rename(pfilename, data) == 0)
			snprintf(response,100,"unprotected\n");
		else snprintf(response,100,"unprotect error\n");
		if (fsro) remountfs(0);
	} else if (strcmp(key,"record") == 0){
		int status;
		if (ffmpeg == 0 || (ffmpeg > 0 && waitpid(ffmpeg, &status, WNOHANG) != 0)){
			if (!hasRTC){
				time_t current_time = atoi(data);
				stime(&current_time); // update the system time with the value from the parameter,
			}
			lastbark = time(NULL);
			ffmpeg = fork();
			if (ffmpeg == 0){
// /home/pi/bin/ffmpeg -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video0 -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video2 -c:v copy -map 0 -map 1 -f segment -segment_time 60 -reset_timestamps 1 test%03d.mkv
// /home/pi/bin/ffmpeg -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video0 -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video2 -c:v copy -map 0 -map 1 -f segment -strftime 1 -segment_time 60 -segment_atclocktime 1 -reset_timestamps 1 cam_%Y-%m-%d_%H-%M-%S.mkv
 				if (fsro) remountfs(1);
				chdir(path); // make sure that this child is actually in the proper path.
//				static char *argv[]={"ffmpeg","-f","video4linux2","-input_format","h264","-video_size","1280x720","-i","/dev/video0","-f","video4linux2","-input_format","h264","-video_size","1280x720","-i","/dev/video2","-c:v","copy","-map","0","-map","1","-f","segment","-strftime","1","-segment_time","60","-segment_atclocktime","1","-reset_timestamps","1","cam_\%Y-\%m-\%d_\%H-\%M-\%S.mkv",NULL};

				static char *argv[]={"ffmpeg","-f","video4linux2","-input_format","h264","-video_size","1280x720","-i","/dev/video1","-c:v","copy","-f","segment","-strftime","1","-segment_time","60","-segment_atclocktime","1","-reset_timestamps","1","cam_\%Y-\%m-\%d_\%H-\%M-\%S.mkv",NULL};

				execv("/home/pi/bin/ffmpeg",argv);
				remountfs(0);
				exit(127);
			} else if (ffmpeg < 0)
				snprintf(response,100,"fork error\n");
			else
				snprintf(response,100,"fork success\n");
		} else
			snprintf(response,100,"ffmpeg already running\n");
	}
    
	if (con_info != NULL){
		con_info->answerstring = malloc(MAXANSWERSIZE);
		snprintf(con_info->answerstring, MAXANSWERSIZE, response);
	}

	return MHD_YES;
}


static int
handle_request (void *cls,
		struct MHD_Connection *connection,
		const char *url,
		const char *method,
		const char *version,
		const char *upload_data,
		size_t *upload_data_size, void **con_cls){

	static int aptr;
	struct MHD_Response *response;
	int ret;
	FILE *file;
	int fd;

	struct stat buf;
  
	if (*con_cls == NULL){
		struct connection_info_struct *con_info;

		con_info = malloc (sizeof (struct connection_info_struct));
		if (con_info == NULL) return MHD_NO;
		con_info->answerstring = NULL;

		if (strcmp (method, "POST") == 0) {
			con_info->postprocessor = MHD_create_post_processor (connection, POSTBUFFERSIZE, iterate_post, (void *) con_info);

			if (con_info->postprocessor == NULL){
				free (con_info);
				return MHD_NO;
			}

			con_info->connectiontype = POST;
		} else
			con_info->connectiontype = GET;

		*con_cls = (void *) con_info;
		return MHD_YES;
	}


	if (!(strcmp(method, MHD_HTTP_METHOD_GET) == 0 || strcmp(method, MHD_HTTP_METHOD_POST) == 0))
		return MHD_NO;              /* unexpected method */

	printf("URL: %s\nMethod: %s\nVersion: %s\n\n",url,method,version);

	if (strstr(url, "favicon") != NULL) return not_found_page(connection); // tell anything asking for favicon to drop dead.

	if (strcmp (method, "POST") == 0){
		struct connection_info_struct *con_info = *con_cls;

		if (*upload_data_size != 0){
			MHD_post_process (con_info->postprocessor, upload_data, *upload_data_size);
			*upload_data_size = 0;

			return MHD_YES;
		} else if (con_info->answerstring != NULL)
			return send_page (connection, con_info->answerstring);
	}

	else if (strcmp(url, "/stop") == 0)
		return stop(connection);
	else if (strcmp(url, "/list") == 0)
		return list(connection);
	else if (strcmp(url, "/check") == 0)
		return check(connection);

	file = fopen (&url[1], "rb"); // strip the first character "/" from the url, and open that.
	if (file != NULL){
		fd = fileno (file);
		if (-1 == fd){
			(void) fclose (file);
			return MHD_NO; /* internal error */
		}
		if ( (0 != fstat (fd, &buf)) || (! S_ISREG (buf.st_mode))){
			/* not a regular file, refuse to serve */
			fclose (file);
			file = NULL;
		}
	}

	if (file != NULL){
		response = MHD_create_response_from_callback (buf.st_size, 32 * 1024, &file_reader, file, &file_free_callback);
		if (response == NULL){
			fclose (file);
			return MHD_NO;
		}
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
	}
	return ret;
}

int checkfree(){
	struct statvfs stat;
	long size, free;
	float pfree;
	if (statvfs(path, &stat) != 0) return -1;
	size = stat.f_bsize * stat.f_blocks;
	free = stat.f_bsize * stat.f_bfree;
	pfree = ((float)free / (float)size) * 100.0;
	return (int)pfree;
}

static void reap(){
	struct dirent **namelist;
	int n;
	while (1){
		n = scandir(path, &namelist, *filter, *compar);
		if (n < 0) perror("scandir");
		else {
			while (n > 0) {
				n--;
				//TODO: activate reaper by uncommenting next line:
				//if (checkfree() < 90) unlink(namelist[n]->d_name);
				free(namelist[n]);
			}
			free(namelist);
		}
		sleep (5*60); // sleep for 5 minutes
	}
}

static void sig_shutdown(int signal){
	terminate = 1;
}

int main (int argc, char *const *argv){
	int daemonize = 1;
	int i;

	standalone = 0;
	hasRTC = 0;
	useWD = 0;

	printf("Optional Parameters:\n");
	printf("--------------------\n");
	printf("    --nodaemon      Do not daemonize.\n");
	printf("    --standalone    Begin recording automatically.\n");
	printf("    --rtc           Only use RTC as timesource, do not update from HTTP.\n");
	printf("    --watchdog      Stop recording automatically if check requests stop.\n");
	printf("\n");
	printf("Warning: --standalone and --watchdog are mutually exclusive parameters.\n\n");

	if (argc >= 2) for (i=1; i<argc; i++){
		if (strcmp(argv[i],"--nodaemon") == 0) daemonize = 0;
		if (strcmp(argv[i],"--standalone") == 0) standalone = 1;
		if (strcmp(argv[i],"--rtc") == 0) hasRTC = 1;
		if (strcmp(argv[i],"--watchdog") == 0) useWD = 1;
	}
	if (daemonize) daemon(0,0);

	struct MHD_Daemon *d;
	pid_t reaper;
	enum MHD_ValueKind bogus;

	port = 8888;
	strcpy(sdev,"/dev/mmcblk0p3");
	strcpy(path,"/mnt/data");

	char fsckcmd[1024];

	struct sigaction sigact;
	sigact.sa_handler = sig_shutdown;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGTERM, &sigact, (struct sigaction *)NULL);

	strcpy(fsckcmd, "fsck -a ");
	strcat(fsckcmd, sdev);

	chdir("/"); // change to rootfs
	umount2(sdev,MNT_FORCE); // unmount existing fs if mounted
	system(fsckcmd); // check and repair filesystem
	if (mount(sdev, path, "ext4", MS_MGC_VAL | MS_RDONLY, "") != 0){ // mount fs readonly
		printf("MOUNT ERROR!!!\n");
	}
	chdir(path); // enter data fs

	d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | 8 /*MHD_USE_INTERNAL_POLLING_THREAD*/ | 1 /*MHD_USE_ERROR_LOG*/, port, NULL, NULL, &handle_request, ERROR404, MHD_OPTION_END);
	if (d == NULL) return 1;

	reaper = fork();
	if (reaper == 0) reap();

	if (standalone) iterate_post (NULL, bogus, "record", NULL, NULL, NULL, "", 0, 0);

	lastbark = 0;
	while (!terminate){
		printf("lastbark: %lld\n",(long long) lastbark);
		if (useWD && ffmpeg != 0 && ((long long) lastbark) < ((long long) time(NULL)) - (3*60)){
			int status;
			if (ffmpeg != 0 && waitpid(ffmpeg, &status, WNOHANG) == 0){
				kill(ffmpeg, SIGTERM);
				waitpid(ffmpeg, NULL, 0);
				ffmpeg = 0;
				remountfs(0);
			}
		}
		sleep (10);
	}

	printf("Shutting everything down\n");

	// stop everything.
	if (ffmpeg != 0){
		kill(ffmpeg, SIGTERM);
		waitpid(ffmpeg, NULL, 0);
	}
	if (reaper != 0){
		kill(reaper, SIGKILL);
		waitpid(reaper, NULL, 0);
	}
	MHD_stop_daemon (d);
	chdir("/");
	sync();
	if (umount2(path,0) != 0) printf("UMOUNT2 ERROR!!! errno: %d\n",errno);
	else printf("UMOUNT2'ed\n");
	return 0;
}

