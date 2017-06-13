#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
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

static int
not_found_page (struct MHD_Connection *connection);

struct connection_info_struct
{
  int connectiontype;
  char *answerstring;
  struct MHD_PostProcessor *postprocessor;
};

/**
 * Handler used to generate a 404 reply.
 * @param connection connection to use
 */
static int
ok_page (struct MHD_Connection *connection)
{
  int ret;
  struct MHD_Response *response;

  /* unsupported HTTP method */
  response = MHD_create_response_from_buffer (strlen (PAGEOK),
					      (void *) PAGEOK,
					      MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (connection,
			    MHD_HTTP_OK,
			    response);
  MHD_add_response_header (response,
			   MHD_HTTP_HEADER_CONTENT_ENCODING,
			   "text/html");
  MHD_destroy_response (response);
  return ret;
}

static int
stop (struct MHD_Connection *connection){
  char emsg[1024];
  struct MHD_Response *response;
  int ret;

  if (ffmpeg == 0)
    snprintf(emsg, sizeof(emsg), "not started");
  else {
    int status;
    pid_t pid = waitpid(ffmpeg, &status, WNOHANG);
    if (pid == 0){
      kill(ffmpeg, SIGTERM);
      waitpid(ffmpeg, NULL, 0);
      snprintf(emsg, sizeof(emsg), "terminated");
    } else if (pid < 0)
      snprintf(emsg, sizeof(emsg), "error");
    else
      snprintf(emsg, sizeof(emsg), "terminated");
  }

  response = MHD_create_response_from_buffer (strlen (emsg), emsg, MHD_RESPMEM_MUST_COPY);
  if (response == NULL)
    return MHD_NO;
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/plain");
  MHD_destroy_response (response);
  return ret;
}

static int
check (struct MHD_Connection *connection){
  char emsg[1024];
  struct MHD_Response *response;
  int ret;

  if (ffmpeg == 0)
    snprintf(emsg, sizeof(emsg), "not started");
  else {
    int status;
    pid_t pid = waitpid(ffmpeg, &status, WNOHANG);
    if (pid == 0)
      snprintf(emsg, sizeof(emsg), "running");
    else if (pid < 0)
      snprintf(emsg, sizeof(emsg), "error");
    else
      snprintf(emsg, sizeof(emsg), "terminated");
  }

  response = MHD_create_response_from_buffer (strlen (emsg), emsg, MHD_RESPMEM_MUST_COPY);
  if (response == NULL)
    return MHD_NO;
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/plain");
  MHD_destroy_response (response);
  return ret;
}

static ssize_t
file_reader (void *cls, uint64_t pos, char *buf, size_t max)
{
  FILE *file = cls;

  (void) fseek (file, pos, SEEK_SET);
  return fread (buf, 1, max, file);
}

static void
file_free_callback (void *cls)
{
  FILE *file = cls;
  fclose (file);
}

static void
dir_free_callback (void *cls)
{
  DIR *dir = cls;
  if (dir != NULL)
    closedir (dir);
}

static ssize_t
dir_reader (void *cls, uint64_t pos, char *buf, size_t max)
{
  DIR *dir = cls;
  int i = 0;
  struct dirent *e;
  long td;

  if (max < 512)
    return 0;
  if (pos == 0)
    return snprintf(buf, max, "<files>\n");
  do { // keep reading the next file from the directory until we find the next valid one -- skip invalid files.
    td = telldir(dir);
    e = readdir (dir);
    if (e != NULL) printf("e->d_name: %s\n", e->d_name);
    else break; // break if we just read past the last directory entry
    i++; // counts the number of entried processed.
  } while (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 || strcmp(e->d_name, "protected") == 0);
  printf("Adding data, position=%d\n",pos);

  // If this NULL was the very first entry on this run, then we already closed the files tag, so return end of stream.
  if (e == NULL && i == 0) return MHD_CONTENT_READER_END_OF_STREAM;

  // read the current position in the filesystem, peek at the next one, and then return to this one.
  // if the NEXT entry is NULL, then we either just close the tag (e==NULL), or add the file AND close the tag.
  td = telldir(dir);
  if (e == NULL) return snprintf (buf, max, "</files>\n");
  else if (readdir(dir) == NULL) return snprintf (buf, max, "<file name=\"%s\"/>\n</files>\n", e->d_name);
  seekdir(dir, td);

  return snprintf (buf, max, "<file name=\"%s\"/>\n", e->d_name);
}

static int
list (struct MHD_Connection *connection, int protected){
  DIR *dir;
  char emsg[1024];
  struct MHD_Response *response;
  int ret;

  if (protected) dir = opendir("protected");
  else dir = opendir(".");
  if (dir == NULL){
    snprintf (emsg, sizeof (emsg), "Failed to open directory `.': %s\n", strerror (errno));
    response = MHD_create_response_from_buffer (strlen (emsg), emsg, MHD_RESPMEM_MUST_COPY);
    if (response == NULL)
      return MHD_NO;
    ret = MHD_queue_response (connection, MHD_HTTP_SERVICE_UNAVAILABLE, response);
    MHD_add_response_header (response,
			   MHD_HTTP_HEADER_CONTENT_ENCODING,
			   "text/xml");
    MHD_destroy_response (response);
  } else {
    response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN, 32 * 1024, &dir_reader, dir, &dir_free_callback);
    if (response == NULL){
      closedir(dir);
      return MHD_NO;
    }
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
  }
  return ret;
}

/**
 * Handler used to generate a 404 reply.
 * @param connection connection to use
 */
static int
not_found_page (struct MHD_Connection *connection)
{
  int ret;
  struct MHD_Response *response;

  /* unsupported HTTP method */
  response = MHD_create_response_from_buffer (strlen (ERROR404),
					      (void *) ERROR404,
					      MHD_RESPMEM_PERSISTENT);
  if (NULL == response)
    return MHD_NO;
  ret = MHD_queue_response (connection,
			    MHD_HTTP_NOT_FOUND,
			    response);
  MHD_add_response_header (response,
			   MHD_HTTP_HEADER_CONTENT_ENCODING,
			   "text/html");
  MHD_destroy_response (response);
  return ret;
}

static int
send_page (struct MHD_Connection *connection, const char *page)
{
  int ret;
  struct MHD_Response *response;


  response =
    MHD_create_response_from_buffer (strlen (page), (void *) page,
				     MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;

  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

static int
iterate_post (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size)
{
  struct connection_info_struct *con_info = coninfo_cls;

  char pfilename[1024];
  snprintf(pfilename, 1023, "protected/%s", data);
  char response[100];

  if (strcmp(key,"protect") == 0){
    if (rename(data, pfilename) == 0)
      snprintf(response,100,"protected\n");
    else snprintf(response,100,"protect error\n");
  } else if (strcmp(key,"unprotect") == 0){
    if (rename(pfilename, data) == 0)
      snprintf(response,100,"unprotected\n");
    else snprintf(response,100,"unprotect error\n");
  } else if (strcmp(key,"record") == 0){
    int status;
    if (ffmpeg == 0 || (ffmpeg > 0 && waitpid(ffmpeg, &status, WNOHANG) != 0)){
      time_t current_time = atoi(data);
      stime(&current_time); // update the system time with the value from the parameter,
      ffmpeg = fork();
      if (ffmpeg == 0){
// /home/pi/bin/ffmpeg -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video0 -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video2 -c:v copy -map 0 -map 1 -f segment -segment_time 60 -reset_timestamps 1 test%03d.mkv
// /home/pi/bin/ffmpeg -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video0 -f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video2 -c:v copy -map 0 -map 1 -f segment -strftime 1 -segment_time 60 -segment_atclocktime 1 -reset_timestamps 1 cam_%Y-%m-%d_%H-%M-%S.mkv
        static char *argv[]={"ffmpeg","-f","video4linux2","-input_format","h264","-video_size","1280x720","-i","/dev/video0","-f","video4linux2","-input_format","h264","-video_size","1280x720","-i","/dev/video2","-c:v","copy","-map","0","-map","1","-f","segment","-strftime","1","-segment_time","60","-segment_atclocktime","1","-reset_timestamps","1","cam_\%Y-\%m-\%d_\%H-\%M-\%S.mkv",NULL};
        execv("/home/pi/bin/ffmpeg",argv);
        exit(127);
      } else if (ffmpeg < 0)
        snprintf(response,100,"fork error\n");
      else
        snprintf(response,100,"fork success\n");
    } else
      snprintf(response,100,"ffmpeg already running\n");
  }
    
  con_info->answerstring = malloc(MAXANSWERSIZE);
  snprintf(con_info->answerstring, MAXANSWERSIZE, response);

  return MHD_YES;
}


static int
handle_request (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data,
	  size_t *upload_data_size, void **con_cls)
{
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

  if (0 == strcmp (method, "POST")){
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
    return list(connection, 0);
  else if (strcmp(url, "/listprotected") == 0)
    return list(connection, 1);
  else if (strcmp(url, "/check") == 0)
    return check(connection);

  file = fopen (&url[1], "rb"); // strip the first character "/" from the url, and open that.
  if (NULL != file)
    {
      fd = fileno (file);
      if (-1 == fd)
        {
          (void) fclose (file);
          return MHD_NO; /* internal error */
        }
      if ( (0 != fstat (fd, &buf)) ||
           (! S_ISREG (buf.st_mode)) )
        {
          /* not a regular file, refuse to serve */
          fclose (file);
          file = NULL;
        }
    }

  if (file != NULL)
    {
      response = MHD_create_response_from_callback (buf.st_size, 32 * 1024,     /* 32k page size */
                                                    &file_reader,
                                                    file,
                                                    &file_free_callback);
      if (NULL == response)
	{
	  fclose (file);
	  return MHD_NO;
	}
      ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
    }
  return ret;
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

int checkfree(){
	struct statvfs stat;
	long size, free;
	float pfree;
	if (statvfs(".", &stat) != 0) return -1;
	size = stat.f_bsize * stat.f_blocks;
	free = stat.f_bsize * stat.f_bfree;
	pfree = ((float)free / (float)size) * 100.0;
	return (int)pfree;
}

static void reap(){
	struct dirent **namelist;
	int n;
	while (1){
		n = scandir(".", &namelist, *filter, *compar);
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

int main (int argc, char *const *argv){
  struct MHD_Daemon *d;
  pid_t reaper;

  if (argc != 2) {
    printf ("%s PORT\n", argv[0]);
    return 1;
  }

  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
                        atoi (argv[1]), NULL, NULL, &handle_request, ERROR404, MHD_OPTION_END);
  if (d == NULL) return 1;

  reaper = fork();
  if (reaper == 0) reap();

  (void) getc (stdin);
  // stop everything.
  kill(ffmpeg, SIGTERM);
  waitpid(ffmpeg, NULL, 0);
  kill(reaper, SIGKILL);
  waitpid(reaper, NULL, 0);
  MHD_stop_daemon (d);
  return 0;
}

