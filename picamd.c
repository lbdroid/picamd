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
#include <sqlite3.h>
#include <gps.h>
#include <pthread.h>

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
static int stoplogging = 0;
pthread_t gps_thread;

int port;
char path[1024];
char sdev[1024];
int useWD;
int hasRTC;
int standalone;

sqlite3 *db = NULL;
char *zErrMsg = 0;
int rc;

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

int compar(const struct dirent **pa, const struct dirent **pb){
	const char *a = (*pa)->d_name;
	const char *b = (*pb)->d_name;
	struct stat ainfo, binfo;
	if (stat(a, &ainfo) != 0 || stat(b, &binfo) != 0) return 0;
	if (ainfo.st_mtime == binfo.st_mtime) return 0;
	else if (ainfo.st_mtime < binfo.st_mtime) return 1;
	return -1;
}

int filter(const struct dirent *d){
        struct dirent a = *d;
        struct stat ainfo;
        stat(a.d_name, &ainfo);
	if(strstr(a.d_name, "CONFIG") != NULL) return 0; // do not list the CONFIG file.
        if(strstr(a.d_name, "gps.db") != NULL) return 0; // do not list the GPS log file.
        if(S_ISREG(ainfo.st_mode)) return 1;
        return 0;
}

int audiofilter(const struct dirent *d){
        struct dirent a = *d;
        struct stat ainfo;
        stat(a.d_name, &ainfo);
        if(strstr(a.d_name, "dsp") != NULL) return 1;
        return 0;
}

int videofilter(const struct dirent *d){
        struct dirent a = *d;
        struct stat ainfo;
        stat(a.d_name, &ainfo);
        if(strstr(a.d_name, "video") != NULL) return 1;
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
		stoplogging = 1;
	}

	if (db != NULL){
		sqlite3_close(db);
		db = NULL;
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

static int
getcams (struct MHD_Connection *connection){
	struct MHD_Response *response;
	int ret = MHD_NO;
	FILE *fp;
	char data[1024];
	char cmd[1024];
	char *xml, *p, *e, *c;
	xml = malloc(10240*sizeof(char));

	strcpy(xml, "<hardware>\n");
	struct dirent **namelist;
	int n = scandir("/dev/", &namelist, *audiofilter, alphasort);
	int i;
	for (i = 0; i < n; i++){
		strcat(xml, "<audiodev name=\"");
		strcat(xml, namelist[i]->d_name);
		strcat(xml, "\" />\n");
		free(namelist[i]);
	}
	free(namelist);

	n = scandir("/dev/", &namelist, *videofilter, alphasort);
	for (i = 0; i < n; i++){
		strcat(xml, "<videodev name=\"");
		strcat(xml, namelist[i]->d_name);
		strcat(xml, "\">");

		snprintf(cmd, 1023, "ffmpeg -hide_banner -f v4l2 -list_formats all -i /dev/%s 2>&1", namelist[i]->d_name);
		fp = popen(cmd, "r");
		if (fp != NULL){
			while (fgets(data, sizeof(path)-1, fp) != NULL){
				if ((p=strstr(data, "Raw")) != NULL || (p=strstr(data, "Compressed")) != NULL){
					strcat(xml, "<format type=\"");
					c = strchr(p, ':');
					e = strchr(p, ' ');
					if (e > c) e = c;
					strncpy(xml+strlen(xml), p, e-p);
					strcat(xml, "\" name=\"");
					p = c + 1;
					while(p[0]==' ')p++;
					c = strchr(p, ':');
					e = strchr(p, ' ');
					if (e > c) e = c;
					strncpy(xml+strlen(xml), p, e-p);
					strcat(xml, "\">");
					c++;
					c = strstr(c, " : ");
					p = c+3;
					e = strchr(p, '\n'); 
					if (strchr(p, '{') != NULL){
						// This is a RANGE, like "{32-2592, 2}x{32-1944, 2}"
						// dump in the range as a single resolution, handle it on other end.
						strcat(xml, "<resolution value=\"");
						strncpy(xml+strlen(xml), p, e-p);
						strcat(xml, "\" />");
					} else {
						// This is a set of distinct resolutions. Add each individually.
						e = strchr(p, ' ');
						while (e != NULL){
							strcat(xml, "<resolution value=\"");
							strncpy(xml+strlen(xml), p, e-p);
							strcat(xml, "\" />");

							p = e+1;
							e = strchr(p, ' ');
							if (e == NULL) e = strchr(p, '\n');
						}

					}
					strcat(xml, "</format>");
				}

			}
		}
		pclose(fp);

		strcat(xml, "</videodev>\n");
	}
	strcat(xml, "</hardware>\n");

	response = MHD_create_response_from_buffer (strlen (xml), xml, MHD_RESPMEM_MUST_COPY);
        if (response == NULL) return MHD_NO;
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING, "text/xml");
        MHD_destroy_response (response);

	free(xml);
	return ret;
}

static int
reboot (struct MHD_Connection *connection){
	struct MHD_Response *response;
	char xml[1024];
	int ret = MHD_NO;
	pid_t rbtpid = fork();

	if (fork() == 0){
		sleep(3);
		system("/sbin/reboot");
		exit(127);		
	}

	strcpy(xml, "<rebooting />");
	response = MHD_create_response_from_buffer (strlen (xml), xml, MHD_RESPMEM_MUST_COPY);
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

void *gpslog_fn(void *run){
	int ret;
	stoplogging = 0;
	char sqldata[1024];
	char nmea[1024];
	timestamp_t gpstime;
	int dbnull;
	struct gps_data_t gps_dat;
	ret = gps_open("localhost", "2947", &gps_dat);
	(void) gps_stream(&gps_dat, WATCH_ENABLE | WATCH_JSON | WATCH_NMEA, NULL);

	dbnull = (db == NULL);
	if (dbnull){
		if (sqlite3_open("/mnt/data/gps.db", &db)) db = NULL;
		else {
			sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS gps (time TEXT PRIMARY KEY DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), gpstime INT, value TEXT)", NULL, NULL, NULL);
			sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS prot (filename TEXT, time TEXT, gpstime INT, value TEXT)", NULL, NULL, NULL);
			sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
		}
	}

	while (db != NULL && stoplogging == 0){

		if (gps_waiting (&gps_dat, 2000000)) { // wait up to 2 seconds (2 million us) for data to appear
			errno = 0;
			if (gps_read (&gps_dat) != -1) {
				/* Display data from the GPS receiver. */
				strcpy(nmea, gps_data(&gps_dat));
				strchr(nmea, '\r')[0] = 0;
				if (nmea[0] == '$' && ((long)gps_dat.fix.time) != 0){
					snprintf(sqldata, 1023, "INSERT INTO gps (gpstime, value) VALUES (%ld, \"%s\")", (long)gps_dat.fix.time, nmea);
//					printf("SQL: %s\n",sqldata);
					sqlite3_exec(db, sqldata, NULL, NULL, NULL);
				}
			}
		}
	}

	if (dbnull) sqlite3_close(db);

	(void) gps_stream(&gps_dat, WATCH_DISABLE, NULL);
	(void) gps_close (&gps_dat);
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
	int dbnull = (db == NULL);
	char sqldata[1024];
	sqldata[0]=0;
	char date[32];
	date[0]=0;

	char gpslog[1024];

	if (strcmp(key,"protect") == 0){
		if (fsro) remountfs(1);
		if (rename(data, pfilename) == 0)
			snprintf(response,100,"<fileop status=\"success\" />");
		else snprintf(response,100,"<fileop status=\"error\" />");

		if (dbnull && sqlite3_open("gps.db", &db)){
			db = NULL;
			if (fsro) remountfs(0);
			return MHD_YES;
		}

		strncpy(date, data+4, 19);
		date[10]=' ';
		date[13]=':';
		date[16]=':';

		snprintf(sqldata, 1023, "INSERT INTO prot SELECT \"%s\" AS filename, time, gpstime, value FROM gps WHERE DATETIME(time, 'localtime') >= \"%s\" AND DATETIME(time, 'localtime') < DATETIME(\"%s\", \"+62 seconds\")", data, date, date);
		sqlite3_exec(db, sqldata, NULL, NULL, NULL);

		if (dbnull){
			sqlite3_close(db);
			db = NULL;
		}
		if (fsro) remountfs(0);
	} else if (strcmp(key,"unprotect") == 0){
		if (fsro) remountfs(1);
		if (rename(pfilename, data) == 0)
			snprintf(response,100,"<fileop status=\"success\" />");

		if (dbnull && sqlite3_open("gps.db", &db)){
			db = NULL;
			if (fsro) remountfs(0);
			return MHD_YES;
		}

		snprintf(sqldata, 1023, "DELETE FROM prot WHERE filename = \"%s\"", data);
		sqlite3_exec(db, sqldata, NULL, NULL, NULL);

		if (dbnull){
			sqlite3_close(db);
			db = NULL;
		}

		else snprintf(response,100,"<fileop status=\"error\" />");
		if (fsro) remountfs(0);
	} else if (strcmp(key,"delete") == 0){
		if (fsro) remountfs(1);
		if (unlink(data) == 0) snprintf(response,100,"<fileop status=\"success\" />");
		else snprintf(response,100,"<fileop status=\"error\" />");
		if (fsro) remountfs(0);
	} else if (strcmp(key,"gpslog") == 0){
		if (!fsro && ffmpeg > 0){
			if (db == NULL){
				if (sqlite3_open("gps.db", &db)) db = NULL;
				else {
					sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS gps (time TEXT PRIMARY KEY DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), gpstime INT, value TEXT)", NULL, 0, &zErrMsg);
					sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS prot (filename TEXT, time TEXT, gpstime INT, value TEXT)", NULL, NULL, NULL);
					sqlite3_exec(db, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
				}
				if (zErrMsg != NULL) sqlite3_free(zErrMsg);
			}
			if (db != NULL){
				char nmea[1024];
				char *c = strchr(data,':');
				if (c != NULL) strncpy(nmea, data, c - data);
				snprintf(response, 1023, "INSERT INTO gps (gpstime, value) VALUES (%s, \"%s\")", c+1, data);
				rc = sqlite3_exec(db, response, NULL, 0, &zErrMsg);
				if( rc!=SQLITE_OK ){
					snprintf(response,100,"<gpslog status=\"error\" value=\"%s\" />", zErrMsg);
					sqlite3_free(zErrMsg);
				} else
					snprintf(response,100,"<gpslog status=\"stored\" />");
			} else snprintf(response,100,"<gpslog status=\"error\" value=\"Cannot open database\" />");
		} else snprintf(response,100,"<gpslog status=\"not recording\" />");
	} else if (strcmp(key,"record") == 0){
		int status;
		if (ffmpeg == 0 || (ffmpeg > 0 && waitpid(ffmpeg, &status, WNOHANG) != 0)){
			if (fsro) remountfs(1);
			if (!hasRTC && !standalone){
				time_t current_time = atoi(data);
				stime(&current_time); // update the system time with the value from the parameter,
			}
			int blob;
			if (strcmp(data, "gps") == 0) pthread_create(&gps_thread, NULL, gpslog_fn, (void* )blob);
			lastbark = time(NULL);
			ffmpeg = fork();
			if (ffmpeg == 0){
				chdir(path); // make sure that this child is actually in the proper path.

				FILE *fp;
				char *line = NULL;
				size_t len = 0;
				ssize_t read;

				int prefix = 0;
				char params[1024];
				params[0] = 0;
				char extracmd[1024];
				extracmd[0] = 0;

				char *allextras;
				allextras = malloc(10240);
				allextras[0] = 0;

				char paramset[2048];
				paramset[0]=0;

				int i;
				fp = fopen("/mnt/data/CONFIG", "r");
				if (fp != NULL){
					while ((read = getline(&line, &len, fp)) != -1){
						if (read > 0){
							if (strstr(line, "params=") != NULL){
								strcpy(params, &line[7]);
								for (i=0; i<strlen(params); i++) if (params[i] == '\n') params[i] = 0; // remove trailing newline
							} else if (strstr(line, "prefix=") != NULL){
								prefix=atoi(&line[7]);
							} else if (strstr(line, "extra=") != NULL){
								strcpy(extracmd, &line[6]);
								system(extracmd);
								strcat(allextras, "extra=");
								strcat(allextras, extracmd);
								strcat(allextras, "\n");
							}
						}
					}
					fclose(fp);
				}
				i == 0;
				if (strlen(params) == 0){
					strcpy(params, "-f video4linux2 -input_format h264 -video_size 640x480 -i /dev/video0 -c:v copy");
					i = 1;
				}
				if (i || (standalone && !hasRTC)){
					fp = fopen("/mnt/data/CONFIG", "w+");
					if (fp != NULL){
						fprintf(fp, "params=%s\nprefix=%d\n%s",params,(standalone && !hasRTC)?prefix+1:prefix,allextras);
						fclose(fp);
					}
				}
				if (strlen(params) > 0){
					if (standalone && !hasRTC)
						sprintf(paramset, "ffmpeg %s -f segment -segment_time 60 -reset_timestamps 1", params);
					else
						sprintf(paramset, "ffmpeg %s -f segment -strftime 1 -segment_time 60 -segment_atclocktime 1 -reset_timestamps 1", params);

					char ** res  = NULL;
					char *  p    = strtok (paramset, " ");
					int n_spaces = 0;

					while (p) {
						res = realloc (res, sizeof (char*) * ++n_spaces);
						if (res == NULL) break;
						printf("loop: n_spaces: %d\n",n_spaces);
						res[n_spaces-1] = p;
						p = strtok (NULL, " ");
					}
					res = realloc (res, sizeof (char*) * (n_spaces+1)); // realloc to 22 pointers.
					n_spaces++; // increment to 22
					res[n_spaces-1] = malloc(48); // allocate a new string length 48 at index 21, the 22nd data element
					res[n_spaces-1][0] = 0;
					if (standalone && !hasRTC){
						sprintf(res[n_spaces-1], "cam_%06d_", prefix);
						strcat(res[n_spaces-1], "\%04d.mkv");
					} else
						strcpy(res[n_spaces-1], "cam_\%Y-\%m-\%d_\%H-\%M-\%S.mkv");

					res = realloc (res, sizeof (char*) * (n_spaces+1)); // realloc to 23 pointers
					res[n_spaces] = 0; // set 23rd pointer to NULL.

					for (i = 0; i < (n_spaces+1); ++i)
						printf ("res[%d] = %s\n", i, res[i]);

					// This (res) is actually a memory leak, but it should clear up when the child exits.
					nice(-20);
					if (res != NULL) execv("/bin/ffmpeg",res);
				}
				if (db != NULL){
					sqlite3_close(db);
					db = NULL;
				}
				stoplogging = 1;
				remountfs(0);
				exit(127);
			} else if (ffmpeg < 0){
				remountfs(0);
				snprintf(response,100,"<ffmpeg status=\"error\" />");
			} else
				snprintf(response,100,"<ffmpeg status=\"running\" />");
		} else
			snprintf(response,100,"<ffmpeg status=\"running\" />");
	} else if (strcmp(key,"setcams") == 0){
		int prefix = 0;
		int i;
		FILE *fp;
		char *line = NULL;
		size_t len = 0;
		ssize_t read;

		char params[1024];
		char *extra;
		char *extradata;
		extradata = malloc(strlen(data)+1);
		strcpy(extradata, data);

		fp = fopen("/mnt/data/CONFIG", "r");
		if (fp != NULL){
			while ((read = getline(&line, &len, fp)) != -1)
				if (read > 0 && strstr(line, "prefix=") != NULL) prefix=atoi(&line[7]);
			fclose(fp);
		}
		if (fsro) remountfs(1);
		fp = fopen("/mnt/data/CONFIG", "w+");
		if (fp != NULL){
			strncpy(params, extradata, (char*)strchrnul(extradata, ':') - extradata);
			fprintf(fp, "params=%s\nprefix=%d\n",params,prefix);
			extra=extradata;
			while((extra=(char*)strchrnul(extra, ':')+1) < extradata+strlen(extradata)){
				strncpy(params, extra, (char*)strchrnul(extra, ':')-extra);
				fprintf(fp, "extra=%s\n", params);
			}
			fclose(fp);
			snprintf(response,100,"<settings status=\"success\" />");
		} else snprintf(response,100,"<settings status=\"failure\" />");
		free(extradata);
		if (fsro) remountfs(0);
	} else if (strcmp(key,"setwifi") == 0){
		char ssid[128], psk[128], keymgmt[128];
		char *p, *e, *mdata;
		FILE *fp;
                mount ("/dev/mmcblk0p2", "/ro", "ext4", MS_MGC_VAL | MS_REMOUNT, NULL);
		fp = fopen("/ro/etc/wpa_supplicant/wpa_supplicant.conf", "w+");
		if (fp != NULL){
			mdata = malloc(strlen(data));
			strcpy(mdata, data);
			p = mdata;
			e = strchr(p, ':');
			strncpy(ssid, p, e-p);
			p = e+1;
			e = strchr(p, ':');
			strncpy(psk, p, e-p);
			p = e+1;
			strncpy(keymgmt, p, strlen(p));
			free(mdata);
			fprintf(fp, "country=GB\nctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\nnetwork={\n  ssid=\"%s\"\n  psk=\"%s\"\n  key_mgmt=%s\n}\n", ssid, psk, keymgmt);
		}
                sync();
                mount ("/dev/mmcblk0p2", "/ro", "ext4", MS_MGC_VAL | MS_REMOUNT | MS_RDONLY, NULL);
		snprintf(response,100,"<settings status=\"success\" note=\"Recommend rebooting now...\" />");
	} else if (strcmp(key, "delete") == 0){
		char dpath[1024];
		if (fsro) remountfs(1);
		snprintf(dpath, 1023, "/mnt/data/%s", data);
		unlink(dpath);
		snprintf(dpath, 1023, "/mnt/data/protected/%s", data);
		unlink(dpath);
		if (fsro) remountfs(0);
	}
    
	if (con_info != NULL){
		con_info->answerstring = malloc(MAXANSWERSIZE);
		snprintf(con_info->answerstring, MAXANSWERSIZE, response);
	}

	return MHD_YES;
}

long startgpstime=0, lastgpstime=0;
int seq = 0;
static int gpslog_cb(void *data, int argc, char **argv, char **colName){
	FILE *file = (FILE *)data;

	long gpstime;
	char nmea[1024];
	char outline[1024];

	int i;
	int dt, ss, ms, hs, se, me, he;
	for (i=0; i<argc; i++){
		if (strstr(colName[i],"gpstime") != NULL) gpstime = atol(argv[i]);
		if (strstr(colName[i],"value") != NULL) strcpy(nmea, argv[i]);
	}

	if (seq == 0) startgpstime = gpstime;

	if (gpstime > lastgpstime){
		if (seq > 0) fprintf(file, "\n");

		dt = gpstime-startgpstime;
		ss = dt%60;
		dt = (dt-ss)/60;
		ms = dt%60;
		hs = (dt-ms)/60;
		dt = gpstime-startgpstime+1;
		se = dt%60;
		dt = (dt-se)/60;
		me = dt%60;
		he = (dt-me)/60;

		fprintf(file, "%d\n%02ld:%02ld:%02ld,000 --> %02ld:%02ld:%02ld,000\n", gpstime-startgpstime+1, hs, ms, ss, he, me, se);
		seq++;
		lastgpstime = gpstime;
	}
	fprintf(file, "%s\n", nmea);

	return 0;
}

static int
get_gps_cb (void *cls, enum MHD_ValueKind kind, const char *key , const char* value){
	if (strstr(key, "gpslog") != NULL) *(int *) cls = 1;
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
	int getgpslog = 0;

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

	if (strstr(url, "favicon") != NULL) return not_found_page(connection); // tell anything asking for favicon to drop dead.

    if (strcmp (method, "GET") == 0)
        MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, get_gps_cb, &getgpslog);

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
	else if (strcmp(url, "/getcams") == 0)
		return getcams(connection);
	else if (strcmp(url, "/reboot") == 0)
		return reboot(connection);

	char *sql;
	char *start;
	char dpath[128];
	char srtpath[64];
	char fndate[64];
	int isprot = 0;
	int dbnull = (db == NULL);

	if (getgpslog){
		strcpy(dpath, url);
		start = strrchr(dpath, '/')+1;
		if (start-dpath > 1) isprot = 1;
		if (dbnull && sqlite3_open("gps.db", &db)){
			db = NULL;
			return MHD_NO;
		}
		strcpy(srtpath,"/tmp/");
		strcat(srtpath,start);
		srtpath[strlen(srtpath)-3]='s';
		srtpath[strlen(srtpath)-2]='r';
		srtpath[strlen(srtpath)-1]='t';

		strncpy(fndate, start+4, 19);
		fndate[10]=' ';
		fndate[13]=':';
		fndate[16]=':';

		char tmppath[64];
		strcpy(tmppath,"/tmp/");
		strcat(tmppath,start);

		sql = malloc(1024);
		if (isprot) snprintf(sql, 1023, "SELECT gpstime, value FROM prot WHERE filename=\"%s\" ORDER BY time ASC", start);
		else snprintf(sql, 1023, "SELECT gpstime, value FROM gps WHERE DATETIME(time, 'localtime') >= \"%s\" AND DATETIME(time, 'localtime') < DATETIME(\"%s\", \"+62 seconds\") ORDER BY time ASC", fndate, fndate);
		FILE *srt = fopen(srtpath, "w+");
		sqlite3_exec(db, sql, gpslog_cb, (void *)srt, NULL);
		fclose(srt);
		if (dbnull) sqlite3_close(db);

		char cmd[512];
		snprintf(cmd, 511, "/bin/ffmpeg -i %s -f srt -i %s -c copy -map 0 -map 1:s %s", dpath+1, srtpath, tmppath);
		system(cmd);

		file = fopen(tmppath, "rb");
		unlink(srtpath);
		unlink(tmppath);
	} else
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
        float pfree;
        if (statvfs(path, &stat) != 0) return -1;
        pfree = ((float)stat.f_bfree / (float)stat.f_blocks) * 100.0;
        printf("Free space: %f\% (float), %d\% (int)\n", pfree, (int)pfree);
        return (int)pfree;
}

static void reap(){
	struct dirent **namelist;
	int n;
	char oldest[32];
	char sql[1024];
	while (1){
		if (!isfsro() && checkfree() < (100 - 90)){
			if (standalone && !hasRTC) n = scandir(path, &namelist, *filter, alphasort);
			else n = scandir(path, &namelist, *filter, *compar);
			if (n < 0) perror("scandir");
			else {
				while (n > 0) {
					n--;
					if (checkfree() < (100 - 90)){
						unlink(namelist[n]->d_name);
						strncpy(oldest, namelist[n-1]->d_name+4, 19);
					}
					free(namelist[n]);
				}
				free(namelist);
			}
			if (db == NULL && sqlite3_open("gps.db", &db)) db = NULL;
			if (db != NULL){
				oldest[10]=' ';
				oldest[13]=':';
				oldest[16]=':';
				snprintf(sql, 1023, "DELETE FROM gps WHERE time < DATETIME(\"%s\", \"-10 seconds\")", oldest);
				rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
			}
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
	printf("MANDATORY Configurations:\n");
	printf("-------------------------\n");
	printf("	Config file is to be located at /mnt/data/CONFIG\n");
	printf("	There are to be two lines in it, of which the first (params=) MUST be adjusted\n");
	printf("	to match YOUR cameras.\n\n");
	printf("	The params= line is the *device specific part* of the ffmpeg commandline to run\n\n");
	printf("	Example:\n");
	printf("	params=-f video4linux2 -input_format h264 -video_size 640x480 -i /dev/video0 -c:v copy\n\n");
	printf("	Example 2 (two cameras, first h264 at /dev/video1, second mjpeg at /dev/video2:\n");
	printf("	params=-f video4linux2 -input_format h264 -video_size 1280x720 -i /dev/video1 -c:v copy -f video4linux2 -input_format mjpeg -video_size 1280x720 -i /dev/video3 -c:v copy -map 0 -map 1\n\n");

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
	if (access(sdev, F_OK) != -1){
		system(fsckcmd); // check and repair filesystem
	} else {
		exit(1); //ABORT, storage path does not exist
	}
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
		//printf("lastbark: %lld\n",(long long) lastbark);
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
	if (db != NULL) sqlite3_close(db);
	sync();
	if (umount2(path,0) != 0) printf("UMOUNT2 ERROR!!! errno: %d\n",errno);
	else printf("UMOUNT2'ed\n");
	return 0;
}

