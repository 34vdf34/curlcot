 /* 
  * curlcot - connect to CoT server and receive updates to sqlite
  * 
  * Copyright (C) 2022 Resilience Theatre
  * 
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of the GNU General Public License
  * as published by the Free Software Foundation; either version 2
  * of the License, or (at your option) any later version.
  * 
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  * 
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
  *  
  * Based on curl examples by: 
  * 
  * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
  * 
  * Dependency: libcurl (sudo apt install libcurl4-nss-dev)
  * 			libcurl4-openssl-dev
  * 			libsqlite3-dev
  * 
  * curl --http0.9 --cacert server.crt.pem --cert-type P12 --cert gateway.p12:atakatak https://gw:8089
  * 
  * NOTE: Check this with Makefile change instead:
  *  
  * /usr/include$ sudo ln -s libxml2/libxml/ .
  * 
  * https://www.developer.com/database/libxml2-everything-you-need-in-an-xml-library/
  * https://www.tutorialspoint.com/sqlite/sqlite_c_cpp.htm
  * 
  */
  
#include <stdio.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h> 
#include <stdlib.h>
#include <time.h>
#include <libxml/parser.h>
#include <sqlite3.h>
#include "log.h"
#include "ini.h"

#define DATABASE "test.db"
#define ENTRYLEN 30

char e_type[ENTRYLEN];
char e_time[ENTRYLEN];
char e_lat[ENTRYLEN];
char e_lon[ENTRYLEN];
char e_callsign[ENTRYLEN];

const unsigned char c_type[] = "type";
const unsigned char c_time[] = "time";
const unsigned char c_lat[] = "lat";
const unsigned char c_lon[] = "lon";
const unsigned char c_callsign[] = "callsign";

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int insert_db_data(char *name, char *lat, char *lon, char *time, char *event)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char sql[500];
	memset(sql,0,500);
	/* Open database */
	rc = sqlite3_open("test.db", &db);
	if( rc ) {
		log_error("[%d] Can't open database %s",getpid(), sqlite3_errmsg(db));
		return(0);
	} else {
		log_info("[%d] DB opened successfully",getpid());
	}
	/* Create SQL statement */
	sprintf(sql,"INSERT INTO COT_DATA (NAME,LAT,LON,TIME,EVENT) \
	VALUES ('%s','%s','%s','%s','%s' );", name,lat,lon,time,event); 
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		log_error("[%d] SQL error: %s",getpid(),zErrMsg);
		sqlite3_free(zErrMsg);
	} else {
		log_info("[%d] DB updated successfully",getpid());
	}
	sqlite3_close(db);
	return 0;
}

int create_db_table()
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char *sql;
	/* Open database */
	rc = sqlite3_open(DATABASE, &db);
	if( rc ) {
		log_error("[%d] Can't open database %s",getpid(),sqlite3_errmsg(db));
		return(0);
	} else {
		log_info("[%d] DB opened successfully",getpid());
	}
	/* Create SQL statement */
	sql = "CREATE TABLE COT_DATA("  \
	  "ID INTEGER PRIMARY KEY AUTOINCREMENT," \
	  "NAME TEXT NOT NULL," \
	  "LAT  TEXT NOT NULL," \
	  "LON  TEXT NOT NULL," \
	  "TIME	 TEXT NOT NULL," \
	  "EVENT TEXT NOT NULL );";
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		log_error("[%d] SQL error: %s",getpid(),zErrMsg);
		sqlite3_free(zErrMsg);
	} else {
		log_info("[%d] DB table created successfully",getpid());
	}
	sqlite3_close(db);
	return 0;
}

int write_db()
{
	sqlite3 *db;
	int rc;
	rc = sqlite3_open(DATABASE, &db);
	if( rc ) {
	  log_error("[%d] SQL error: %s",getpid(),sqlite3_errmsg(db));
	  return(0);
	} else {
	  log_info("[%d] DB opened successfully",getpid());
	}
	sqlite3_close(db);
	return 0;
}
 
int is_leaf(xmlNode * node)
{
	xmlNode * child = node->children;
	while(child)
	{
		if(child->type == XML_ELEMENT_NODE) return 0;
		
		child = child->next;
	}
	return 1;
}

void print_xml(xmlNode * node, int indent_len)
{
	unsigned char *stored_c_type = NULL;
	unsigned char *stored_c_time = NULL;
	unsigned char *stored_c_lat = NULL;
	unsigned char *stored_c_lon = NULL;
	unsigned char *stored_c_callsign = NULL;
	
	while(node)
    {
        if(node->type == XML_ELEMENT_NODE)
        {
			if ( strcmp("event",(char*)node->name) == 0) {
				stored_c_type = xmlGetProp(node, c_type);
				stored_c_time = xmlGetProp(node, c_time);
				log_info("[%d] stored_c_type: %s  ",getpid(), stored_c_type  );
				log_info("[%d] stored_c_time: %s  ",getpid(), stored_c_time  );
				strcpy(e_type, (char *)stored_c_type );
				strcpy(e_time, (char *)stored_c_time );
				xmlFree(stored_c_type);
				xmlFree(stored_c_time);
			}
			if ( strcmp("point",(char*)node->name) == 0) {
				stored_c_lat = xmlGetProp(node, c_lat);
				stored_c_lon = xmlGetProp(node, c_lon);
				log_info("[%d] stored_c_lat: %s  ",getpid(), stored_c_lat  );
				log_info("[%d] stored_c_lon: %s  ",getpid(), stored_c_lon  );
				strcpy(e_lat, (char *)stored_c_lat );
				strcpy(e_lon, (char *)stored_c_lon );
				xmlFree(stored_c_lat);
				xmlFree(stored_c_lon);				
			}
			if ( strcmp("contact",(char*)node->name) == 0) {
				stored_c_callsign = xmlGetProp(node, c_callsign);
				log_info("[%d] stored_c_callsign: %s  ",getpid(), stored_c_callsign  );
				strcpy(e_callsign, (char *) stored_c_callsign );
				xmlFree(stored_c_callsign);
			}
        }
        print_xml(node->children, indent_len + 1);
        node = node->next;
    }

}


/* Change log level to LOG_DEBUG to show raw data */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	log_info("[%d] write_data() ",getpid());
	log_debug("[%d] write_data() Payload: %s ",getpid(),ptr);
	log_debug("[%d] write_data() Payload size: %d ",getpid(),nmemb);
	/* Parse XML */
	xmlDoc         *document=NULL;
	xmlNode        *root=NULL; 
	document = xmlReadMemory(ptr,nmemb,NULL,NULL,0);
	root = xmlDocGetRootElement(document);
	print_xml(root, 3);
	xmlFreeDoc(document);
	// Update DB 
	insert_db_data(e_callsign,e_lat,e_lon,e_time,e_type);
	// Clean 
	memset(e_type,0,ENTRYLEN);
	memset(e_time,0,ENTRYLEN);
	memset(e_lat,0,ENTRYLEN);
	memset(e_lon,0,ENTRYLEN);
	memset(e_callsign,0,ENTRYLEN);
	return nmemb;
}

int main(int argc, char *argv[])
{
	char *ini_file=NULL;
	char *server_address = "";
	char *client_cert="";
	char *client_key="";
	char *client_key_password="";
	char *ca_cert="";
	char *cn_override_to_localhost="";
	char *port_override_to_localhost="";
	int c=0;
	int log_level=LOG_INFO;
	
	/* DB */
	write_db();
	create_db_table();
	xmlInitParser();
	
	while ((c = getopt (argc, argv, "dhi:")) != -1)
	switch (c)
	{
		case 'd':
			log_level=LOG_DEBUG;
			break;
		case 'i':
			ini_file = optarg;
			break;
		case 'h':
			log_info("[%d] curlcot",getpid());
			log_info("[%d] Usage: -i [ini_file] ",getpid());
			log_info("[%d]        -d debug log ",getpid());
			return 1;
		break;
			default:
			break;
	}
	if (ini_file == NULL) 
	{
		log_error("[%d] ini file not specified, exiting. ", getpid());
		return 0;
	}
	/* Set log level: LOG_INFO, LOG_DEBUG */
	log_set_level(log_level);
	
	/* read ini-file */
	ini_t *config = ini_load(ini_file);
	ini_sget(config, "curlcot", "server_address", NULL, &server_address);
	ini_sget(config, "curlcot", "client_cert", NULL, &client_cert);
	ini_sget(config, "curlcot", "client_key", NULL, &client_key);
	ini_sget(config, "curlcot", "client_key_password", NULL, &client_key_password);
	ini_sget(config, "curlcot", "ca_cert", NULL, &ca_cert);
	ini_sget(config, "curlcot", "cn_override_to_localhost", NULL, &cn_override_to_localhost);
	ini_sget(config, "curlcot", "port_override_to_localhost", NULL, &port_override_to_localhost); 
	log_info("[%d] Server address: %s ",getpid(),server_address);
	log_info("[%d] Client cert %s",getpid(),client_cert);
	log_info("[%d] Client key: %s",getpid(),client_key);
	log_debug("[%d] Client key password: %s ",getpid(),client_key_password);
	log_info("[%d] CA-cert: %s ",getpid(),ca_cert);
	/* Init CURL */ 
	CURL *curl;
	CURLcode res;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	char errbuf[CURL_ERROR_SIZE];

	curl = curl_easy_init();

	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, server_address); 
		curl_easy_setopt(curl, CURLOPT_HTTP09_ALLOWED, 1L);
			/* provide a buffer to store errors in */
			curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
			errbuf[0] = 0;

			struct curl_slist *dns;
			char dns_override_entry[256];
			memset(dns_override_entry,0,256);
			sprintf(dns_override_entry, "%s:%s:127.0.0.1",cn_override_to_localhost,port_override_to_localhost);
			
			dns = curl_slist_append(NULL, dns_override_entry);
			curl_easy_setopt(curl, CURLOPT_RESOLVE, dns);

			/* keep reconnecting */
			curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
			curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
			if(client_key_password) {
				curl_easy_setopt(curl, CURLOPT_KEYPASSWD, client_key_password);
			}
			curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
			curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
			curl_easy_setopt(curl, CURLOPT_CAINFO,ca_cert);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
			res = curl_easy_perform(curl);
			if(res != CURLE_OK) {

			size_t len = strlen(errbuf);
    			fprintf(stderr, "\nlibcurl: (%d) ", res);
    			if(len)
      				fprintf(stderr, "%s%s", errbuf,
              			((errbuf[len - 1] != '\n') ? "\n" : ""));
				// log_error("[%d] curl_easy_perform() failed: %s ",getpid(),curl_easy_strerror(res));
			}
			log_info("[%d] Disconnected, will try re-connect in 5 s ",getpid());			
			sleep(5);
		curl_easy_cleanup(curl);	
	}
	
	curl_global_cleanup();
	return 0;	
}








