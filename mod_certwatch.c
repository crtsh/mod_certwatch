/* mod_certwatch - PL/pgSQL gateway for certwatch_db and httpd
 * Written by Rob Stradling
 * Copyright (C) 2015-2019 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>

/* Apache 2.0 include files */
#include "apr_lib.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"

/* PostgreSQL include files */
#include "libpq-fe.h"


#if (AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER < 4)
	#define useragent_ip	connection->remote_ip
#endif


/* Typedef for per-directory configuration information */
typedef struct tCertWatchDirConfig {
	char* m_connInfo;
} tCertWatchDirConfig;


/* Forward reference for module record */
module AP_MODULE_DECLARE_DATA certwatch_module;


/******************************************************************************
 * certwatch_dirConfig_create()                                               *
 *   Creates the per-directory configuration structure.                       *
 *                                                                            *
 * IN:	v_pool - pool to use for memory allocation.                           *
 *                                                                            *
 * Returns:	pointer to per-directory config structure.                    *
 ******************************************************************************/
static void* certwatch_dirConfig_create(
	apr_pool_t* v_pool,
	char* v_directory_unused
)
{
	tCertWatchDirConfig* t_certWatchDirConfig;

	/* Allocate zeroized memory for per-server config structure */
	t_certWatchDirConfig = (tCertWatchDirConfig*)apr_pcalloc(
		v_pool, sizeof(*t_certWatchDirConfig)
	);

	return (void*)t_certWatchDirConfig;
}


/******************************************************************************
 * certwatch_read_body()                                                      *
 *   Read the request body of this POST or PUT request.                       *
 *                                                                            *
 * IN:	v_request - the request record.                                       *
 *                                                                            *
 * OUT:	v_body_data - the request body.                                       *
 * 	v_body_size - the size of v_body_data (in bytes).                     *
 *                                                                            *
 * Returns:	OK = Request body read successfully.                          *
 * 		DECLINED = An error occurred.                                 *
 ******************************************************************************/
static int certwatch_read_body(
	request_rec* const v_request,
	unsigned char** const v_body_data,
	long* v_body_size
)
{
	/* Initialize the data buffer */
	*v_body_data = NULL;
	*v_body_size = 0;

	if ((v_request->method_number == M_POST)
				|| (v_request->method_number == M_PUT)) {
		/* Create a bucket brigade */
		apr_bucket_brigade* t_bucketBrigade = apr_brigade_create(
			v_request->pool, v_request->connection->bucket_alloc
		);
		apr_status_t t_result;
		int t_seenEOS = 0;
		do {
			/* Link to the input filter stack */
			t_result = ap_get_brigade(
				v_request->input_filters, t_bucketBrigade,
				AP_MODE_READBYTES, APR_BLOCK_READ,
				HUGE_STRING_LEN
			);
			if (t_result != APR_SUCCESS) {
				*v_body_data = NULL;
				break;
			}

			/* Read the data from the bucket(s) */
			apr_bucket* t_bucket;
			for (t_bucket = APR_BRIGADE_FIRST(t_bucketBrigade);
					t_bucket != APR_BRIGADE_SENTINEL(
							t_bucketBrigade);
					t_bucket = APR_BUCKET_NEXT(t_bucket)) {
				if (APR_BUCKET_IS_EOS(t_bucket)) {
					t_seenEOS = 1;
					break;
				}
				else if (APR_BUCKET_IS_FLUSH(t_bucket))
					continue;

				/* Read the data from this bucket */
				const char* t_data;
				apr_size_t t_size;
				t_result = apr_bucket_read(
					t_bucket, &t_data, &t_size,
					APR_BLOCK_READ
				);
				if (t_result != APR_SUCCESS) {
					*v_body_data = NULL;
					break;
				}

				/* Create a new APR-allocated buffer */
				unsigned char* t_body_data = apr_palloc(
					v_request->pool,
					*v_body_size + t_size + 1
				);
				if (!t_body_data) {
					*v_body_data = NULL;
					break;
				}

				/* Concatenate all of the bucket data that we've
				  read so far */
				if (*v_body_data)
					memcpy(t_body_data,
						*v_body_data,
						*v_body_size);
				memcpy(t_body_data + (*v_body_size),
					t_data, t_size);
				*v_body_data = t_body_data;
				*v_body_size += t_size;
				t_body_data[*v_body_size] = '\0';
			}

			/* Cleanup the bucket brigade */
			apr_brigade_cleanup(t_bucketBrigade);
		} while (!t_seenEOS);

		/* Destroy the bucket brigade */
		apr_brigade_destroy(t_bucketBrigade);

		/* Check that some data was read successfully */
		if (*v_body_data)
			return OK;
	}

	*v_body_size = 0;

	return DECLINED;
}


/******************************************************************************
 * escapeArrayString()                                                        *
 *   Escapes a string for inclusion in an array parameter in a call to        *
 * PQexecParams().  Puts a " character at each end and prepends each \ and "  *
 * character with a \ character.                                              *
 *                                                                            *
 * IN:	v_from - pointer to input string.                                     *
 *                                                                            *
 * OUT:	v_to - escaped string (using newly allocated memory).                 *
 *                                                                            *
 * Returns:	pointer to NULL-terminator at end of 'v_to'.                  *
 ******************************************************************************/
static char* escapeArrayString(
	apr_pool_t* v_pool,
	char** v_to,
	const char* v_from
)
{
	char* t_to = apr_palloc(v_pool, (strlen(v_from) * 2) + 4);
	const char* t_from = v_from;

	*v_to = t_to;
	*(t_to++) = '"';

	while (*t_from) {
		/* If necessary, prepend a \ character */
		if (((*t_from) == '\\') || ((*t_from) == '"'))
			*(t_to++) = '\\';
		/* Copy the source character */
		*(t_to++) = *(t_from++);
	}

	*(t_to++) = '"';
	*t_to = '\0';

	return t_to;
}


/******************************************************************************
 * certwatch_makeParamArrays()                                                *
 *   Construct the parameter name/value array strings from the query string.  *
 *                                                                            *
 * IN:	v_request - the request record.                                       *
 * 	v_urlEncodedData - the URL-encoded data (e.g. the GET query string).  *
 *                                                                            *
 * OUT:	v_nameArray - the parameter name array (PostgreSQL array string).     *
 * 	v_valueArray - the parameter value array (PostgreSQL array string).   *
 ******************************************************************************/
static void certwatch_makeParamArrays(
	request_rec* const v_request,
	char* const v_urlEncodedData,
	char** v_nameArray,
	char** v_valueArray
)
{
	char* t_nextArgName = v_urlEncodedData;
	char* t_argName;
	char* t_argValue;
	char* t_offset;
	char* t_escaped;
	int t_length;

	/* Initialize the output parameters */
	*v_nameArray = "";
	*v_valueArray = "";

	while (1) {
		if (!t_nextArgName)
			break;		/* No more parameters */

		/* Look for the next "=" or "&" character */
		t_argName = t_nextArgName;
		t_length = strcspn(t_argName, "=&");
		if (!t_length)
			break;		/* No more parameters */

		t_argValue = t_argName + t_length;
		if (*t_argValue == '=') {
			/* "=" character found; NULLify it */
			*(t_argValue++) = '\0';

			/* Look for the next "&" character; if found, NULLify
			   it */
			t_nextArgName = ap_strchr(t_argValue, '&');
			if (t_nextArgName)
				*(t_nextArgName++) = '\0';
		}
		else if (*t_argValue == '&') {
			/* No "=" character found (i.e. no value specified) */
			t_nextArgName = t_argValue + 1;
			*t_argValue = '\0';
		}
		else
			t_nextArgName = NULL;

		/* Replace all + characters with SPACE characters (assume
		   URL-encoding is being used: is this always right? */
		for (t_offset = t_argName; *t_offset; t_offset++)
			if (*t_offset == '+')
				*t_offset = ' ';
		for (t_offset = t_argValue; *t_offset; t_offset++)
			if (*t_offset == '+')
				*t_offset = ' ';

		/* Unescape the name and value strings */
		ap_unescape_url(t_argName);
		ap_unescape_url(t_argValue);

		/* Convert the name to upper case, because all argument name
		   comparisons are case-insensitive */
		ap_str_tolower(t_argName);
		
		/* Add the name and value to the array strings, escaping the "
		  and \ characters */
		(void)escapeArrayString(v_request->pool, &t_escaped, t_argName);
		*v_nameArray = apr_psprintf(
			v_request->pool, "%s,%s", *v_nameArray, t_escaped
		);
		(void)escapeArrayString(
			v_request->pool, &t_escaped, t_argValue
		);
		*v_valueArray = apr_psprintf(
			v_request->pool, "%s,%s", *v_valueArray, t_escaped
		);
	}

	if ((strlen(v_request->unparsed_uri) > 1)
			&& (!strstr(v_request->unparsed_uri, "/?"))) {
		t_offset = v_request->uri + 1;
		if (!strncmp(t_offset, "_ROB_IS_TESTING_/", 17))
			t_offset += 17;
		*v_nameArray = apr_psprintf(
			v_request->pool, "%s,\"output\"", *v_nameArray
		);
		(void)escapeArrayString(v_request->pool, &t_escaped, t_offset);
		*v_valueArray = apr_psprintf(
			v_request->pool, "%s,%s", *v_valueArray, t_escaped
		);
	}

	if (strlen(*v_nameArray) > 0) {
		*v_nameArray = apr_psprintf(
			v_request->pool, "{%s}", (*v_nameArray) + 1
		);
		*v_valueArray = apr_psprintf(
			v_request->pool, "{%s}", (*v_valueArray) + 1
		);
	}
	else {
		*v_nameArray = NULL;
		*v_valueArray = NULL;
	}
}


/******************************************************************************
 * certwatch_contentHandler()                                                 *
 *   Handle an HTTP request from a CertWatch client and return an HTTP        *
 * Response.                                                                  *
 *                                                                            *
 * IN:	v_request - the request record.                                       *
 *                                                                            *
 * Returns:	OK, DECLINED or some other Apache HTTP error code.            *
 ******************************************************************************/
static int certwatch_contentHandler(
	request_rec* const v_request
)
{
	PGconn* t_PGconn = NULL;
	PGresult* t_PGresult = NULL;
	const char* t_paramValues[3];
	char* t_requestParams = NULL;
	char* t_nameArray = NULL;
	char* t_valueArray = NULL;
	char* t_response = NULL;
	char* t_endOfHeaders = NULL;
	char* t_name;
	char* t_value;
	char* t_next;
	char* t_uri;
	unsigned char* t_body_data = NULL;
	long t_body_size = 0;
	int t_response_len = 0;
	int t_returnCode = DECLINED;

	/* Check if we need to handle this request at all */
	if (strcmp(v_request->handler, "certwatch"))
		return DECLINED;

	/* Get the per-directory configuration structure */
	tCertWatchDirConfig* t_certWatchDirConfig =
		(tCertWatchDirConfig*)ap_get_module_config(
			v_request->per_dir_config, &certwatch_module
		);
	if (!t_certWatchDirConfig)
		return DECLINED;

	/* Isolate the path component of the URI */
	t_uri = apr_pstrdup(v_request->pool, v_request->unparsed_uri);
	t_value = ap_strchr(t_uri, '?');
	if (t_value)
		*t_value = '\0';

	/* If there's a dot in the path, decline to handle it here (except for
	  *.json): images, robots.txt, etc */
	t_value = ap_strrchr(t_uri, '.');
	if ((t_value != NULL) && (strcmp(t_value, ".json") != 0))
		return DECLINED;

	/* Process this request */
	if (!strncmp(v_request->uri, "/test/", 6)) {
		apr_table_set(
			v_request->headers_out, "Location",
			apr_psprintf(
				v_request->pool, "https://%s/?%s",
				v_request->hostname, v_request->args
			)
		);
		return HTTP_MOVED_TEMPORARILY;
	}
	else if (v_request->method_number == M_GET)
		t_requestParams = v_request->args;
	else if (v_request->method_number == M_POST) {
		if (certwatch_read_body(v_request, &t_body_data, &t_body_size)
				!= OK)
			return DECLINED;
		t_requestParams = (char*)t_body_data;
	}
	else
		return DECLINED;

	certwatch_makeParamArrays(
		v_request, t_requestParams, &t_nameArray, &t_valueArray
	);

	/* Open a connection to the PostgreSQL database.  No connection pooling
	  is performed here, so use of a connection pooler such as PgBouncer is
	  recommended */
	time_t t_startTime = time(NULL);
	t_PGconn = PQconnectdb(t_certWatchDirConfig->m_connInfo);
	if (PQstatus(t_PGconn) != CONNECTION_OK) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, 0, NULL,
			"PQconnectdb() failed"
		);
		PQfinish(t_PGconn);
		return DECLINED;
	}

	/* Execute the required function */
	t_paramValues[0] = strrchr(v_request->uri, '/') + 1;
	t_paramValues[1] = t_nameArray;
	t_paramValues[2] = t_valueArray;
	t_PGresult = PQexecParams(
		t_PGconn,
		apr_psprintf(v_request->pool,
			"SELECT web_apis%s($1,$2,$3) -- %s",
			strncmp(v_request->uri, "/_ROB_IS_TESTING_/", 18)
				? "" : "_test",
			v_request->useragent_ip
		),
		3, NULL, t_paramValues, NULL, NULL, 0
	);

	/* Close the connection to the PostgreSQL database */
	PQfinish(t_PGconn);

	/* Ensure that the SQL query was successful */
	if (PQresultStatus(t_PGresult) != PGRES_TUPLES_OK) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, 0, NULL,
			"PQexecParams() => %s",
			PQresultErrorMessage(t_PGresult)
		);

		/* Return a 503 with an error webpage */
		time_t t_endTime = time(NULL);
		struct tm t_tm;
		gmtime_r(&t_endTime, &t_tm);
		v_request->status = HTTP_SERVICE_UNAVAILABLE;
		v_request->content_type = "text/html; charset=UTF-8";
		t_response = apr_psprintf(
			v_request->pool,
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"><HTML><HEAD><TITLE>crt.sh | ERROR!</TITLE><LINK href=\"//fonts.googleapis.com/css?family=Roboto+Mono|Roboto:400,400i,700,700i\" rel=\"stylesheet\"><STYLE type=\"text/css\">body{color:#888888;font:12pt Roboto,sans-serif;padding-top:10px;text-align:center} span{border-radius:10px} span.title{background-color:#00B373;color:#FFFFFF;font:bold 18pt Roboto,sans-serif;padding:0px 5px} span.whiteongrey{background-color:#D9D9D6;color:#FFFFFF;font:bold 18pt Roboto,sans-serif;padding:0px 5px} .copyright{font:8pt Roboto,sans-serif;color:#00B373}</STYLE></HEAD><BODY><A style=\"text-decoration:none\" href=\"/\"><SPAN class=\"title\">crt.sh</SPAN></A>&nbsp; <SPAN class=\"whiteongrey\">Certificate Search</SPAN><BR><BR><BR><BR>Sorry, something went wrong... :-(<BR><BR>Your request was terminated by the crt.sh database server after <B>%d</B> second%s with the following messages:<BR><BR><TEXTAREA readonly rows=\"8\" cols=\"100\">%s</TEXTAREA><BR><BR>Unfortunately, searches that would produce many results may never succeed. For other requests, please try again later.<BR><BR><BR><P class=\"copyright\">&copy; Sectigo Limited 2015-%d. All rights reserved.</P><DIV><A href=\"https://sectigo.com/\"><IMG src=\"/sectigo_s.png\"></A>&nbsp;<A href=\"https://github.com/crtsh\"><IMG src=\"/GitHub-Mark-32px.png\"></A></DIV></BODY></HTML>",
			(t_endTime - t_startTime), (((t_endTime - t_startTime) == 1) ? "": "s"),
			PQresultErrorMessage(t_PGresult), (t_tm.tm_year + 1900)
		);
		t_response_len = strlen(t_response);
		t_returnCode = OK;
		goto label_outputResponse;
	}

	/* Does the function's response require any HTTP Response headers to be
	  set or modified? */
	t_response = PQgetvalue(t_PGresult, 0, 0);
	t_response_len = PQgetlength(t_PGresult, 0, 0);
	if (t_response_len == 0) {
		t_returnCode = DECLINED;
		goto label_return;
	}
	#define C_HTTP_HEADERS		"[BEGIN_HEADERS]\n"
	#define C_HTTP_HEADERS_CLOSE	"[END_HEADERS]\n"
	if (!strncmp(t_response, C_HTTP_HEADERS, strlen(C_HTTP_HEADERS))) {
		t_endOfHeaders = strstr(t_response, C_HTTP_HEADERS_CLOSE);
		if (t_endOfHeaders) {
			/* Customize the HTTP headers as requested by the
			  function's response */
			for (t_name = t_response + strlen(C_HTTP_HEADERS);
					t_name < t_endOfHeaders;
					t_name = t_next + 1) {
				/* Isolate the header name */
				t_value = strchr(t_name, ':');
				if (!t_value)
					break;
				*(t_value++) = '\0';
				while (apr_isspace(*t_value))
					t_value++;

				/* Isolate the header value */
				t_next = strchr(t_value, '\n');
				if (!t_next)
					break;
				*t_next = '\0';

				if (!strcasecmp(t_name, "Content-Type"))
					v_request->content_type = apr_pstrdup(
						v_request->pool, t_value
					);
				else
					apr_table_set(
						v_request->headers_out, t_name,
						t_value
					);
			}
			t_response_len -= (t_endOfHeaders - t_response);
			t_response_len -= strlen(C_HTTP_HEADERS_CLOSE);
			t_response += (t_endOfHeaders - t_response);
			t_response += strlen(C_HTTP_HEADERS_CLOSE);
		}
	}

	/* If no HTTP header customization was requested, set some defaults */
	if (!t_endOfHeaders)
		v_request->content_type = "text/html; charset=UTF-8";

	t_returnCode = OK;

	/* Output the response */
label_outputResponse:
	ap_rwrite(t_response, t_response_len, v_request);

label_return:
	if (t_PGresult)
		PQclear(t_PGresult);

	return t_returnCode;
}


/*----------------------------------------------------------------------------
  - Command Table                                                            -
  ----------------------------------------------------------------------------*/
static const command_rec certwatch_commandTable[] = {
	AP_INIT_TAKE1(
		"ConnInfo", ap_set_string_slot,
		(void*)APR_OFFSETOF(tCertWatchDirConfig, m_connInfo),
		ACCESS_CONF, "PostgreSQL connection string"
	),
	{ NULL }
};


/******************************************************************************
 * certwatch_registerHooks()                                                  *
 ******************************************************************************/
static void certwatch_registerHooks(
	apr_pool_t* const v_pool_unused
)
{
	/* Register HTTP(S) content handler - this runs once for each HTTP
	  request */
	ap_hook_handler(
		certwatch_contentHandler, NULL, NULL, APR_HOOK_MIDDLE
	);
}


/*----------------------------------------------------------------------------
  - Module record                                                            -
  ----------------------------------------------------------------------------*/
module AP_MODULE_DECLARE_DATA certwatch_module = {
	STANDARD20_MODULE_STUFF,
	certwatch_dirConfig_create,	/* per-directory config creator       */
	NULL,				/* per-directory config merger        */
	NULL,				/* per-server config creator          */
	NULL,				/* per-server config merger           */
	certwatch_commandTable,		/* command table                      */
	certwatch_registerHooks		/* register hooks                     */
};
