/* mod_certwatch - PL/pgSQL gateway for certwatch_db and httpd
 * Written by Rob Stradling
 * Copyright (C) 2015 COMODO CA Limited
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

/* PostgreSQL connector module header file */
#include "mod_pgconn/mod_pgconn.h"

#if (AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER < 4)
	#define useragent_ip	connection->remote_ip
#endif


/* Typedef for per-directory configuration information */
typedef struct tCertWatchDirConfig {
	tPGconnContainer* m_PGconnContainer;
} tCertWatchDirConfig;


/* Forward reference for module record */
module AP_MODULE_DECLARE_DATA certwatch_module;


/* Imported functions from mod_pgconn, the PostgreSQL connector module */
static APR_OPTIONAL_FN_TYPE(getPGconnContainerByName)* getPGconnContainerByName;
static APR_OPTIONAL_FN_TYPE(acquirePGconn)* acquirePGconn;
static APR_OPTIONAL_FN_TYPE(releasePGconn)* releasePGconn;
static APR_OPTIONAL_FN_TYPE(measurePGconnAvailability)*
						measurePGconnAvailability;


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
 * PGconn_command()                                                           *
 *   Process the "PGconn" command.                                            *
 *                                                                            *
 * IN:	v_cmdParms - various server configuration details.                    *
 * 	v_certWatchDirConfig - the per-directory config structure.            *
 * 	v_PGconnName - the name of the <PGconn> container to use for this     *
 * 			module/directory.                                     *
 * 	v_moduleName - must be "certwatch" for this module to process this    *
 * 			command.                                              *
 *                                                                            *
 * Returns:	NULL or an error message.                                     *
 ******************************************************************************/
static const char* PGconn_command(
	cmd_parms* v_cmdParms,
	void* v_certWatchDirConfig,
	const char* v_moduleName,
	const char* v_PGconnName
)
{
	tPGconnServerConfig* t_PGconnServerConfig =
		(tPGconnServerConfig*)ap_get_module_config(
			v_cmdParms->server->module_config, &pgconn_module
		);

	/* Check if this directive should be handled by another module */
	if (!v_PGconnName)
		return DECLINE_CMD;
	else if (strcasecmp(v_moduleName, "certwatch"))
		return DECLINE_CMD;

	/* Find the desired <PGconn> container */
	#define t_certWatchDirConfig					\
		((tCertWatchDirConfig*)v_certWatchDirConfig)
	t_certWatchDirConfig->m_PGconnContainer = getPGconnContainerByName(
		t_PGconnServerConfig, v_PGconnName
	);
	if (t_certWatchDirConfig->m_PGconnContainer)
		return NULL;	/* <PGconn> container found OK */
	#undef t_certWatchDirConfig

	return "Invalid Connection Name";
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

	if (strlen(*v_nameArray) > 0)
		*v_nameArray = apr_psprintf(
			v_request->pool, "{%s}", (*v_nameArray) + 1
		);
	if (strlen(*v_valueArray) > 0)
		*v_valueArray = apr_psprintf(
			v_request->pool, "{%s}", (*v_valueArray) + 1
		);
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
	char* t_nameArray = NULL;
	char* t_valueArray = NULL;
	char* t_response = NULL;
	char* t_endOfHeaders = NULL;
	char* t_name;
	char* t_value;
	char* t_next;
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

	/* Process this request */
	if (!strcmp(v_request->uri, "/PGconn-status")) {
		ap_rprintf(
			v_request, "%d%% of connections available\n",
			measurePGconnAvailability(
				t_certWatchDirConfig->m_PGconnContainer
			)
		);
		return OK;
	}
	else if (strcmp(v_request->uri, "/") && strncmp(v_request->uri, "/?", 2)
				&& strncmp(v_request->uri, "/test/", 6))
		return DECLINED;
	else if (v_request->method_number == M_GET) {
		if (v_request->args && *(v_request->args))
			/* There is a query string and it's more than just a
			  single "?" character */
			certwatch_makeParamArrays(
				v_request, v_request->args, &t_nameArray,
				&t_valueArray
			);
	}
	else if (v_request->method_number == M_POST) {
		if (certwatch_read_body(v_request, &t_body_data, &t_body_size)
				!= OK)
			return DECLINED;
		certwatch_makeParamArrays(
			v_request, (char*)t_body_data, &t_nameArray,
			&t_valueArray
		);
	}
	else
		return DECLINED;

	/* Acquire a PostgreSQL database connection.  If necessary, block until
	  a connection becomes available */
	if (acquirePGconn(t_certWatchDirConfig->m_PGconnContainer, &t_PGconn)
							!= PGCONN_ACQUIRED) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, 0, NULL,
			"acquirePGconn() failed"
		);
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
			strstr(v_request->uri, "/test/") ? "_test" : "",
			v_request->useragent_ip
		),
		3, NULL, t_paramValues, NULL, NULL, 0
	);

	/* Release the PostgreSQL database connection */
	if (releasePGconn(t_certWatchDirConfig->m_PGconnContainer, &t_PGconn)
							!= PGCONN_RELEASED) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, 0, NULL,
			"releasePGconn() failed"
		);
		goto label_return;
	}

	/* Ensure that the SQL query was successful */
	if (PQresultStatus(t_PGresult) != PGRES_TUPLES_OK) {
		ap_log_error(
			APLOG_MARK, APLOG_ERR, 0, NULL,
			"PQexecParams() => %s",
			PQresultErrorMessage(t_PGresult)
		);
		goto label_return;
	}

	/* Does the function's response require any HTTP Response headers to be
	  set or modified? */
	t_response = PQgetvalue(t_PGresult, 0, 0);
	t_response_len = PQgetlength(t_PGresult, 0, 0);
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

	/* Output the response */
	ap_rwrite(t_response, t_response_len, v_request);

	t_returnCode = OK;

label_return:
	if (t_PGresult)
		PQclear(t_PGresult);

	return t_returnCode;
}


/*----------------------------------------------------------------------------
  - Command Table                                                            -
  ----------------------------------------------------------------------------*/
static const command_rec certwatch_commandTable[] = {
	AP_INIT_TAKE12(
		"PGconn", PGconn_command, NULL, ACCESS_CONF,
		"a <PGconn> container name"
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
	/* Import PostgreSQL connector functions */
	getPGconnContainerByName = APR_RETRIEVE_OPTIONAL_FN(
		getPGconnContainerByName
	);
	acquirePGconn = APR_RETRIEVE_OPTIONAL_FN(acquirePGconn);
	releasePGconn = APR_RETRIEVE_OPTIONAL_FN(releasePGconn);
	measurePGconnAvailability = APR_RETRIEVE_OPTIONAL_FN(
		measurePGconnAvailability
	);

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
