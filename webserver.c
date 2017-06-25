//
// This is a simple HTTP 1.0 compliant webserver capable of serving static
// files to clients.
//

#include <SDKDDKVer.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <assert.h>
#include <process.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>

//
// Parameters for tuning webserver performance.
// (For testing purposes, use very small buffer sizes to ensure reallocation code is excercised.)
//

//
// Define TESTING to excercise test code instead of running the webserver.
//

#define TEST_ITERATIONS 10
int code_coverage[64];
int simulate_error[64];

// #define TESTING

#ifdef TESTING

#define MAX_BUF 13
#define READ_CHUNK_SIZE 73
int test = 1;

#else

#define MAX_BUF (1024*1024)
#define READ_CHUNK_SIZE (64*1024)
int test;

#endif

#define NEWLINE "\r\n"
#define HTTP_PREFIX "http://"
#define WEBSITE_DIR "c:\\website"

#define ERROR_EXIT(err_msg) { \
	perror(err_msg); \
	exit(errno); \
}

void client_thread(void* thread_argument);
int init_lineparser(struct context** outctxt);

int gen_rand_data(char* buf, int len) {
	int i;
	int generated_amount;
	generated_amount = (rand() % len) + 1;
	for (i = 0; i < generated_amount; i++) {
		buf[i] = (rand() % 255) + 1;
	}
	return generated_amount;
}

struct context {
	char* line_buffer;
	size_t line_buffer_len;

	char* next;

	SOCKET client;

	char* request_uri;
};

//
// Reads a single line of data from a socket, returning the value in outline.
//
// Preconditions:
//   ctxt points to a structure initialized with init_lineparser().
//   ctxt->client is a valid socket.
//   outline is a valid pointer which receives a pointer to a line of data.
//
// Postconditions:
//   0:     the call was successful and outline receives a pointer to a null
//          terminated string which the caller frees.
//   other: the call failed. outline was not modified.
//
// Remarks:
//
// This routine stores data read from the socket but not yet returned as a
// complete line in a temporary buffer in ctxt.
//
// It is designed to use as little memory as possible, which means that once a
// line of data is returned to the caller, it only stores whatever is leftover
// in a small buffer with only a small amount of extra room.

int readline(struct context* ctxt, char** outline) {
	size_t amt_read, chars_cur_in_line_buf_not_inc_null_term;
	size_t line_buffer_terminator_offset, new_line_buffer_len, leftover_len;
	size_t line_len;
	char *newline = NULL;
	char *leftover, *line, *new_line_buffer, *tmp;
	int i = 0;
	*outline = NULL;
	do {
		// Is there a complete line already in the line_buffer?
		newline = strstr(ctxt->line_buffer, NEWLINE);
		if (newline) {
			// How many characters are in the line, not including \r\n?
			line_len = newline - ctxt->line_buffer;

			//
			// Copy the line's data into a new buffer, failing if there isn't
			// enough memory.
			//

			// Allocate enough for the buffer, including NULL terminator.
			line = malloc(line_len + 1);
			if (!line || simulate_error[0]) {
				if (simulate_error[0]) free(line);
				code_coverage[0] = 1;
				return ENOMEM;
			}

			// Copy the line into the new buffer.
			memcpy(line, ctxt->line_buffer, line_len);
			line[line_len] = '\0';
			leftover = newline + strlen(NEWLINE);

			//
			// If there is data for a new line, copy it into its own memory,
			// since this line's will be freed before returning the line to the
			// caller.
			//

			leftover_len = strlen(leftover);
			if (leftover_len) {
				code_coverage[1] = 1;

				//
				// Round up to a buffer size worth of data, then add another
				// buffer for room for future read calls.
				//

				// First, can this string handle potentially two more buffers
				// worth of data without an integer overflow? If not, that's an
				// error.
				if ((SIZE_MAX - leftover_len) < MAX_BUF * 2 || simulate_error[1]) {
					code_coverage[2] = 1;
					free(line);
					return ERANGE;
				}

				new_line_buffer_len = (leftover_len / MAX_BUF + 2) * MAX_BUF;
				new_line_buffer = malloc(new_line_buffer_len);
				if (!new_line_buffer || simulate_error[2]) {
					if (simulate_error[2]) free(new_line_buffer);
					code_coverage[3] = 1;
					free(line);
					return ENOMEM;
				}

				memcpy(new_line_buffer, leftover, leftover_len);
				new_line_buffer[leftover_len] = '\0';
			}
			else {
				new_line_buffer = malloc(MAX_BUF);
				if (!new_line_buffer || simulate_error[3]) {
					if (simulate_error[3]) free(new_line_buffer);
					code_coverage[4] = 1;
					free(line);
					return ENOMEM;
				}

				new_line_buffer[0] = '\0';
				new_line_buffer_len = MAX_BUF;
			}

			// Finally, free the line buffer.
			free(ctxt->line_buffer);
			ctxt->line_buffer = new_line_buffer;
			ctxt->line_buffer_len = new_line_buffer_len;
			*outline = line;

			code_coverage[5] = 1;
			return 0;
		}

		// Read more data until there's a newline.
		chars_cur_in_line_buf_not_inc_null_term = strlen(ctxt->line_buffer);
		line_buffer_terminator_offset = chars_cur_in_line_buf_not_inc_null_term;

		// Is there enough buffer space to read something reasonable? Otherwise, realloc more memory.
		if ((ctxt->line_buffer_len - chars_cur_in_line_buf_not_inc_null_term) <= MAX_BUF / 2) {
			code_coverage[6] = 1;

			// Can we represent more memory?
			if ((SIZE_MAX - ctxt->line_buffer_len) < MAX_BUF || simulate_error[4]) {
				code_coverage[7] = 1;
				return ERANGE;
			}

			tmp = realloc(ctxt->line_buffer, ctxt->line_buffer_len + MAX_BUF);
			if (!tmp || simulate_error[5]) {
				code_coverage[8] = 1;
				return ENOMEM;
			}

			ctxt->line_buffer = tmp;
			ctxt->line_buffer_len += MAX_BUF;
		}

		code_coverage[9] = 1;
		if (!test) {
			amt_read = recv(ctxt->client,
				ctxt->line_buffer + line_buffer_terminator_offset,
				(int)min(ctxt->line_buffer_len - chars_cur_in_line_buf_not_inc_null_term - 1, INT_MAX),
				0);
		}
		else {
			amt_read = gen_rand_data(ctxt->line_buffer + line_buffer_terminator_offset,
				(int)min(ctxt->line_buffer_len - chars_cur_in_line_buf_not_inc_null_term - 1, INT_MAX));
		}

		if (amt_read == -1 || simulate_error[6]) {
			// socket error
			code_coverage[10] = 1;
			if (simulate_error[6]) return ECONNRESET;
			return errno;
		}

		if (amt_read == 0 || simulate_error[7]) {
			// other end closed connection, and we haven't seen a CRLF pair yet
			code_coverage[11] = 1;
			return EINVAL;
		}

		chars_cur_in_line_buf_not_inc_null_term += amt_read;
		line_buffer_terminator_offset += amt_read;
		ctxt->line_buffer[line_buffer_terminator_offset] = '\0';
		i++;

	} while (!newline);

	code_coverage[12] = 1;
	return 0;
}

//
// This routine tests the readline routine by directing it to artificially
// induce errors in itself.
//
int test_readline() {
	char* line;
	int i = 0;
	int j;
	int err;
	struct context* ctxt;

	err = init_lineparser(&ctxt);
	if (err) return err;

	do {
		if (i >= TEST_ITERATIONS) break;

		err = readline(ctxt, &line);
		if (err) return err;

		for (j = 0; j < 7; j++) {
			if (j != 0) simulate_error[j - 1] = 0;
			simulate_error[j] = 1;
			err = readline(ctxt, &line);
			if (!err) return EBADMSG;
		}
		simulate_error[j] = 0;
		i++;
	} while (strlen(line) != 0);

	return err;
}

//
// This routine tests the line unfolding ability of the readandunfoldheaders
// routine by artificially folding received lines at every valid opportunity.
//
// It acts as a filter in-between readandunfoldheaders and readline and has the
// same function signature as readline.
//
int fold_line(struct context* ctxt, char** line) {
	char* aspace;
	char* ret;
	int err;

	if (ctxt->next) {
		ret = ctxt->next;
		ctxt->next = NULL;
		*line = ret;
		return 0;
	}

	err = readline(ctxt, &ret);
	if (err) {
		return err;
	}

	if (!strlen(ret)) {
		*line = ret;
		return 0;
	}

	aspace = strstr(ret, " ");
	if (!aspace) {
		return EINVAL;
	}
	ctxt->next = _strdup(aspace);
	if (!ctxt->next) {
		return ENOMEM; // Make a new line at the space character
	}
	*(aspace + 1) = '\0';
	*line = ret;
	return 0;
}

//
// This routine frees the memory allocated by readheaders. Normally this occurs
// in parseheaders once it is done with them; however, in the case of an error,
// readandunfoldheaders will also call this routine before returing to its
// caller.
// 
//
void freeheaders(char** headers) {
	char **curheader = headers;
	while (*curheader) {
		free(*curheader);
		curheader++;
	};
	free(headers);
}

//
// This routine calls readline repeatedly assembling the results into an array
// which it returns via outheaders. If an error is not returned, the caller is
// responsible for freeing this array via a call to freeheaders.
//
int readheaders(struct context* ctxt, char*** outheaders) {
	char* header;
	char** headers;
	char** newheaders;
	size_t headers_len = MAX_BUF;
	size_t i = 0;
	int err;
	headers = malloc(MAX_BUF * sizeof(char*)); if (!headers) return ENOMEM;

#define FREE_THINGS_RH()	\
	headers[i] = NULL;		\
	freeheaders(headers);	\

	do {
		if (i >= headers_len - 1) {
			if (SIZE_MAX - headers_len * sizeof(char*) < MAX_BUF * sizeof(char*)) {
				FREE_THINGS_RH();
				return ERANGE;
			}
			newheaders = realloc(headers, (headers_len + MAX_BUF) * sizeof(char*));
			if (!newheaders) {
				FREE_THINGS_RH();
				return ENOMEM;
			}
			headers = newheaders;
			headers_len += MAX_BUF;
		}
		err = fold_line(ctxt, &header);
		if (err) {
			FREE_THINGS_RH();
			return err;
		}
		headers[i] = header;
		i++;
		//if (!((i + 1) % 10)) {
		//	header[0] = ' ';
		//}
		//else if (!((i + 1) % 17)) {
		//	header[0] = '\t';
		//}
		//if (i >= 100) {
		//	free(header);
		//	headers[i - 1] = "";
		//	return headers;
		//}
	} while (strlen(header) != 0);

	*outheaders = headers;
	return 0;
}

//
// This routine reads data from a TCP connection assuming it to be HTTP headers.
// In then unfolds them if needed, and returns the unfolded headers (which are
// ASCII newline terminated strings) in outheaders.
// Outheaders points to an array of strings with the final element a pointer to
// an empty string.
//
// If successful, it returns 0 and the caller is responsible for freeing each
// string of the array and then the array itself. If not, it returns a POSIX
// error code and outheaders is not modified. 
//
int readandunfoldheaders(struct context* ctxt, char*** outheaders) {
	char **headers, **curheader, *foldedheader, **prevheader = NULL, *tmp;
	int i = 0;
	size_t newlen;
	int err;

	err = readheaders(ctxt, &headers);
	if (err) {
		return err;
	}

	curheader = headers;
	while (**curheader) {
		if (**curheader == ' ' || **curheader == '\t') { // This line belongs with the previous one
			if (!prevheader) { // There must be a previous line to fold this header with or that's a client error.
				freeheaders(headers);
				return EINVAL;
			}

			foldedheader = *curheader;
			while (*foldedheader == ' ' || *foldedheader == '\t') foldedheader++; // advance past whitespace
			if (!strlen(foldedheader)) { // If after skipping past the whitespace there's nothing left, that's also a client error.
				freeheaders(headers);
				return EINVAL;
			}

			if (SIZE_MAX - strlen(foldedheader) - 1 < strlen(*prevheader)) { // Int overflow check
				freeheaders(headers);
				return ERANGE;
			}

			newlen = strlen(*prevheader) + strlen(foldedheader) + 1;
			tmp = realloc(*prevheader, newlen);
			if (!tmp) { // Expand prevheader
				freeheaders(headers);
				return ENOMEM;
			}

			*prevheader = tmp;
			strcat_s(*prevheader, newlen, foldedheader);
			free(*curheader);
			*curheader = calloc(1, 1); if (!*curheader) {
				freeheaders(headers);
				return ENOMEM;
			}
		}
		//printf("%d: '%s'\n",i, *curheader);
		i++;
		if (**curheader != '\0') prevheader = curheader;
		curheader++;
	}
	free(*curheader);
	*curheader = NULL;
	*outheaders = headers;
	return 0;
}

//
// This routine initializes a shared ctxt data structure used by routines which
// serve clients webpages.
//
// Upon success, it returns 0 and populates outctxt.
// Upon failure, it returns a POSIX error code and does not modify outcxtx.
// If successful, the caller is responsible for freeing outctxt.
//
int init_lineparser(struct context** outctxt) {
	struct context* ctxt = malloc(sizeof(struct context)); if (!ctxt) return ENOMEM;
	ctxt->line_buffer = malloc(MAX_BUF);
	if (!ctxt->line_buffer) {
		free(ctxt);
		return ENOMEM;
	}

	ctxt->line_buffer[0] = '\0';
	ctxt->line_buffer_len = MAX_BUF;

	ctxt->next = NULL;

	ctxt->request_uri = NULL;

	*outctxt = ctxt;
	return 0;
}

//
// This routine accepts a string containing an HTTP request and parses the
// request action to see if it one supported by this server.
//
// In particular, if it is a HTTP GET request. If it is, it parses the request
// URI and places it in ctxt->request_uri.
//
// It returns 0 upon success and a POSIX error on failure.
// If it returns success, the caller is responsible for freeing
// ctxt->request_uri
//
#define VERB_GET "GET "
int parse_get(struct context* ctxt, char* header) {
	char* next_token = NULL;
	char* tok = strtok_s(header, " ", &next_token);
	int i = 0;

	while (tok) {
		switch (i) {
		case 0:
			if (strcmp("GET", tok)) return ENOSYS; // Only GET implemented
			break;
		case 1:
			ctxt->request_uri = _strdup(tok); if (!ctxt->request_uri) return ENOMEM;
			break;
		case 2:
			if (strstr(tok, "HTTP/") != tok) return EINVAL; // Should start with HTTP/ and the rest should parse as a float
			// Don't actually care about the version.
			break;
		default:
			return EINVAL; // Request method can only contain 3 parts
		}
		tok = strtok_s(NULL, " ", &next_token);
		i++;
	}

	if (!ctxt->request_uri) return EINVAL; // Must supply a URI
	return 0;
}

void parseheader(char* header) {
	// Don't care about any other header for now.
}

//
// This routine reads data from a TCP connection and attempts to parse it as
// HTTP request headers.
//
// If successful, it populates ctxt with the header information.
//
// It returns 0 upon success, and a POSIX error on failure.
// If it returns success, the caller is responsible for freeing
// ctxt->request_uri.
//
int parseheaders(struct context* ctxt) {
	int parsed_first_line = 0;
	char **curheader, **headers;
	int i = 0;
	int err;

	err = readandunfoldheaders(ctxt, &headers);
	if (err) {
		return err;
	}

	curheader = headers;
	while (*curheader) {
		if (strlen(*curheader)) {
			if (!parsed_first_line) {
				err = parse_get(ctxt, *curheader);
				if (err) {
					if (ctxt->request_uri) free(ctxt->request_uri);
					freeheaders(headers);
					return err;
				}
				parsed_first_line = 1;
			}
			//printf("%d: '%s'\n", i, *curheader);
			parseheader(*curheader);
		}
		i++;
		curheader++;
	};

	freeheaders(headers);
	return err;
}

//
// This routine wraps the socket send call, repeatedly calling it until the
// entire buffer data is sent, or an error occurs.
//
// It returns the same error values as the underlying send() call.
//
int sendall(SOCKET s, char* data, size_t len) {
	int err;
	int ret_send;
	size_t amt_sent = 0;
	size_t left_to_send = len;

	char *ptr_send;

	ptr_send = data;

	do {
		if ((ret_send = send(s, ptr_send, (int)min(left_to_send, INT_MAX), 0)) == -1) {
			err = WSAGetLastError();
			return err;
		}

		amt_sent += ret_send;
		ptr_send += amt_sent;
		left_to_send -= amt_sent;

	} while (amt_sent != len);
	return 0;
}

//
// This routine serves an HTTP error status code.
//
// It expects ctxt->client to be valid.
//
void serveerr(struct context* ctxt, int err) {
	char full_response[32];
	int http_status_code;
	assert(err != 0);
	switch (err) {
		case ENOSYS:
			http_status_code = 501; // Not Implemented
			break;
		case ERANGE:
			// ERANGE is returned if a memory allocation would result in an integer overflow.
			// Any request that would require that much memory is almost certainly incorrect.
			http_status_code = 400; // Bad Request
			break;
		case ENOENT:
			http_status_code = 404; // Not Found
			break;
		default:
			http_status_code = 503; // Service Unavailable
			break;
	}

	sprintf_s(full_response, _countof(full_response), "HTTP/1.0 %d \r\n\r\n", http_status_code);
	sendall(ctxt->client, full_response, strlen(full_response));
	printf(full_response);
}

//
// This routine accepts a string (uri) and, if it is an HTTP URI, parses it into
// its component pieces.
//
// Each of the pieces (out*) are optional and may be NULL if not needed.
//
// If successful, it returns 0. Otherwise, it returns a standard POSIX error.
//
// If successful and out* is not null, the caller is responsible for freeing the
// value.
//
int format_uri(char* uri, char** outserver, int* outport, char** outpath, char** outcookedpath) {
	char *server = NULL, *path = NULL, *cookedpath = NULL;
	// Theoretically ports could be any length, but C isn't going to be able to
	// represent more than 64 bits anyway, so size it that large.
	char portstr[32]; // 2^64 is 18446744073709551616 or 20 chars
	int err, args_converted, port;
	char *next_token = NULL;
	char* token;
	int tokens = 0;

	size_t unconstrained_uri_buf_size = strlen(uri) + 1;
	// sscanf_s's length parameters are unsigned int; if the URI string is larger than this, don't even try to parse it.
	unsigned int uri_buf_size = (unsigned int)min(unconstrained_uri_buf_size, UINT_MAX);
	if (unconstrained_uri_buf_size != uri_buf_size) {
		return ERANGE;
	}

#define ERR_OUT(specific_err) {			\
	err = specific_err;					\
	if (server) free(server);			\
	if (path) free(path);				\
	if (cookedpath) free(cookedpath);	\
	return err;							\
	}

#define APPEND_COOKED_PATH(src)										\
	if (err = strcat_s(cookedpath, MAX_PATH, src)) {				\
		ERR_OUT(err);												\
	}

#define CHECK_MALLOC(thing)	\
	if (!thing) {			\
		ERR_OUT(ENOMEM);	\
	}

	// Each of the server and path could concievably require up to the full length
	// of the incoming URI, so allocate that much memory just to be safe.
	server = malloc(uri_buf_size);
	CHECK_MALLOC(server);

	path = malloc(uri_buf_size);
	CHECK_MALLOC(path);

	// Path can be any length, but the OS can only address MAX_PATH, so don't
	// bother allocating more than that. Additionally, the path can be shorter than
	// the cooked path because of the need to add the base directory path.
	cookedpath = malloc(MAX_PATH);
	CHECK_MALLOC(cookedpath);
	cookedpath[0] = '\0';

	APPEND_COOKED_PATH(WEBSITE_DIR);

	// Try to parse a full HTTP path with port
	C_ASSERT(_countof(portstr) < UINT_MAX);
	args_converted = sscanf_s(uri, "http://%[^:/]:%[^/]/%s", server, uri_buf_size, portstr, (unsigned int)_countof(portstr), path, uri_buf_size);
	if (args_converted == 3) {
		port = atoi(portstr);
	}
	else {
		// Try to parse a full HTTP path without port
		args_converted = sscanf_s(uri, "http://%[^/]/%s", server, uri_buf_size, path, uri_buf_size);
		if (args_converted == 2) {
			port = 80;
		}
		else {
			// Try to convert a relative path
			args_converted = sscanf_s(uri, "/%s", path, uri_buf_size);
			if (args_converted == 1 || strcmp(uri, "/") == 0) {
				port = 80;
				server[0] = '\0';
				if (strcmp(uri, "/") == 0) {
					path[0] = '\0';
				}
			}
			else {
				ERR_OUT(EINVAL);
			}
		}
	}

	// Create a filesystem path out of the relpath. Check for .. to avoid escaping
	// out of base directory.
	token = strtok_s(path, "/", &next_token);
	while (token) {
		if (!strcmp(token, "..")) {
			// There's nothing in the HTTP spec prohibiting .., but this implementation
			// chooses not to serve documents with that in the path.
			ERR_OUT(ENOENT);
		}

		APPEND_COOKED_PATH("\\");
		APPEND_COOKED_PATH(token);
		token = strtok_s(NULL, "/", &next_token);
		tokens++;
	}

	// If the URI is just a /, add the default document of index.html
	if (tokens == 0) {
		APPEND_COOKED_PATH("\\index.html");
	}

	if (outserver) *outserver = server;
	else free(server);

	if (outport) *outport = port;

	if (outcookedpath) *outcookedpath = cookedpath;
	else free(cookedpath);

	return 0;
}

//
// This routine attempts to server a static website from disk to a network
// client which made an HTTP 1.0 request.
//
// It expects ctxt to be populated by a previous call to parseheaders().
//
// It returns 0 on success, otherwise a standard POSIX error.
// It also sets the attempt_to_serve_error variable depending on the nature of
// the error.
// If true, the socket connect is intact, and the caller may attempt to serve
// other data (such as a 404 page). If not, it is broken and no further data
// transfer is possible.
//
int serve_document(struct context* ctxt, int* attempt_to_serve_error) {
	// Things needing freeing
	char *filename = NULL, *data = NULL;
	FILE* fp = NULL;
	long file_size;

#define FREE_THINGS_SD() \
	if (filename) free(filename); \
	if (data) free(data); \
	if (fp) fclose(fp);

	// Things not needing freeing
	char full_response[32], *ptr_send;
	size_t amt_read;
	int err, amt_sent = 0;

	// By default serve errors (socket errors will clear this)
	*attempt_to_serve_error = 1;

	if (err = format_uri(ctxt->request_uri, NULL, NULL, NULL, &filename)) {
		return ENOMEM;
	}

	data = malloc(READ_CHUNK_SIZE);
	if (!data) {
		FREE_THINGS_SD();
		return ENOMEM;
	}

	//printf("Serving %s\n", filename);
	if ((err = fopen_s(&fp, filename, "rb")) || !fp) {
		err = errno;
		printf("file %s not found\n", filename);
		FREE_THINGS_SD();
		return err;
	}

	if (err = fseek(fp, 0, SEEK_END)) {
		err = errno;
		FREE_THINGS_SD();
		return err;
	}

	if ((file_size = ftell(fp)) == -1) {
		err = errno;
		FREE_THINGS_SD();
		return err;
	}

	rewind(fp);

	printf("serve %s\n", filename);
	sprintf_s(full_response, _countof(full_response), "HTTP/1.0 200 \r\n");
	if (err = sendall(ctxt->client, full_response, strlen(full_response))) {
		FREE_THINGS_SD();
		*attempt_to_serve_error = 0;
		return err;
	}

	sprintf_s(full_response, _countof(full_response), "Content-Length : %d \r\n\r\n", file_size);
	if (err = sendall(ctxt->client, full_response, strlen(full_response))) {
		FREE_THINGS_SD();
		*attempt_to_serve_error = 0;
		return err;
	}

	do {
		amt_read = fread(data, 1, READ_CHUNK_SIZE, fp);
		ptr_send = data;
		if (err = ferror(fp)) {
			FREE_THINGS_SD();
			*attempt_to_serve_error = 1;
			return err;
		}
		if (amt_read) {
			err = sendall(ctxt->client, data, amt_read);
			if (err) {
				FREE_THINGS_SD();
				*attempt_to_serve_error = 0;
				return err;
			}
		}
	} while (amt_read != 0);

	FREE_THINGS_SD();
	return 0;
}

//
// This routine runs a simple webserver on localhost port 8080.
//
// For each connection received, it spawns a thread which runs the
// client_thread routine.
//
// It never returns.
//
void simple_server() {
	// Initialize Winsock.
	WSADATA d = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &d)) ERROR_EXIT("WSAStartup");
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1) ERROR_EXIT("socket");

	// Setup a socket listening on 8080.
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(8080);
	sa.sin_addr.s_addr = inet_addr("0.0.0.0");
	memset(sa.sin_zero, '\0', sizeof(sa.sin_zero));
	if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) ERROR_EXIT("bind");

	struct sockaddr_storage ta;
	int tas = sizeof(ta);
	if (listen(s, 10) == -1) ERROR_EXIT("listen");

	// Accept connections, creating a new thread for each.
	SOCKET client;
	while (1) {
		client = accept(s, (struct sockaddr*)&ta, &tas);
		if (client == -1) ERROR_EXIT("accept");

		_beginthread(client_thread, 0, (void*)client);
	}
}

int main(int argc, char *argv[]) {
	int err = 0;

#ifndef TESTING

	printf("Starting server in normal (non-test) mode.\n");
	simple_server();
	return 0;

#else 

	printf("Testing the server.\n");

	printf("Testing readline() function.\n");
	err = test_readline();
	printf("done\n");

    return err;

#endif

}

//
// This routine runs from the thread spawned by simple_server in response to an
// incoming TCP connection.
//
// It attemps to parse an HTTP request from a client and, if successful, return
// a single static website.
//
// After doing so (successful or not), it exits and the thread terminates.
//
// It does not return a value.
//
void client_thread(void* thread_argument) {
	SOCKET client = (SOCKET)thread_argument;

	int err, attempt_to_serve_error = 1;
	struct context* ctxt;
	err = init_lineparser(&ctxt);

	if (!err) {
		ctxt->client = client;
		err = parseheaders(ctxt);
		if (!err) {
			err = serve_document(ctxt, &attempt_to_serve_error);
			free(ctxt->request_uri);
		}
	}

	if (err && attempt_to_serve_error) {
		serveerr(ctxt, err);
	}

	closesocket(ctxt->client);
	free(ctxt->line_buffer);
	free(ctxt);
}
