#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <http_parser.h>
#include <openssl/sha.h>
#include <inttypes.h>
#include <ctype.h>
#include "base64.h"

#define MAX_CONNECTIONS_BACKLOG 5
#define MAX_HTTP_HEADERS 20
#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define MSG_BUFFER_SIZE 1024*80
#define MAX_HTTP_MSG_SIZE MSG_BUFFER_SIZE*10
#define MAX_FRAME_SIZE 2^32

struct http_header {
	char *key;
	char *value;
};

struct http_headers {
	size_t count;
	struct http_header headers[MAX_HTTP_HEADERS];
	int complete;
};

void exit_with_error(const char *err) {
	perror(err);
	exit(1);
}

int get_socket_port(const int sockfd) {
	
	struct sockaddr_in socket_addr;
	socklen_t len = sizeof(socket_addr);

	int could_get_sockname =
		getsockname(sockfd, (struct sockaddr *)&socket_addr, &len) == 0;

	if (could_get_sockname)
		return ntohs(socket_addr.sin_port);
	else return -1;
}

int on_header_field(const http_parser *parser, const char *at, const size_t len) {
	struct http_headers *parsed_headers = parser->data;

	if (parsed_headers->count == MAX_HTTP_HEADERS) {
		printf("Request contained too many headers\n");
		exit(1);
	}
	
	char *key = calloc(1, len + 1);
	strncpy(key, at, len);

	parsed_headers->headers[parsed_headers->count].key = key;
	
	return 0;
}

int on_header_value(http_parser *parser, char *at, size_t len) {
	struct http_headers *parsed_headers = parser->data;

	char *value = calloc(1, len + 1);
	strncpy(value, at, len);

	parsed_headers->headers[parsed_headers->count].value = value;
	parsed_headers->count++;
	
	return 0;
}

int on_headers_complete(http_parser *parser) {
	((struct http_headers *)parser->data)->complete = 1;
	return 0;
}

char *get_header_val(const struct http_headers *headers, const char *header_key) {
	size_t len = headers->count;
	
	for(size_t i = 0; i < len; i++) {
		struct http_header h = headers->headers[i];
		if (strcmp(h.key, header_key) == 0)
			return h.value;
	}

	return NULL;
}

void upcase(char *s) {
	while((*s = toupper(*s)))
		++s;
}

int perform_websocket_handshake(int client_sockfd, const struct http_headers *upgrade_headers) {
	
	char *sec_websocket_val = get_header_val(upgrade_headers, "Sec-WebSocket-Key");

	if (sec_websocket_val == NULL) {
		printf("Request did not contain a Sec-Webnsocket-Key\n");
		return 0;
	} else {		
		size_t concatenated_val_len =
			strlen(sec_websocket_val) + strlen(WEBSOCKET_GUID) + 1;

		char *concatenated_val = malloc(concatenated_val_len);
		char *pos = concatenated_val;
		pos = stpcpy(pos, sec_websocket_val);
		pos = stpcpy(pos, WEBSOCKET_GUID);
		*(pos + 1) = '\0';

		unsigned char sha1_hash[SHA_DIGEST_LENGTH];

		SHA1((unsigned char *)concatenated_val, concatenated_val_len - 1, sha1_hash);

		size_t b64_str_len = base64_encode(sha1_hash, NULL, sizeof(sha1_hash), 0);

		char *b64_str = calloc(1, b64_str_len + 1);

		base64_encode(sha1_hash, b64_str, sizeof(sha1_hash), 0);

		char response[2048];

		snprintf(response,sizeof(response),
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n\r\n",
			 b64_str);

		write(client_sockfd, response, strlen(response));

		fprintf(stderr, "Handshake sent\n");

		return 1;
	}
}

int send_websocket_frame(int client_sockfd, const char *payload, size_t payload_len) {
	unsigned char frame_buf[MAX_FRAME_SIZE];
	
	// FIN = 1 (it's the last message) RSV1 = 0, RSV2 = 0, RSV3 =
	// 0 OpCode(4b) = 1 (text)
	frame_buf[0] = 0x81;
	
	size_t offset;

	if (payload_len < 126) {
		offset = 2;
		frame_buf[1] = (char)payload_len;
	} else if (payload_len < 65536) {
		offset = 4;
		frame_buf[1] = 126;
		*((short *)frame_buf + 2) = htons(payload_len);
	} else {
		fprintf(stderr, "Cannot write payloads larger than 2^32 bytes (can't htoni)");
		exit(1);
	}

	memcpy(frame_buf + offset, payload, payload_len);

	size_t msg_size = offset + payload_len;

	write(client_sockfd, frame_buf, msg_size);

	return 0;
}

void handle_websocket(int client_sockfd, const struct http_headers *upgrade_headers) {
	// RFC6455 for websockets: https://tools.ietf.org/html/rfc6455

	int handshake_was_successful =
		perform_websocket_handshake(client_sockfd, upgrade_headers);

	if (handshake_was_successful) {
		unsigned char buf[MSG_BUFFER_SIZE];
		
		while(1) {
			ssize_t client_msg_len = recv(client_sockfd, buf, sizeof(buf), 0);

			if (client_msg_len < 0) {
				perror("Error reading websocket frame from client");
				return;
			} else if (client_msg_len == 0) {
				fprintf(stderr, "Client closed connection while in frame mode\n");
				break;
			} else {				
				// A client message follows the binary format outlined
				// in the RFC
				unsigned char has_fin = buf[0] & 0x80;
				unsigned char has_rsv1 = buf[0] & 0x40;
				unsigned char has_rsv2 = buf[0] & 0x20;
				unsigned char has_rsv3 = buf[0] & 0x10;
				unsigned char op_code = buf[0] & 0xF;
				unsigned char has_mask = buf[1] & 0x80;

				unsigned char small_payload_len = buf[1] & 0x7F;
				
				unsigned char mask_offset;
				unsigned long payload_len;

				if (small_payload_len < 126) {
					// Just use the specified length
					payload_len = small_payload_len;
					mask_offset = 2;
				} else if (small_payload_len == 126) {
					unsigned short payload_len_nbo = *((unsigned short *)buf + 2);
					payload_len = ntohs(payload_len_nbo);
					mask_offset = 4;
				} else {
					// The following 8 bytes are an unsigned 64-bit integer. MSB = 0
					// multibyte lengths are in network byte order
					fprintf(stderr, "64-bit payload lengths not supported (no ntohll available)\n");
					exit(1);
					mask_offset = 10;				
				}					

				unsigned char masking_key[4];
				masking_key[0] = buf[mask_offset];
				masking_key[1] = buf[mask_offset + 1];
				masking_key[2] = buf[mask_offset + 2];
				masking_key[3] = buf[mask_offset + 3];

				char *masked_payload_data = calloc(1, payload_len + 1);
				const char *payload_start = (char *)buf + mask_offset + 4;				
				strncpy(masked_payload_data, payload_start, payload_len);

				for (size_t i = 0; i < payload_len; i++) {
					char mask = masking_key[i % 4];
					masked_payload_data[i] = masked_payload_data[i] ^ mask;
				}

				printf("Unmasked Payload: %s\n", masked_payload_data);

				upcase(masked_payload_data);

				send_websocket_frame(client_sockfd, masked_payload_data, payload_len);
			}
		}
	} else {
		fprintf(stderr, "Client handshake failed\n");
	}
}

void handle_client_connection(int client_sockfd) {
	// The first thing a client should send is a HTTP GET request
	// to upgrade the connection to Websocket. Anything else is a
	// bad request.
	
	ssize_t bytes_recv_total = 0;

	for(;;) {
		http_parser_settings settings = {0};
		settings.on_header_field = (http_data_cb)on_header_field;
		settings.on_header_value = (http_data_cb)on_header_value;
		settings.on_headers_complete = (http_cb)on_headers_complete;
		
		http_parser *parser = (http_parser *)malloc(sizeof(http_parser));
		http_parser_init(parser, HTTP_REQUEST);
		
		struct http_headers *parsed_headers =
			(struct http_headers *)malloc((sizeof(struct http_headers)));
		
		parser->data = parsed_headers;
		
		char buf[MSG_BUFFER_SIZE];
		ssize_t bytes_recv;
		
		bytes_recv = recv(client_sockfd, buf, sizeof(buf), 0);
		bytes_recv_total += bytes_recv;

		if (bytes_recv > 0) {
			http_parser_execute(parser, &settings, buf, bytes_recv);

			printf("%s\n", buf);

			if (parsed_headers->complete) {
				if (parser->upgrade) {
					printf("Connection upgrade requested. Performing upgrade\n");
					handle_websocket(client_sockfd, parsed_headers);
					break;
				} else {
					fprintf(stderr, "Request was not an upgrade request.\n");
					break;
				}
			}
		} else if (bytes_recv == 0) {
			fprintf(stderr, "Client closed the connection\n");
			break;
		} else {
			perror("Error recieving data from client");
			break;
		}

		

		if (bytes_recv_total > MAX_HTTP_MSG_SIZE) {
			fprintf(stderr, "Client initial HTTP message exceeded the maximum message size\n");
			break;
		} else continue;

		free(parser);
		free(parsed_headers);
	}
}

void accept_connections_through(int server_sockfd) {
	for(;;) {
		struct sockaddr_in client_address;
		unsigned int client_address_len = sizeof(client_address);
		
		int client_sockfd =
			accept(server_sockfd, (struct sockaddr *) &client_address, &client_address_len);

		if (client_sockfd > 0) {
					handle_client_connection(client_sockfd);
					shutdown(client_sockfd, 2);

		} else {
					exit_with_error("Error accepting client connection");
		}
	}
}

int try_open_server_on_port(int port) {
	
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (server_socket < 0)
		exit_with_error("Error opening socket");

	struct sockaddr_in server_address = {0};

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = port;

	int socket_could_not_bind =
		bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0;

	if (socket_could_not_bind)
		exit_with_error("Error binding the socket to an address");

	int socket_could_not_start_listening =
		listen(server_socket, MAX_CONNECTIONS_BACKLOG) < 0;

	if (socket_could_not_start_listening)
		exit_with_error("Error making the socket start listening");

	int server_port = get_socket_port(server_socket);

	if (server_port < 0)
		exit_with_error("Error getting the server's port\n");
	
	fprintf(stderr, "Server listening on port %i\n", server_port);

	return server_socket;
}

int main() {
	int server_sockfd = try_open_server_on_port(0);
	accept_connections_through(server_sockfd);
}
