#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#define BUFFER_SIZE 1024
#define LOG_FILE_SYSTEM "system.log"
#define LOG_FILE_ACCESS "access.log"
#define MAX_EVENTS 100

int running = 1;
int debug_mode = 1;
char log_file_system[BUFFER_SIZE] = "system.log";//日志
char log_file_access[BUFFER_SIZE] = "access.log";//日志

//基本安全证书用户名密码
const char* AUTH_USERNAME = "jyt";
const char* AUTH_PASSWORD = "111";
/*下列为函数声明*/
void log_message(const char* filename, const char* level, const char* message);//日志信息
void log_system(const char* level, const char* message);//系统日志
void log_access(const char* client_ip, const char* request_line);//访问日志
void error(const char* msg);//错误报告
void set_nonblocking(int sock);//设置套接字为非阻塞套接字
const char* get_mime_type(const char* path);//确定对应的MIME类型
int read_file(const char* file_path, char** content, size_t* length);//读文件
int calcDecodeLength(const char* b64input);//计算长度
int authenticate(const char* auth_header);//授权、安全认证
int base64_decode(const char* input, unsigned char** output);//Base64编码
void handle_get_request(int client_sock, const char* path, const char* auth_header, struct sockaddr_in client_addr);//get请求
void handle_post_request(int client_sock, const char* request, const char* body, struct sockaddr_in client_addr);//post请求
void handle_client_request(int client_sock, struct sockaddr_in client_addr);//客户端链接
void sigint_handler(int signo);//信号量
void parse_config(const char* filename, char* address, int* port, char* log_level, char* system_log, char* access_log, char* index_path, char* search_path, char* add_path);//配置文件导入

int main() {
    signal(SIGINT, sigint_handler);
    char address[BUFFER_SIZE] = "127.0.0.1";
    int port = 8080;
    char log_level[BUFFER_SIZE] = "INFO";
    char index_path[BUFFER_SIZE] = "www/index1.html";
    char search_path[BUFFER_SIZE] = "/search";
    char add_path[BUFFER_SIZE] = "/add";
    //配置文件
    parse_config("config.json", address, &port, log_level, log_file_system, log_file_access, index_path, search_path, add_path);
    int server_sock, epoll_fd;
    struct sockaddr_in server_addr;
    struct epoll_event ev, events[MAX_EVENTS];
    int nfds, i;
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        error("socket");
    }
    log_system("INFO", "Socket created");
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        error("setsockopt");
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        error("bind");
    }
    log_system("INFO", "Bind done");
    if (listen(server_sock, 10) < 0) {
        error("listen");
    }
    log_system("INFO", "Waiting for incoming connections...");
    set_nonblocking(server_sock);
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        error("epoll_create1");
    }
    ev.events = EPOLLIN;
    ev.data.fd = server_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sock, &ev) < 0) {
        error("epoll_ctl");
    }
    while (running) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            error("epoll_wait");
        }

        for (i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
                if (client_sock < 0) {
                    error("accept");
                }
                log_system("INFO", "Connection accepted");
                set_nonblocking(client_sock);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = client_sock;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sock, &ev) < 0) {
                    error("epoll_ctl");
                }
            }
            else {
                handle_client_request(events[i].data.fd, *(struct sockaddr_in*)&events[i].data.ptr);
                close(events[i].data.fd);
            }
        }
    }
    close(server_sock);
    return 0;
}

/*各个函数实现*/

//导入信息
void log_message(const char* filename, const char* level, const char* message) {
    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        perror("Failed to open log file");
        return;
    }
    time_t now;
    time(&now);
    char* timestr = ctime(&now);//系统时间
    timestr[strlen(timestr) - 1] = '\0';
    fprintf(file, "[%s] [%s] %s\n", timestr, level, message);//输出
    fclose(file);
}

//系统日志
void log_system(const char* level, const char* message) {
    if (strcmp(level, "DEBUG") == 0 && !debug_mode) {
        return; // 如果DEBUG日志关闭，则不记录
    }
    log_message(LOG_FILE_SYSTEM, level, message);
}

//访问日志
void log_access(const char* client_ip, const char* request_line) {
    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "Client IP: %s, Request: %s\n", client_ip, request_line);
    log_message(LOG_FILE_ACCESS, "INFO", message);
}

//错误异常
void error(const char* msg) {
    perror(msg);
    log_system("ERROR", msg);
    exit(1);
}

//设置套接字为非阻塞套接字
void set_nonblocking(int sock) {
    int opts = fcntl(sock, F_GETFL);
    if (opts < 0) {
        error("fcntl(F_GETFL)");
    }
    opts = (opts | O_NONBLOCK);
    if (fcntl(sock, F_SETFL, opts) < 0) {
        error("fcntl(F_SETFL)");
    }
}

//解析HTTP请求的文件扩展名，根据文件扩展名确定对应的MIME类型
const char* get_mime_type(const char* path) {
    if (strstr(path, ".html")) return "text/html";
    if (strstr(path, ".css")) return "text/css";
    if (strstr(path, ".js")) return "application/javascript";
    if (strstr(path, ".jpg")) return "image/jpg";
    if (strstr(path, ".jpeg")) return "image/jpeg";
    if (strstr(path, ".gif")) return "image/gif";
    if (strstr(path, ".ico")) return "image/x-icon";
    if (strstr(path, ".png")) return "image/png";
    return "text/plain";
}

//读文件
int read_file(const char* file_path, char** content, size_t* length) {
    FILE* file = fopen(file_path, "r");

    if (!file) {
        return 0; // 读取失败
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    *content = (char*)malloc(*length + 1);
    if (!*content) {
        fclose(file);
        return 0; // 内存分配失败
    }

    fread(*content, 1, *length, file);
    (*content)[*length] = '\0'; // 添加 null 终结符

    fclose(file);
    return 1; // 读取成功
}

//计算经 base64 编码后信息的长度
int calcDecodeLength(const char* b64input) {
    int len = strlen(b64input), padding = 0;
    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') // last char is =
        padding = 1;
    return (int)len * 0.75 - padding;
}

//HTTP Basic认证函数
int authenticate(const char* auth_header) {
    log_system("DEBUG", "Entering authenticate function");

    if (auth_header == NULL) {
        log_system("ERROR", "Authorization header not found");
        return 0;  
    }

    char* encoded_credentials = strdup(auth_header + 21);
    unsigned char* decoded_credentials;
    int decoded_length = base64_decode(encoded_credentials, &decoded_credentials);
    free(encoded_credentials);

    //错误处理
    if (decoded_length < 0) {
        log_system("ERROR", "Memory allocation for decoded credentials failed");
        return 0;  
    }
    char credentials[BUFFER_SIZE];
    snprintf(credentials, sizeof(credentials), "%s", decoded_credentials);
    free(decoded_credentials);

    char* username = strtok(credentials, ":");
    char* password = strtok(NULL, ":");
    //比较判断输入的用户名和密码与授权正确用户名密码
    //输入成功返回值为1，失败返回值为0
    int auth_result = (username && password && strcmp(username, AUTH_USERNAME) == 0 && strcmp(password, AUTH_PASSWORD) == 0);
    return auth_result;
}
//GET and POST
void handle_get_request(int client_sock, const char* path, const char* auth_header, struct sockaddr_in client_addr) {
    //将字符串比较输入
    if (strcmp(path, "/") == 0) {
        path = "/index1.html";
    }

    if (strcmp(path, "/secured") == 0) {
        if (!authenticate(auth_header)) {
            const char* auth_response =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 43\r\n"
                "WWW-Authenticate: Basic realm=\"Secure Area\"\r\n"
                "\r\n"
                "<html><body><h1>401 Unauthorized</h1></body></html>";
            send(client_sock, auth_response, strlen(auth_response), 0);
            close(client_sock);
            return;
        }
        path = "/index1.html";
        //return;
    }

    char file_path[BUFFER_SIZE] = "www";
    strncat(file_path, path, sizeof(file_path) - strlen(file_path) - 1);

    char* file_content;
    size_t file_length;

    if (!read_file(file_path, &file_content, &file_length)) {
        const char* not_found_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "<html><body><h1>404 Not Found</h1></body></html>";
        send(client_sock, not_found_response, strlen(not_found_response), 0);
        log_system("ERROR", "File not found");
        close(client_sock);
        return;
    }

    const char* mime_type = get_mime_type(file_path);
    //http显示
    char response_template[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n";
    char response_header[BUFFER_SIZE];
    snprintf(response_header, sizeof(response_header), response_template, mime_type, file_length);

    send(client_sock, response_header, strlen(response_header), 0);
    send(client_sock, file_content, file_length, 0);

    free(file_content);
    close(client_sock);
} 

void handle_post_request(int client_sock, const char* request, const char* body, struct sockaddr_in client_addr) {
    char key1[BUFFER_SIZE] = { 0 };
    char student_id[BUFFER_SIZE] = { 0 };
    char name[BUFFER_SIZE] = { 0 };
    char gender[BUFFER_SIZE] = { 0 };
    char dorm[BUFFER_SIZE] = { 0 };

    // 解析POST请求
    char* body_copy = strdup(body);
    char* token = strtok(body_copy, "&");
    while (token) {
        if (strncmp(token, "key1=", 5) == 0) {
            strncpy(key1, token + 5, sizeof(key1) - 1);
        }
        else if (strncmp(token, "student_id=", 11) == 0) {
            strncpy(student_id, token + 11, sizeof(student_id) - 1);
        }
        else if (strncmp(token, "name=", 5) == 0) {
            strncpy(name, token + 5, sizeof(name) - 1);
        }
        else if (strncmp(token, "gender=", 7) == 0) {
            strncpy(gender, token + 7, sizeof(gender) - 1);
        }
        else if (strncmp(token, "dorm=", 5) == 0) {
            strncpy(dorm, token + 5, sizeof(dorm) - 1);
        }
        token = strtok(NULL, "&");
    }
    free(body_copy);

    if (strcmp(request, "/search") == 0) {
        char file_path[BUFFER_SIZE] = "www/";
        strcat(file_path, key1);
        strcat(file_path, ".txt");

        char* file_content;
        size_t file_length;
        if (!read_file(file_path, &file_content, &file_length)) {
            const char* not_found_response =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 46\r\n"
                "\r\n"
                "<html><body><h1>404 Not Found</h1></body></html>";
            send(client_sock, not_found_response, strlen(not_found_response), 0);
            log_system("ERROR", "File not found");
            close(client_sock);
            return;
        }

        char result[BUFFER_SIZE * 10] = "";
        char* line = strtok(file_content, "\n");
        while (line != NULL) {
            if (strstr(line, student_id) != NULL) {
                strcat(result, line);
                strcat(result, "<br>");
            }
            line = strtok(NULL, "\n");
        }

        char response_template[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "\r\n";
        char response_header[BUFFER_SIZE];
        snprintf(response_header, sizeof(response_header), response_template, strlen(result));

        send(client_sock, response_header, strlen(response_header), 0);
        send(client_sock, result, strlen(result), 0);

        free(file_content);
        close(client_sock);
    }
    else if (strcmp(request, "/add") == 0) {
        char file_path[BUFFER_SIZE] = "www/";
        strcat(file_path, key1);
        strcat(file_path, ".txt");

        FILE* file = fopen(file_path, "a");
        if (!file) {
            const char* error_response =
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 36\r\n"
                "\r\n"
                "<html><body><h1>500 Internal Server Error</h1></body></html>";
            send(client_sock, error_response, strlen(error_response), 0);
            log_system("ERROR", "Failed to open file for appending");
            close(client_sock);
            return;
        }
        fprintf(file, "%s %s %s %s\n", student_id, name, gender, dorm);
        fclose(file);

        const char* success_response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 27\r\n"
            "\r\n"
            "<html><body><h1>Record added</h1></body></html>";
        send(client_sock, success_response, strlen(success_response), 0);
        close(client_sock);
    }
    else {
        const char* not_found_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "<html><body><h1>404 Not Found</h1></body></html>";
        send(client_sock, not_found_response, strlen(not_found_response), 0);
        log_system("ERROR", "Invalid request path");
        close(client_sock);
    }
}

void handle_client_request(int client_sock, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    log_system("DEBUG", "Starting to handle client request");
    int received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
    if (received < 0) {
        error("recv failed");
    }

    buffer[received] = '\0';
    log_system("DEBUG", "Received request");
    char method[BUFFER_SIZE], path[BUFFER_SIZE], protocol[BUFFER_SIZE];
    sscanf(buffer, "%s %s %s", method, path, protocol);
    
    char* auth_header = NULL;
    char* header_start = strstr(buffer, "Authorization: ");
    if (header_start) {
        auth_header = strtok(header_start, "\r\n");
    }

    log_access(inet_ntoa(client_addr.sin_addr), buffer);

    if (strcmp(method, "GET") == 0) {
        handle_get_request(client_sock, path, auth_header, client_addr);
    }
    else if (strcmp(method, "POST") == 0) {
        char* body = strstr(buffer, "\r\n\r\n") + 4;
        handle_post_request(client_sock, path, body,  client_addr);
    }
    else {
        const char* not_implemented_response =
            "HTTP/1.1 501 Not Implemented\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 50\r\n"
            "\r\n"
            "<html><body><h1>501 Not Implemented</h1></body></html>";
        send(client_sock, not_implemented_response, strlen(not_implemented_response), 0);
        close(client_sock);
        log_system("DEBUG", "Finished handling client request");
    }
}

//信号量机制
void sigint_handler(int signo) {
    if (signo == SIGINT) {
        running = 0;
    }
}

//实现server对配置文件的解析
void parse_config(const char* filename, char* address, int* port, char* log_level, char* system_log, char* access_log, char* index_path, char* search_path, char* add_path) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Cannot open config file");
        exit(EXIT_FAILURE);
    }

    struct json_object* parsed_json;
    struct json_object* server;
    struct json_object* log;
    struct json_object* routes;
    struct json_object* address_json;
    struct json_object* port_json;
    struct json_object* level_json;
    struct json_object* system_log_json;
    struct json_object* access_log_json;
    struct json_object* index_json;
    struct json_object* search_json;
    struct json_object* add_json;

    char buffer[1024];
    fread(buffer, 1024, 1, fp);
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);
    json_object_object_get_ex(parsed_json, "server", &server);
    json_object_object_get_ex(parsed_json, "log", &log);
    json_object_object_get_ex(parsed_json, "routes", &routes);

    json_object_object_get_ex(server, "address", &address_json);
    json_object_object_get_ex(server, "port", &port_json);

    json_object_object_get_ex(log, "level", &level_json);
    json_object_object_get_ex(log, "system_log", &system_log_json);
    json_object_object_get_ex(log, "access_log", &access_log_json);

    json_object_object_get_ex(routes, "/", &index_json);
    json_object_object_get_ex(routes, "/search", &search_json);
    json_object_object_get_ex(routes, "/add", &add_json);

    strcpy(address, json_object_get_string(address_json));
    *port = json_object_get_int(port_json);

    strcpy(log_level, json_object_get_string(level_json));
    strcpy(system_log, json_object_get_string(system_log_json));
    strcpy(access_log, json_object_get_string(access_log_json));
    strcpy(index_path, json_object_get_string(index_json));
    strcpy(search_path, json_object_get_string(search_json));
    strcpy(add_path, json_object_get_string(add_json));

    json_object_put(parsed_json); 
}

//将传送的信息经 base64 编码
int base64_decode(const char* input, unsigned char** output) {
    BIO* bio, * b64;
    int decodeLen = calcDecodeLength(input);
    *output = (unsigned char*)malloc(decodeLen + 1);
    if (*output == NULL) {
        return -1;
    }
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, *output, strlen(input));
    (*output)[decodeLen] = '\0';
    BIO_free_all(bio);
    return decodeLen;
}

