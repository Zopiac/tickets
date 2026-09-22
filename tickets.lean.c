#define _GNU_SOURCE
#include <microhttpd.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PORT 8080
#define MAX_BODY 20000

static sqlite3 *db;

static void die(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static void json_response(struct MHD_Connection *connection, unsigned status, const char *json) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);

    if (!response)
        return;

    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "same-origin");

    MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
}

static void init_db(void) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS tickets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ticket_number TEXT NOT NULL UNIQUE,"
        "ticket_date TEXT NOT NULL,"
        "day_sequence INTEGER NOT NULL,"
        "name TEXT NOT NULL,"
        "severity TEXT NOT NULL CHECK(severity IN ('Low','High')),"
        "problem TEXT NOT NULL,"
        "client_time_local TEXT,"
        "client_time_iso TEXT,"
        "client_timezone TEXT,"
        "client_timezone_offset_minutes INTEGER,"
        "user_agent TEXT,"
        "language TEXT,"
        "screen_width INTEGER,"
        "screen_height INTEGER,"
        "pixel_ratio REAL,"
        "cookie_string TEXT,"
        "source_ip TEXT NOT NULL,"
        "received_at TEXT NOT NULL,"
        "completed INTEGER NOT NULL DEFAULT 0,"
        "UNIQUE(ticket_date, day_sequence)"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_ticket_received "
        "ON tickets(received_at);"

        "CREATE INDEX IF NOT EXISTS idx_ticket_severity "
        "ON tickets(severity);"

        "CREATE INDEX IF NOT EXISTS idx_ticket_completed "
        "ON tickets(completed);"

        "CREATE INDEX IF NOT EXISTS idx_ticket_ip "
        "ON tickets(source_ip);"

        "CREATE INDEX IF NOT EXISTS idx_ticket_date "
        "ON tickets(ticket_date);";

    char *error = NULL;

    if (sqlite3_open("tickets.db", &db) != SQLITE_OK)
        die(sqlite3_errmsg(db));

    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "SQLite: %s\n", error);
        sqlite3_free(error);
        exit(EXIT_FAILURE);
    }
}

static void utc_date(char output[16]) {
    time_t now = time(NULL);
    struct tm tm_now;

    gmtime_r(&now, &tm_now);
    strftime(output, 16, "%Y%m%d", &tm_now);
}

static int next_daily_sequence(const char *ticket_date) {
    sqlite3_stmt *statement = NULL;
    int sequence = 1;

    const char *sql = "SELECT COALESCE(MAX(day_sequence), 0) + 1 FROM tickets WHERE ticket_date = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(statement, 1, ticket_date, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(statement) == SQLITE_ROW)
        sequence = sqlite3_column_int(statement, 0);

    sqlite3_finalize(statement);
    return sequence;
}

static const char *str_field(cJSON *object, const char *name) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(item) ? item->valuestring : "";
}

static int int_field(cJSON *object, const char *name) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsNumber(item) ? item->valueint : 0;
}

static double double_field(cJSON *object, const char *name) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsNumber(item) ? item->valuedouble : 0.0;
}

static void utc_now(char output[32]) {
    time_t now = time(NULL);
    struct tm tm_now;

    gmtime_r(&now, &tm_now);
    strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &tm_now);
}

static int valid_length(const char *text, size_t maximum) {
    return text && strlen(text) <= maximum;
}

static int get_client_ip(struct MHD_Connection *connection, char output[INET6_ADDRSTRLEN]) {
    //const char *forwarded;
    const char *real_ip;

    real_ip = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Real-IP");

    if (real_ip && *real_ip) {
        snprintf(output, INET6_ADDRSTRLEN, "%s", real_ip);
        return 1;
    }

     // Fallback for requests that do not contain X-Real-IP.
     // This will normally be 127.0.0.1 when accessed through nginx
    const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

    if (!info || !info->client_addr)
        return 0;

    const struct sockaddr *address = info->client_addr;

    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        return inet_ntop(AF_INET, &ipv4->sin_addr, output, INET6_ADDRSTRLEN) != NULL;
    }

    if (address->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        return inet_ntop(AF_INET6, &ipv6->sin6_addr, output, INET6_ADDRSTRLEN) != NULL;
    }
    
    return 0;
}

static int insert_ticket(const char *body,
                         const char *source_ip,
                         char **ticket_number_out,
                         char **error_message) {
    cJSON *json = NULL;
    sqlite3_stmt *statement = NULL;
    char received_at[32];
    char ticket_date[16];
    char ticket_number[64];
    int result;
    int sequence;

    *ticket_number_out = NULL;
    *error_message = NULL;

    json = cJSON_ParseWithLength(body, strlen(body));

    if (!json) {
        *error_message = strdup("invalid JSON");
        return 0;
    }

    const char *name = str_field(json, "name");
    const char *severity = str_field(json, "severity");
    const char *problem = str_field(json, "problem");

    if (!*name || !*problem || (strcmp(severity, "Low") != 0 && strcmp(severity, "High") != 0) ||
    !valid_length(name, 120) || !valid_length(problem, 10000)) {
        *error_message = strdup("invalid name, severity, or problem");
        cJSON_Delete(json);
        return 0;
    }

    utc_now(received_at);
    utc_date(ticket_date);

    // A few retries handle two requests arriving simultaneously.
    // SQLite's UNIQUE constraint is the final authority
    for (int attempt = 0; attempt < 10; attempt++) {
        sequence = next_daily_sequence(ticket_date);

        if (sequence < 1) {
            *error_message = strdup("could not determine daily sequence");
            cJSON_Delete(json);
            return 0;
        }

        snprintf(ticket_number, sizeof(ticket_number), "%s_%04d", ticket_date, sequence);

        const char *sql = "INSERT INTO tickets (ticket_number,ticket_date,day_sequence,"
                          "name,severity,problem,client_time_local,client_time_iso,"
                          "client_timezone,client_timezone_offset_minutes,user_agent,"
                          "language,screen_width,screen_height,pixel_ratio,"
                          "cookie_string,source_ip,received_at)"
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        result = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

        if (result != SQLITE_OK) {
            *error_message = strdup(sqlite3_errmsg(db));
            cJSON_Delete(json);
            return 0;
        }

#define BIND_TEXT(index, value) sqlite3_bind_text(statement, index, value, -1, SQLITE_TRANSIENT)

        BIND_TEXT(1, ticket_number);
        BIND_TEXT(2, ticket_date);
        sqlite3_bind_int(statement, 3, sequence);
        BIND_TEXT(4, name);
        BIND_TEXT(5, severity);
        BIND_TEXT(6, problem);
        BIND_TEXT(7, str_field(json, "client_time_local"));
        BIND_TEXT(8, str_field(json, "client_time_iso"));
        BIND_TEXT(9, str_field(json, "client_timezone"));

        sqlite3_bind_int(statement, 10, int_field(json, "client_timezone_offset_minutes"));

        BIND_TEXT(11, str_field(json, "user_agent"));
        BIND_TEXT(12, str_field(json, "language"));

        cJSON *screen = cJSON_GetObjectItemCaseSensitive(json, "screen");

        sqlite3_bind_int(statement, 13, int_field(screen, "width"));
        sqlite3_bind_int(statement, 14, int_field(screen, "height"));
        sqlite3_bind_double(statement, 15, double_field(screen, "pixel_ratio"));

        BIND_TEXT(16, str_field(json, "cookie_string"));
        BIND_TEXT(17, source_ip);
        BIND_TEXT(18, received_at);

#undef BIND_TEXT

        result = sqlite3_step(statement);
        sqlite3_finalize(statement);
        statement = NULL;

        if (result == SQLITE_DONE) {
            *ticket_number_out = strdup(ticket_number);
            cJSON_Delete(json);
            return 1;
        }

        //A concurrent writer may have taken this sequence number, so retry.
        if (result == SQLITE_CONSTRAINT)
            continue;

        *error_message = strdup(sqlite3_errmsg(db));
        cJSON_Delete(json);
        return 0;
    }

    *error_message = strdup("could not allocate a daily ticket number");
    cJSON_Delete(json);
    return 0;
}

struct upload {
    char *body;
    size_t length;
};

static enum MHD_Result request_handler(void *cls,
                                       struct MHD_Connection *connection,
                                       const char *url,
                                       const char *method,
                                       const char *version,
                                       const char *upload_data,
                                       size_t *upload_data_size,
                                       void **con_cls) {
    (void)cls;
    (void)version;

    struct upload *upload = *con_cls;

    if (!upload) {
        upload = calloc(1, sizeof(*upload));
        if (!upload)
            return MHD_NO;

        *con_cls = upload;
        return MHD_YES;
    }

    if (strcmp(method, "POST") != 0 || strcmp(url, "/api/tickets") != 0) {
        json_response(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
        free(upload->body);
        free(upload);
        *con_cls = NULL;
        return MHD_YES;
    }

    if (*upload_data_size > 0) {
        if (upload->length + *upload_data_size > MAX_BODY) {
            json_response(connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE, "{\"error\":\"request too large\"}");
            free(upload->body);
            free(upload);
            *con_cls = NULL;
            return MHD_YES;
        }

        char *new_body = realloc(upload->body, upload->length + *upload_data_size + 1);
        if (!new_body)
            return MHD_NO;

        upload->body = new_body;
        memcpy(upload->body + upload->length, upload_data, *upload_data_size);

        upload->length += *upload_data_size;
        upload->body[upload->length] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    //const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

    char source_ip[INET6_ADDRSTRLEN] = "unknown";

    if (!get_client_ip(connection, source_ip))
        snprintf(source_ip, sizeof(source_ip), "unknown");
    char *ticket_number = NULL;
    char *error = NULL;

    if (!insert_ticket(upload->body ? upload->body : "", source_ip, &ticket_number, &error)) {
        char response[512];

        snprintf(response, sizeof(response), "{\"error\":\"%s\"}", error ? error : "database error");

        json_response(connection, MHD_HTTP_BAD_REQUEST, response);
        free(error);
    } else {
        char response[256];

        snprintf(response, sizeof(response), "{\"ok\":true,\"ticket_id\":\"%s\"}", ticket_number);

        json_response(connection, MHD_HTTP_CREATED, response);
        free(ticket_number);
    }

    free(upload->body);
    free(upload);
    *con_cls = NULL;
    return MHD_YES;
}

int main(int argc, char **argv) {
    init_db();

    if (argc >= 2 && strcmp(argv[1], "serve") == 0) {
        unsigned short port = argc >= 3 ? (unsigned short)atoi(argv[2]) : PORT;

        struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, port, NULL, NULL, &request_handler, NULL, MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30, MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t)MAX_BODY + 4096, MHD_OPTION_END);

        if (!daemon)
            die("could not start HTTP server");

        printf("listening on http://127.0.0.1:%u\n", port);
        printf("press Ctrl-C to stop\n");

        for (;;)
            pause();

        MHD_stop_daemon(daemon);
    }

    sqlite3_close(db);
    return 0;
}