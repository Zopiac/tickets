#define _GNU_SOURCE
#include <microhttpd.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <stdint.h>
#include <netinet/in.h>

#define PORT 8080
#define MAX_BODY 20000

static sqlite3 *db;

static void die(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static void json_response(struct MHD_Connection *connection,
                          unsigned status, const char *json)
{
    struct MHD_Response *response =
        MHD_create_response_from_buffer(strlen(json), (void *)json,
                                        MHD_RESPMEM_MUST_COPY);

    if (!response)
        return;

    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "same-origin");

    MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
}

static void init_db(void)
{
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

static void utc_date(char output[16])
{
    time_t now = time(NULL);
    struct tm tm_now;

    gmtime_r(&now, &tm_now);
    strftime(output, 16, "%Y%m%d", &tm_now);
}

static int next_daily_sequence(const char *ticket_date)
{
    sqlite3_stmt *statement = NULL;
    int sequence = 1;

    const char *sql =
        "SELECT COALESCE(MAX(day_sequence), 0) + 1 "
        "FROM tickets WHERE ticket_date = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(statement, 1, ticket_date, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(statement) == SQLITE_ROW)
        sequence = sqlite3_column_int(statement, 0);

    sqlite3_finalize(statement);
    return sequence;
}

static const char *str_field(cJSON *object, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(item) ? item->valuestring : "";
}

static int int_field(cJSON *object, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsNumber(item) ? item->valueint : 0;
}

static double double_field(cJSON *object, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsNumber(item) ? item->valuedouble : 0.0;
}

static void utc_now(char output[32])
{
    time_t now = time(NULL);
    struct tm tm_now;

    gmtime_r(&now, &tm_now);
    strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &tm_now);
}

static int valid_length(const char *text, size_t maximum)
{
    return text && strlen(text) <= maximum;
}

static int parse_cidr(const char *text,
                      struct sockaddr_storage *network,
                      int *prefix_length)
{
    char buffer[INET6_ADDRSTRLEN + 8];
    char *slash;
    int family;
    int max_prefix;

    if (!text || strlen(text) >= sizeof(buffer))
        return 0;

    strcpy(buffer, text);

    slash = strchr(buffer, '/');
    if (!slash)
        return 0;

    *slash = '\0';
    slash++;

    char *end = NULL;
    long prefix = strtol(slash, &end, 10);

    if (*slash == '\0' || *end != '\0')
        return 0;

    struct sockaddr_in *ipv4 =
        (struct sockaddr_in *)network;
    struct sockaddr_in6 *ipv6 =
        (struct sockaddr_in6 *)network;

    memset(network, 0, sizeof(*network));

    if (inet_pton(AF_INET, buffer, &ipv4->sin_addr) == 1) {
        family = AF_INET;
        max_prefix = 32;
        ipv4->sin_family = AF_INET;
    } else if (inet_pton(AF_INET6, buffer, &ipv6->sin6_addr) == 1) {
        family = AF_INET6;
        max_prefix = 128;
        ipv6->sin6_family = AF_INET6;
    } else {
        return 0;
    }

    if (prefix < 0 || prefix > max_prefix)
        return 0;

    *prefix_length = (int)prefix;
    (void)family;
    return 1;
}

static int normalize_cidr(const char *input,
                          char *output,
                          size_t output_size)
{
    struct sockaddr_storage network;
    int prefix_length;

    if (!input || !*input)
        return 0;

    /*
     * If the input already contains '/', retain it.
     */
    if (strchr(input, '/')) {
        if (strlen(input) >= output_size)
            return 0;

        strcpy(output, input);
    } else {
        /*
         * IPv6 addresses contain ':'; IPv4 addresses do not.
         */
        const char *suffix = strchr(input, ':') ? "/128" : "/32";

        if (snprintf(output, output_size, "%s%s", input, suffix)
            >= (int)output_size)
            return 0;
    }

    /*
     * Validate the normalized result.
     */
    if (!parse_cidr(output, &network, &prefix_length))
        return 0;

    return 1;
}

static int address_in_cidr(const char *address_text,
                           const char *cidr_text)
{
    struct sockaddr_storage network;
    struct sockaddr_storage address;
    int prefix_length;

    if (!parse_cidr(cidr_text, &network, &prefix_length))
        return 0;

    memset(&address, 0, sizeof(address));

    struct sockaddr_in *address4 =
        (struct sockaddr_in *)&address;
    struct sockaddr_in6 *address6 =
        (struct sockaddr_in6 *)&address;

    if (inet_pton(AF_INET, address_text,
                  &address4->sin_addr) == 1) {
        address4->sin_family = AF_INET;
    } else if (inet_pton(AF_INET6, address_text,
                         &address6->sin6_addr) == 1) {
        address6->sin6_family = AF_INET6;
    } else {
        return 0;
    }

    int network_family = network.ss_family;
    int address_family = address.ss_family;

    if (network_family != address_family)
        return 0;

    if (network_family == AF_INET) {
        uint32_t network_bits =
            ntohl(((struct sockaddr_in *)&network)->sin_addr.s_addr);
        uint32_t address_bits =
            ntohl(((struct sockaddr_in *)&address)->sin_addr.s_addr);

        if (prefix_length == 0)
            return 1;

        uint32_t mask = 0xffffffffu << (32 - prefix_length);
        return (network_bits & mask) == (address_bits & mask);
    }

    if (network_family == AF_INET6) {
        const unsigned char *network_bytes =
            ((struct sockaddr_in6 *)&network)->sin6_addr.s6_addr;
        const unsigned char *address_bytes =
            ((struct sockaddr_in6 *)&address)->sin6_addr.s6_addr;

        int whole_bytes = prefix_length / 8;
        int remaining_bits = prefix_length % 8;

        if (memcmp(network_bytes, address_bytes, whole_bytes) != 0)
            return 0;

        if (remaining_bits != 0) {
            unsigned char mask =
                (unsigned char)(0xff << (8 - remaining_bits));

            if ((network_bytes[whole_bytes] & mask) !=
                (address_bytes[whole_bytes] & mask))
                return 0;
        }

        return 1;
    }

    return 0;
}

static int insert_ticket(const char *body,
                         const char *source_ip,
                         char **ticket_number_out,
                         char **error_message)
{
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

    if (!*name ||
        !*problem ||
        (strcmp(severity, "Low") != 0 &&
         strcmp(severity, "High") != 0) ||
        !valid_length(name, 120) ||
        !valid_length(problem, 10000)) {
        *error_message = strdup("invalid name, severity, or problem");
        cJSON_Delete(json);
        return 0;
    }

    utc_now(received_at);
    utc_date(ticket_date);

    /*
     * A few retries handle two requests arriving simultaneously.
     * SQLite's UNIQUE constraint is the final authority.
     */
    for (int attempt = 0; attempt < 10; attempt++) {
        sequence = next_daily_sequence(ticket_date);

        if (sequence < 1) {
            *error_message = strdup("could not determine daily sequence");
            cJSON_Delete(json);
            return 0;
        }

        snprintf(ticket_number, sizeof(ticket_number),
                 "%s_%d", ticket_date, sequence);

        const char *sql =
            "INSERT INTO tickets ("
            "ticket_number,ticket_date,day_sequence,"
            "name,severity,problem,"
            "client_time_local,client_time_iso,"
            "client_timezone,client_timezone_offset_minutes,"
            "user_agent,language,screen_width,screen_height,pixel_ratio,"
            "cookie_string,source_ip,received_at"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        result = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

        if (result != SQLITE_OK) {
            *error_message = strdup(sqlite3_errmsg(db));
            cJSON_Delete(json);
            return 0;
        }

#define BIND_TEXT(index, value) \
        sqlite3_bind_text(statement, index, value ? value : "", \
                          -1, SQLITE_TRANSIENT)

        BIND_TEXT(1, ticket_number);
        BIND_TEXT(2, ticket_date);
        sqlite3_bind_int(statement, 3, sequence);
        BIND_TEXT(4, name);
        BIND_TEXT(5, severity);
        BIND_TEXT(6, problem);
        BIND_TEXT(7, str_field(json, "client_time_local"));
        BIND_TEXT(8, str_field(json, "client_time_iso"));
        BIND_TEXT(9, str_field(json, "client_timezone"));

        sqlite3_bind_int(
            statement, 10,
            int_field(json, "client_timezone_offset_minutes"));

        BIND_TEXT(11, str_field(json, "user_agent"));
        BIND_TEXT(12, str_field(json, "language"));

        cJSON *screen =
            cJSON_GetObjectItemCaseSensitive(json, "screen");

        sqlite3_bind_int(statement, 13, int_field(screen, "width"));
        sqlite3_bind_int(statement, 14, int_field(screen, "height"));
        sqlite3_bind_double(statement, 15,
                            double_field(screen, "pixel_ratio"));

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

        /*
         * Another writer may have taken this sequence number.
         * Retry by calculating the next sequence again.
         */
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

static enum MHD_Result request_handler(
    void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
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
        json_response(connection, MHD_HTTP_NOT_FOUND,
                      "{\"error\":\"not found\"}");
        free(upload->body);
        free(upload);
        *con_cls = NULL;
        return MHD_YES;
    }

    if (*upload_data_size > 0) {
        if (upload->length + *upload_data_size > MAX_BODY) {
            json_response(connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE,
                          "{\"error\":\"request too large\"}");
            free(upload->body);
            free(upload);
            *con_cls = NULL;
            return MHD_YES;
        }

        char *new_body = realloc(upload->body,
                                 upload->length + *upload_data_size + 1);
        if (!new_body)
            return MHD_NO;

        upload->body = new_body;
        memcpy(upload->body + upload->length,
               upload_data, *upload_data_size);

        upload->length += *upload_data_size;
        upload->body[upload->length] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    const union MHD_ConnectionInfo *info =
        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

    char source_ip[INET6_ADDRSTRLEN] = "unknown";

    if (info && info->client_addr) {
        const struct sockaddr *address = info->client_addr;

        if (address->sa_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
            inet_ntop(AF_INET, &ipv4->sin_addr,
                      source_ip, sizeof(source_ip));
        } else if (address->sa_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
            inet_ntop(AF_INET6, &ipv6->sin6_addr,
                      source_ip, sizeof(source_ip));
        }
    }

    char *ticket_number = NULL;
    char *error = NULL;

    if (!insert_ticket(upload->body ? upload->body : "",
                       source_ip,
                       &ticket_number,
                       &error)) {
        char response[512];

        snprintf(response, sizeof(response),
                 "{\"error\":\"%s\"}",
                 error ? error : "database error");

        json_response(connection, MHD_HTTP_BAD_REQUEST, response);
        free(error);
    } else {
        char response[256];

        snprintf(response, sizeof(response),
                 "{\"ok\":true,\"ticket_id\":\"%s\"}",
                 ticket_number);

        json_response(connection, MHD_HTTP_CREATED, response);
        free(ticket_number);
    }

    free(upload->body);
    free(upload);
    *con_cls = NULL;
    return MHD_YES;
}

static void list_tickets(const char *severity,
                         const char *from,
                         const char *to,
                         const char *ip_filter,
                         const char *completed)
{
    char normalized_cidr[INET6_ADDRSTRLEN + 8];

    if (ip_filter) {
        if (!normalize_cidr(ip_filter,
                            normalized_cidr,
                            sizeof(normalized_cidr))) {
            fprintf(stderr, "invalid IP address or CIDR range: %s\n",
                    ip_filter);
            return;
        }

        ip_filter = normalized_cidr;
    }

    char sql[2048] =
        "SELECT ticket_number, received_at, source_ip, severity,"
        "completed, name "
        "FROM tickets WHERE 1=1";

    sqlite3_stmt *statement = NULL;
    int parameter = 1;

    if (severity)  strcat(sql, " AND severity = ?");
    if (from)      strcat(sql, " AND received_at >= ?");
    if (to)        strcat(sql, " AND received_at <= ?");
    if (completed) strcat(sql, " AND completed = ?");

    strcat(sql, " ORDER BY received_at DESC;");

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        die(sqlite3_errmsg(db));

    if (severity)
        sqlite3_bind_text(statement, parameter++, severity, -1,
                          SQLITE_TRANSIENT);

    if (from)
        sqlite3_bind_text(statement, parameter++, from, -1,
                          SQLITE_TRANSIENT);

    if (to)
        sqlite3_bind_text(statement, parameter++, to, -1,
                          SQLITE_TRANSIENT);

    if (completed)
        sqlite3_bind_int(statement, parameter++, atoi(completed));

    printf("%-16s %-20s %-39s %-8s %-5s %s\n",
           "TICKET", "RECEIVED", "IP", "SEVERITY", "DONE", "NAME");

    while (sqlite3_step(statement) == SQLITE_ROW) {
        const char *ticket = (const char *)sqlite3_column_text(statement, 0);
        const char *received = (const char *)sqlite3_column_text(statement, 1);
        const char *source_ip = (const char *)sqlite3_column_text(statement, 2);
        const char *severity_value =
            (const char *)sqlite3_column_text(statement, 3);
        int done = sqlite3_column_int(statement, 4);
        const char *name = (const char *)sqlite3_column_text(statement, 5);

        if (ip_filter && !address_in_cidr(source_ip, ip_filter))
            continue;

        printf("%-16s %-20s %-39s %-8s %-5s %s\n",
               ticket,
               received,
               source_ip,
               severity_value,
               done ? "yes" : "no",
               name);
    }

    sqlite3_finalize(statement);
}

static void show_ticket(const char *ticket_number)
{
    const char *sql =
        "SELECT ticket_number, received_at, source_ip, completed,"
        "name, severity, problem,"
        "client_time_local, client_time_iso, client_timezone,"
        "client_timezone_offset_minutes, user_agent, language,"
        "screen_width, screen_height, pixel_ratio, cookie_string "
        "FROM tickets WHERE ticket_number = ?";

    sqlite3_stmt *statement = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        die(sqlite3_errmsg(db));

    sqlite3_bind_text(statement, 1, ticket_number, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(statement) != SQLITE_ROW) {
        fprintf(stderr, "ticket not found: %s\n", ticket_number);
        sqlite3_finalize(statement);
        return;
    }

#define TEXT_COLUMN(index) \
    ((const char *)sqlite3_column_text(statement, index))

    printf("Ticket:             %s\n", TEXT_COLUMN(0));
    printf("Received:           %s\n", TEXT_COLUMN(1));
    printf("Source IP:          %s\n", TEXT_COLUMN(2));
    printf("Completed:          %s\n",
           sqlite3_column_int(statement, 3) ? "yes" : "no");
    printf("Name:               %s\n", TEXT_COLUMN(4));
    printf("Severity:           %s\n", TEXT_COLUMN(5));

    printf("\nProblem:\n%s\n", TEXT_COLUMN(6));

    printf("\nClient information:\n");
    printf("  Local time:       %s\n", TEXT_COLUMN(7));
    printf("  ISO time:         %s\n", TEXT_COLUMN(8));
    printf("  Time zone:        %s\n", TEXT_COLUMN(9));
    printf("  UTC offset:       %d minutes\n",
           sqlite3_column_int(statement, 10));
    printf("  User agent:       %s\n", TEXT_COLUMN(11));
    printf("  Language:         %s\n", TEXT_COLUMN(12));
    printf("  Screen:           %dx%d\n",
           sqlite3_column_int(statement, 13),
           sqlite3_column_int(statement, 14));
    printf("  Pixel ratio:      %.2f\n",
           sqlite3_column_double(statement, 15));

    printf("\nCookie string:\n%s\n", TEXT_COLUMN(16));

#undef TEXT_COLUMN

    sqlite3_finalize(statement);
}

static void complete_ticket(const char *ticket_number)
{
    sqlite3_stmt *statement = NULL;

    const char *sql =
        "UPDATE tickets SET completed=1 "
        "WHERE ticket_number=?";

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        die(sqlite3_errmsg(db));

    sqlite3_bind_text(statement, 1, ticket_number, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(statement) != SQLITE_DONE)
        die(sqlite3_errmsg(db));

    if (sqlite3_changes(db) == 0)
        fprintf(stderr, "ticket not found: %s\n", ticket_number);
    else
        printf("marked ticket %s complete\n", ticket_number);

    sqlite3_finalize(statement);
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s serve [port]\n"
        "  %s show TICKET_NUMBER\n"
        "  %s list [options]\n"
        "  %s complete TICKET_NUMBER\n"
        "\n"
        "List options:\n"
        "  --severity Low|High\n"
        "  --from ISO_TIMESTAMP\n"
        "  --to ISO_TIMESTAMP\n"
        "  --ip ADDRESS</range>\n"
        "  --completed 0|1\n",
        program, program, program, program);

    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    init_db();

    if (argc >= 2 && strcmp(argv[1], "serve") == 0) {
        unsigned short port = argc >= 3 ? (unsigned short)atoi(argv[2]) : PORT;

        struct MHD_Daemon *daemon =
            MHD_start_daemon(
                MHD_USE_INTERNAL_POLLING_THREAD,
                port,
                NULL, NULL,
                &request_handler, NULL,
                MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
                MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                    (size_t)MAX_BODY + 4096,
                MHD_OPTION_END);

        if (!daemon)
            die("could not start HTTP server");

        printf("listening on http://127.0.0.1:%u\n", port);
        printf("press Ctrl-C to stop\n");

        for (;;)
            pause();

        MHD_stop_daemon(daemon);
    } else if (argc >= 2 && strcmp(argv[1], "complete") == 0) {
        if (argc != 3)
            usage(argv[0]);

        complete_ticket(argv[2]);
    } else if (argc >= 2 && strcmp(argv[1], "list") == 0) {
        const char *severity = NULL;
        const char *from = NULL;
        const char *to = NULL;
        const char *ip_filter = NULL;
        const char *completed = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--severity") == 0 && i + 1 < argc)
                severity = argv[++i];
            else if (strcmp(argv[i], "--from") == 0 && i + 1 < argc)
                from = argv[++i];
            else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc)
                to = argv[++i];
            else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
                ip_filter = argv[++i];
            else if (strcmp(argv[i], "--completed") == 0 && i + 1 < argc)
                completed = argv[++i];
            else
                usage(argv[0]);
        }

        list_tickets(severity, from, to, ip_filter, completed);
    } else if (argc >= 2 && strcmp(argv[1], "show") == 0) {
        if (argc != 3)
            usage(argv[0]);

        show_ticket(argv[2]);

    } else {
        usage(argv[0]);
    }

    sqlite3_close(db);
    return 0;
}
