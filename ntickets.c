//#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#define REFRESH_INTERVAL_SECONDS 10

#include <ncurses.h>
#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <regex.h>
#include <ctype.h>

#include <time.h>

typedef enum {
    FILTER_OPEN,
    FILTER_CLOSED,
    FILTER_ALL
} Filter;

typedef struct {
    sqlite3_int64 id;
    char *name;
    char *ticket_date;
    char *client_time_local;
    char *ticket_number;
    char *severity;
    char *source_ip;
    int completed;
    char *problem;
} Ticket;

typedef struct {
    sqlite3_int64 id;
    const char *name;
    const char *value;
} DetailField;

typedef enum {
    SORT_NAME,
    SORT_TIME,
    SORT_TICKET_NUMBER,
    SORT_SEVERITY,
    SORT_IP,
    SORT_STATUS,
    SORT_PROBLEM
} SortColumn;

static SortColumn sort_column = SORT_TICKET_NUMBER;
static int sort_descending = 1;

static sqlite3 *db;
static Filter current_filter = FILTER_OPEN;

static Ticket *tickets;
static int ticket_count;
static int selected_ticket;

/* Forward declarations */
static const char *filter_name(void);
static const char *sort_name(void);
static const char *sort_sql(void);
static void free_tickets(void);
static int load_tickets(void);

static const char *sort_sql(void) {
    switch (sort_column) {
    case SORT_NAME:
        return "name COLLATE NOCASE";

    case SORT_TIME:
        return "substr(client_time_local, 17, 8)";

    case SORT_TICKET_NUMBER:
        return "ticket_number";

    case SORT_SEVERITY:
        return "severity COLLATE NOCASE";

    case SORT_IP:
        return "source_ip COLLATE NOCASE";

    case SORT_STATUS:
        return "completed";

    case SORT_PROBLEM:
        return "problem";

    default:
        return "ticket_date";
    }
}

static const char *sort_name(void) {
    switch (sort_column) {
    case SORT_NAME:
        return "Name";
    case SORT_TIME:
        return "Time";
    case SORT_TICKET_NUMBER:
        return "Ticket number";
    case SORT_SEVERITY:
        return "Severity";
    case SORT_IP:
        return "IP";
    case SORT_STATUS:
        return "Status";
    case SORT_PROBLEM:
        return "Status";
    }

    return "";
}

static char *copy_sql_text(sqlite3_stmt *stmt, int column) {
    const unsigned char *text = sqlite3_column_text(stmt, column);

    if (!text)
        return strdup("");

    return strdup((const char *)text);
}

static void short_local_time(
    const char *client_time_local,
    char output[9]) {
    /*
     * Expected format:
     * Tue Sep 22 2026 06:38:02 GMT-0400 (...)
     * The time starts at offset 16.
     */
    if (client_time_local &&
        strlen(client_time_local) >= 24 &&
        client_time_local[16] >= '0' &&
        client_time_local[16] <= '9' &&
        client_time_local[18] == ':' &&
        client_time_local[21] == ':') {
        memcpy(output, client_time_local + 16, 8);
        output[8] = '\0';
        return;
    }

    strcpy(output, "--:--:--");
}

static void free_tickets(void) {
    for (int i = 0; i < ticket_count; i++) {
        free(tickets[i].name);
        free(tickets[i].ticket_date);
	free(tickets[i].client_time_local);
        free(tickets[i].ticket_number);
        free(tickets[i].severity);
        free(tickets[i].source_ip);
        free(tickets[i].problem);
    }

    free(tickets);
    tickets = NULL;
    ticket_count = 0;
}

static int load_tickets(void) {
    const char *sql = "SELECT id, name, ticket_date, client_time_local, ticket_number, severity, source_ip, completed, problem FROM tickets ";

    if (current_filter == FILTER_OPEN)
        sql = "SELECT id, name, ticket_date, client_time_local, ticket_number, severity, source_ip, completed, problem FROM tickets WHERE completed = 0 ";

    else if (current_filter == FILTER_CLOSED)
        sql = "SELECT id, name, ticket_date, client_time_local, ticket_number, severity, source_ip, completed, problem FROM tickets WHERE completed = 1 ";

    char query[1024];

    snprintf(
        query,
        sizeof(query),
        "%s ORDER BY %s %s, id DESC",
        sql,
        sort_sql(),
        sort_descending ? "DESC" : "ASC"
    );

    char title[1024];

    snprintf(
        title,
	sizeof(title),
	" Ticket Viewer  - %s tickets (%d) - Sort: %s %s",
	filter_name(),
	ticket_count,
	sort_name(),
	sort_descending ? "descending" : "ascending"
    );

 
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    free_tickets();

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Ticket *new_tickets = realloc(tickets, sizeof(Ticket) * (size_t)(ticket_count + 1)
        );

        if (!new_tickets) {
            sqlite3_finalize(stmt);
            free_tickets();
            return 0;
        }

        tickets = new_tickets;

        Ticket *ticket = &tickets[ticket_count];

        ticket->id = sqlite3_column_int64(stmt, 0);
        ticket->name = copy_sql_text(stmt, 1);
        ticket->ticket_date = copy_sql_text(stmt, 2);
        ticket->client_time_local = copy_sql_text(stmt, 3);
        ticket->ticket_number = copy_sql_text(stmt, 4);
        ticket->severity = copy_sql_text(stmt, 5);
        ticket->source_ip = copy_sql_text(stmt, 6);
        ticket->completed = sqlite3_column_int(stmt, 7);
        ticket->problem = copy_sql_text(stmt, 8);

        ticket_count++;
    }

    sqlite3_finalize(stmt);

    if (ticket_count == 0)
        selected_ticket = 0;
    else if (selected_ticket >= ticket_count)
        selected_ticket = ticket_count - 1;

    return 1;
}

static void change_sort(int direction) {
    int column = (int)sort_column + direction;
    //lazy skip of status/problem columns
    if (column < 0)
        column = SORT_IP;

    if (column > SORT_IP)
        column = SORT_NAME;

    /* Moving to another column starts with ascending order.
     * Pressing the same direction again can still be used to
     * reverse the current column's direction.
     */
    if ((SortColumn)column == sort_column)
        sort_descending = !sort_descending;
    else {
        sort_column = (SortColumn)column;
        sort_descending = 0;
    }

    selected_ticket = 0;
    load_tickets();
}

static int toggle_completion(sqlite3_int64 id) {
    const char *sql =
        "UPDATE tickets "
        "SET completed = CASE completed WHEN 0 THEN 1 ELSE 0 END "
        "WHERE id = ?";

    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, id);

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return result == SQLITE_DONE;
}

static const char *filter_name(void) {
    switch (current_filter) {
    case FILTER_OPEN:
        return "OPEN";
    case FILTER_CLOSED:
        return "CLOSED";
    case FILTER_ALL:
        return "ALL";
    }

    return "";
}

static void draw_header(const char *title) {
    int width = COLS;

    attron(A_BOLD);
    mvprintw(0, 0, "%-*s", width, title);
    attroff(A_BOLD);

    mvhline(1, 0, ACS_HLINE, width);

    mvprintw(
        2,
        1,
        "up/dn: Select ticket | lt/rt: Select column | Enter: View | Space: Close | "
        "o/c/a: Open/Closed/All | r: Refresh | q: Quit"
    );

    mvhline(3, 0, ACS_HLINE, width);
}

static void draw_column_header(
    int row,
    int column,
    int width,
    const char *text,
    int selected) {
    if (selected)
        attron(A_REVERSE);

    attron(A_BOLD);

    mvprintw(
        row,
        column,
        "%-*s",
        width,
        text
    );

    attroff(A_BOLD);

    if (selected)
        attroff(A_REVERSE);
}

static void draw_list(void) {
    erase();

    char title[128];
    snprintf(
        title,
        sizeof(title),
        " Ticket Viewer - %s tickets (%d)",
        filter_name(),
        ticket_count
    );

    draw_header(title);

    int header_row = 4;
    int first_data_row = 5;
    int visible_rows = LINES - first_data_row - 1;

    if (visible_rows < 1)
        visible_rows = 1;

    int first_item = 0;
    
    draw_column_header(
        header_row,
        0,
        25,
        " Name/Location",
        sort_column == SORT_NAME
    );

    draw_column_header(
        header_row,
        25,
        10,
        "Time",
        sort_column == SORT_TIME
    );

    draw_column_header(
        header_row,
        35,
        15,
        "Ticket #",
        sort_column == SORT_TICKET_NUMBER
    );

    draw_column_header(
        header_row,
        50,
        6,
        "Sev.",
        sort_column == SORT_SEVERITY
    );

    draw_column_header(
        header_row,
        56,
        16,
        "IP address",
        sort_column == SORT_IP
    );

    draw_column_header(
        header_row,
        72,
        8,
        "Status",
        sort_column == SORT_STATUS
    );

    draw_column_header(
        header_row,
        80,
        40,
        "Problem",
        sort_column == SORT_PROBLEM
    );

    if (selected_ticket >= visible_rows)
        first_item = selected_ticket - visible_rows + 1;

    mvhline(header_row + 1, 0, ACS_HLINE, COLS);

    for (int row = 0; row < visible_rows; row++) {
        int index = first_item + row;

        if (index >= ticket_count)
            break;

        Ticket *ticket = &tickets[index];
        int screen_row = first_data_row + row;

        if (index == selected_ticket) {
            attron(A_REVERSE);
        }

        char name[26];
        char local_time[9];
        char number[15];
        char severity[7];
        char ip[16];
        char status[7];
        char problem[41];

        snprintf(name, sizeof(name), "%.25s", ticket->name);
        //snprintf(date, sizeof(date), "%.12s", ticket->ticket_date);
        short_local_time(ticket->client_time_local,local_time);
	snprintf(number, sizeof(number), "%.14s", ticket->ticket_number);
        snprintf(severity, sizeof(severity), "%.4s", ticket->severity);
        snprintf(ip, sizeof(ip), "%.15s", ticket->source_ip);
        snprintf(status, sizeof(status), "%.6s", ticket->completed ? "Closed" : "Open");
        snprintf(problem, sizeof(problem), "%.40s", ticket->problem);

        mvprintw(
            screen_row,
            0,
            " %-25s %-9s %-14s %-5s %-15s %-7s %-40s",
            name,
            local_time,
            number,
            severity,
            ip,
            status,
            problem
        );

        if (index == selected_ticket)
            attroff(A_REVERSE);
    }

    if (ticket_count == 0) {
        mvprintw(first_data_row + 1, 2, "No tickets found.");
    }

    refresh();
}

static char *database_value(sqlite3_stmt *stmt, int column) {
    const unsigned char *text = sqlite3_column_text(stmt, column);

    if (!text)
        return strdup("");

    return strdup((const char *)text);
}

static int load_ticket_details(
    sqlite3_int64 id,
    char ***names_out,
    char ***values_out,
    int *count_out) {
    const char *sql =
        "SELECT "
        "id, ticket_number, ticket_date, day_sequence, name, severity, "
        "problem, client_time_local, client_time_iso, client_timezone, "
        "client_timezone_offset_minutes, user_agent, language, "
        "screen_width, screen_height, pixel_ratio, cookie_string, "
        "source_ip, received_at, completed "
        "FROM tickets WHERE id = ?";

    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    static const char *field_names[] = {
        "id",
        "ticket_number",
        "ticket_date",
        "day_sequence",
        "name",
        "severity",
        "problem",
        "client_time_local",
        "client_time_iso",
        "client_timezone",
        "client_timezone_offset_minutes",
        "user_agent",
        "language",
        "screen_width",
        "screen_height",
        "pixel_ratio",
        "cookie_string",
        "source_ip",
        "received_at",
        "completed"
    };

    const int field_count = (int)(sizeof(field_names) / sizeof(field_names[0]));

    char **names = calloc((size_t)field_count, sizeof(char *));
    char **values = calloc((size_t)field_count, sizeof(char *));

    if (!names || !values) {
        free(names);
        free(values);
        sqlite3_finalize(stmt);
        return 0;
    }

    for (int i = 0; i < field_count; i++) {
        names[i] = strdup(field_names[i]);

        if (i == 0 || i == 3 ||
            i == 10 || i == 13 || i == 14 || i == 19) {
            char buffer[64];

            if (i == 0 || i == 3 || i == 10 ||
                i == 13 || i == 14 || i == 19) {
                snprintf(
                    buffer,
                    sizeof(buffer),
                    "%lld",
                    (long long)sqlite3_column_int64(stmt, i)
                );
            }

            values[i] = strdup(buffer);
        } else if (i == 15) {
            char buffer[64];

            snprintf(
                buffer,
                sizeof(buffer),
                "%g",
                sqlite3_column_double(stmt, i)
            );

            values[i] = strdup(buffer);
        } else
            values[i] = database_value(stmt, i);

        if (!names[i] || !values[i]) {
            for (int j = 0; j <= i; j++) {
                free(names[j]);
                free(values[j]);
            }

            free(names);
            free(values);
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    sqlite3_finalize(stmt);

    *names_out = names;
    *values_out = values;
    *count_out = field_count;

    return 1;
}

static void free_details(char **names, char **values, int count) {
    for (int i = 0; i < count; i++) {
        free(names[i]);
        free(values[i]);
    }

    free(names);
    free(values);
}

static void draw_detail(void) {
    erase();

    if (ticket_count == 0) {
        draw_header(" Ticket Details");
        mvprintw(5, 2, "No ticket selected.");
        refresh();
        return;
    }

    Ticket *ticket = &tickets[selected_ticket];

    char title[256];
    snprintf(
        title,
        sizeof(title),
        " Ticket Details - %s",
        ticket->ticket_number
    );

    draw_header(title);

    char **names = NULL;
    char **values = NULL;
    int count = 0;

    if (!load_ticket_details(
            ticket->id,
            &names,
            &values,
            &count)) {
        mvprintw(5, 2, "Unable to load ticket details.");
        refresh();
        return;
    }

    int row = 5;
    int max_value_width = COLS - 31;

    if (max_value_width < 10)
        max_value_width = 10;

    for (int i = 0; i < count && row < LINES - 1; i++) {
        mvprintw(row, 2, "%-30s", names[i]);

        // Long fields are wrapped manually.
        const char *value = values[i];
        int remaining = (int)strlen(value);

        if (remaining == 0) {
            mvprintw(row, 33, "(empty)");
            row++;
            continue;
        }

        int offset = 0;
        int first_line = 1;

        while (remaining > 0 && row < LINES - 1) {
            int amount = remaining;

            if (amount > max_value_width)
                amount = max_value_width;

            if (!first_line)
                mvprintw(row, 2, "%-30s", "");

            mvprintw(
                row,
                33,
                "%.*s",
                amount,
                value + offset
            );

            offset += amount;
            remaining -= amount;
            row++;
            first_line = 0;
        }
    }

    free_details(names, values, count);

    refresh();
}

static int initialize_database(const char *path) {
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "Unable to open database: %s\n",
                sqlite3_errmsg(db));
        return 0;
    }

    // To coexist cleanly with the writer.
    sqlite3_busy_timeout(db, 3000);

    return 1;
}

int main(int argc, char **argv) {
    const char *database_path = "tickets.db";

    if (argc >= 2)
        database_path = argv[1];

    if (!initialize_database(database_path))
        return EXIT_FAILURE;

    current_filter = FILTER_OPEN;

    if (!load_tickets()) {
        fprintf(stderr, "Unable to load tickets: %s\n",
                sqlite3_errmsg(db));
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    
    setenv("ESCDELAY", "25", 1);
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);
        attron(COLOR_PAIR(1));
    }

    int detail_view = 0;
    int running = 1;

    while (running) {
        if (detail_view)
            draw_detail();
        else
            draw_list();

        int key = getch();

        if (detail_view) {
            if (key == 27 || key == KEY_BACKSPACE ||
                key == 127 || key == 8) {
                detail_view = 0;
                continue;
            }

            if (key == 'q' || key == 'Q') {
                running = 0;
                continue;
            }

            if (key == ' ') {
                Ticket *ticket = &tickets[selected_ticket];

                if (toggle_completion(ticket->id)) {
                    ticket->completed = !ticket->completed;

                    /*
                     * Reloading is important if the current filter is
                     * open-only or closed-only.
                     */
                    load_tickets();

                    if (ticket_count == 0)
                        detail_view = 0;
                }

                continue;
            }

            continue;
        }

        switch (key) {
        case KEY_UP:
        case 'k':
            if (selected_ticket > 0)
                selected_ticket--;
            break;

        case KEY_DOWN:
        case 'j':
            if (selected_ticket + 1 < ticket_count)
                selected_ticket++;
            break;

	case KEY_LEFT:
	    change_sort(-1);
	    break;

	case KEY_RIGHT:
	    change_sort(1);
            break;

	case 's':
        case 'S':
            sort_descending = !sort_descending;
            load_tickets();
            break;

        case '\n':
        case KEY_ENTER:
            if (ticket_count > 0)
                detail_view = 1;
            break;

        case 'r':
        case 'R':
            load_tickets();
            break;

        case ' ':
            if (ticket_count > 0) {
                Ticket *ticket = &tickets[selected_ticket];

                if (toggle_completion(ticket->id)) {
                    ticket->completed = !ticket->completed;
                    load_tickets();
                }
            }
            break;

        case 'o':
        case 'O':
            current_filter = FILTER_OPEN;
            selected_ticket = 0;
            load_tickets();
            break;

        case 'c':
        case 'C':
            current_filter = FILTER_CLOSED;
            selected_ticket = 0;
            load_tickets();
            break;

        case 'a':
        case 'A':
            current_filter = FILTER_ALL;
            selected_ticket = 0;
            load_tickets();
            break;

        case KEY_RESIZE:
            clear();
            break;

        case 'q':
        case 'Q':
            running = 0;
            break;
        }
    }

    endwin();

    free_tickets();
    sqlite3_close(db);

    return EXIT_SUCCESS;
}

