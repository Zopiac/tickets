Preface: Feel free to flame me for the awful software that this probably is. At least this readme had no clanker input, outside the provided compiler commands.


**THE SOFTWARE:**

Compile the main program with:
```cc -std=c11 -Wall -Wextra -O2 tickets.c -lmicrohttpd -lsqlite3 -lcjson -o tickets```

This includes the main server (`tickets serve`) as well as basic browsing functions (`tickets list` and `tickets show <ticket#>`), and even marking of tickets as complete (`tickets complete <ticket#>`). Also provided is a leaner version without the extra functions.

And the ncurses interface with:
```cc -Wall -Wextra -O2 -o ntickets ntickets.c $(pkg-config --cflags --libs sqlite3 ncurses)```

...which provides a TUI interface for the `tickets list|show|complete` functions, with sorting and a few filters. 


**THE PROCESS:**

The "version 1.0" code was completed in two hours, using the Luna model that duck.ai defaulted to, with another few for the ncurses ticket browser. Each component (server+cli browser, webpage, and ncurses browser) fit within one provided session/content window.

There are certainly changes to be made, such as having separate title/body instead of singular "problem" field and removing superfluous timezone offset, cookie string, and pixel ratio fields.
