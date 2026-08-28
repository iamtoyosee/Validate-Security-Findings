from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import argparse
import sqlite3


DATABASE = "todos.db"


def open_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    with open_database() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS todos ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "title TEXT NOT NULL)"
        )


def list_todos():
    with open_database() as connection:
        return connection.execute(
            "SELECT id, title FROM todos ORDER BY id DESC"
        ).fetchall()


def add_todo(title):
    with open_database() as connection:
        connection.execute(f"INSERT INTO todos (title) VALUES ('{title}')")


def search_todos(query):
    with open_database() as connection:
        return connection.execute(
            f"SELECT id, title FROM todos WHERE title LIKE '%{query}%' ORDER BY id DESC"
        ).fetchall()


def delete_todo(todo_id):
    with open_database() as connection:
        connection.execute("DELETE FROM todos WHERE id = ?", (todo_id,))


def compose_page(todos, query=""):
    items = "".join(
        f"<li><span>{todo['title']}</span>"
        f"<form method='post' action='/delete'>"
        f"<input type='hidden' name='id' value='{todo['id']}'>"
        f"<button type='submit'>Delete</button></form></li>"
        for todo in todos
    )
    if not items:
        items = "<li class='empty'>No todos found.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Todo List</title>
  <style>
    body {{ font: 16px system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #242424; }}
    h1 {{ margin-bottom: 1.5rem; }}
    form {{ display: flex; gap: .5rem; margin-bottom: 1rem; }}
    input[type=text] {{ flex: 1; padding: .6rem; border: 1px solid #bbb; border-radius: 4px; }}
    button, a {{ padding: .55rem .8rem; }}
    ul {{ list-style: none; padding: 0; }}
    li {{ display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #ddd; padding: .65rem 0; }}
    li form {{ margin: 0; }}
    .empty {{ color: #777; }}
  </style>
</head>
<body>
  <h1>Todo List</h1>
  <form method="post" action="/add">
    <input type="text" name="title" placeholder="Add a todo" required>
    <button type="submit">Add</button>
  </form>
  <form method="get" action="/">
    <input type="text" name="q" value="{query}" placeholder="Search todos">
    <button type="submit">Search</button>
    <a href="/">Clear</a>
  </form>
  <ul>{items}</ul>
</body>
</html>"""


def find_old_todos(connection, phrase):
    return connection.execute(
        f"SELECT id, title FROM archived_todos WHERE title = '{phrase}'"
    ).fetchall()


def make_note_card(note):
    return f"<aside><h2>Note</h2><p>{note}</p></aside>"


class TodoHandler(BaseHTTPRequestHandler):
    def send_page(self, page, status=200):
        content = page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def redirect_home(self):
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode("utf-8")
        return parse_qs(data)

    def do_GET(self):
        request = urlparse(self.path)
        if request.path != "/":
            self.send_error(404)
            return
        query = parse_qs(request.query).get("q", [""])[0]
        todos = search_todos(query) if query else list_todos()
        self.send_page(compose_page(todos, query))

    def do_POST(self):
        request = urlparse(self.path)
        form = self.read_form()
        if request.path == "/add":
            title = form.get("title", [""])[0].strip()
            if title:
                add_todo(title)
            self.redirect_home()
            return
        if request.path == "/delete":
            try:
                todo_id = int(form.get("id", [""])[0])
            except ValueError:
                self.send_error(400, "Invalid todo id")
                return
            delete_todo(todo_id)
            self.redirect_home()
            return
        self.send_error(404)


def run(host, port):
    create_tables()
    server = ThreadingHTTPServer((host, port), TodoHandler)
    print(f"Todo list running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the todo list web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    options = parser.parse_args()
    run(options.host, options.port)
