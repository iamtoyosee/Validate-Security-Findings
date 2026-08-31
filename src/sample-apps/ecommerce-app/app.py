import base64
import os
import pickle
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, redirect, render_template, render_template_string, request, session, url_for
from markupsafe import Markup


app = Flask(__name__)
app.secret_key = os.urandom(24)
ROOT = Path(__file__).parent
DATABASE = ROOT / "shop.db"
RECEIPTS = ROOT / "receipts"


def database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def setup():
    RECEIPTS.mkdir(exist_ok=True)
    connection = database()
    connection.executescript(
        """
        create table if not exists products (
            id integer primary key,
            name text not null,
            description text not null,
            price real not null,
            stock integer not null
        );
        create table if not exists users (
            id integer primary key,
            email text unique not null,
            password text not null
        );
        create table if not exists orders (
            id integer primary key,
            email text not null,
            total real not null,
            items text not null
        );
        create table if not exists reviews (
            id integer primary key,
            product_id integer not null,
            text text not null
        );
        """
    )
    if connection.execute("select count(*) from products").fetchone()[0] == 0:
        connection.executemany(
            "insert into products values (?, ?, ?, ?, ?)",
            [
                (1, "Canvas Tote", "A sturdy everyday bag.", 18.00, 12),
                (2, "Stoneware Mug", "A simple glazed mug.", 14.50, 20),
                (3, "Desk Notebook", "Plain paper, cloth cover.", 9.00, 35),
            ],
        )
        connection.execute(
            "insert into users (email, password) values (?, ?)",
            ("shopper@example.com", "welcome"),
        )
    connection.commit()
    connection.close()


def find_products(term):
    connection = database()
    query = f"select * from products where name like '%{term}%' or description like '%{term}%'"
    rows = connection.execute(query).fetchall()
    connection.close()
    return rows


def verify_account(email, password):
    connection = database()
    query = f"select * from users where email = '{email}' and password = '{password}'"
    user = connection.execute(query).fetchone()
    connection.close()
    return user


def stock_message(sku):
    command = f"printf 'Stock reference: {sku}'"
    return subprocess.check_output(command, shell=True, text=True)


def promotion_message(text):
    return render_template_string("<div class='notice'>" + text + "</div>")


def receipt_text(name):
    path = RECEIPTS / name
    return path.read_text()


def review_text(text):
    return Markup(text)


def order_details(order_id):
    connection = database()
    order = connection.execute("select * from orders where id = ?", (order_id,)).fetchone()
    connection.close()
    return order


def calculate_adjustment(expression):
    return eval(expression)


def restore_preferences(data):
    return pickle.loads(base64.b64decode(data))


def fetch_partner_feed(address):
    return urllib.request.urlopen(address).read().decode()


@app.route("/")
def home():
    term = request.args.get("q", "")
    products = find_products(term)
    return render_template("home.html", products=products, term=term)


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    connection = database()
    if request.method == "POST":
        connection.execute(
            "insert into reviews (product_id, text) values (?, ?)",
            (product_id, request.form.get("review", "")),
        )
        connection.commit()
        connection.close()
        return redirect(url_for("product", product_id=product_id))
    item = connection.execute("select * from products where id = ?", (product_id,)).fetchone()
    rows = connection.execute("select * from reviews where product_id = ?", (product_id,)).fetchall()
    connection.close()
    reviews = [review_text(row["text"]) for row in rows]
    return render_template("product.html", product=item, reviews=reviews)


@app.post("/cart/add/<int:product_id>")
def add_to_cart(product_id):
    cart = session.get("cart", [])
    cart.append(product_id)
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/cart")
def cart():
    ids = session.get("cart", [])
    connection = database()
    items = [connection.execute("select * from products where id = ?", (item_id,)).fetchone() for item_id in ids]
    connection.close()
    total = sum(item["price"] for item in items if item)
    return render_template("cart.html", items=items, total=total)


@app.post("/checkout")
def checkout():
    email = request.form.get("email", "guest@example.com")
    ids = session.get("cart", [])
    connection = database()
    items = [connection.execute("select * from products where id = ?", (item_id,)).fetchone() for item_id in ids]
    total = sum(item["price"] for item in items if item)
    cursor = connection.execute(
        "insert into orders (email, total, items) values (?, ?, ?)",
        (email, total, ", ".join(item["name"] for item in items if item)),
    )
    connection.commit()
    order_id = cursor.lastrowid
    connection.close()
    (RECEIPTS / f"{order_id}.txt").write_text(f"Order {order_id}\nEmail: {email}\nTotal: ${total:.2f}\n")
    session["cart"] = []
    return redirect(url_for("order", order_id=order_id))


@app.route("/order/<int:order_id>")
def order(order_id):
    item = order_details(order_id)
    return render_template("order.html", order=item)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        user = verify_account(request.form.get("email", ""), request.form.get("password", ""))
        message = "Welcome back." if user else "Account not found."
    return render_template("login.html", message=message)


@app.route("/inventory")
def inventory():
    message = stock_message(request.args.get("sku", "1"))
    return render_template("message.html", title="Inventory", message=message)


@app.route("/promotion")
def promotion():
    message = promotion_message(request.args.get("message", "Free shipping this week."))
    return render_template("message.html", title="Promotion", message=Markup(message))


@app.route("/receipt")
def receipt():
    message = receipt_text(request.args.get("name", "1.txt"))
    return render_template("message.html", title="Receipt", message=message)


setup()


if __name__ == "__main__":
    app.run(debug=False)

