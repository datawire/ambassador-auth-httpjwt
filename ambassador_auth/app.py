# Copyright 2018 Datawire Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base64 import b64encode
from flask import Flask, request, Response
from functools import wraps
from pathlib import Path
from hashlib import sha256
from werkzeug.routing import Rule

import bcrypt
import jwt
import logging
import os
import re
import threading
import yaml


app = Flask(__name__)

# Specify the /extauth route here because Flask requires manual specification of all the HTTP methods on the @app.route
# decorator which is tedious and prone to break in practice from new or custom HTTP methods being introduced.
app.url_map.add(Rule("/extauth", strict_slashes=False, endpoint="handle_authorization", defaults={"path": ""}))
app.url_map.add(Rule("/extauth/<path:path>", endpoint="handle_authorization"))

config_file = Path(os.getenv("AMBASSADOR_AUTH_CONFIG_FILE", "/var/lib/ambassador/auth-httpjwt/config.yaml"))
config = {}
users_last_modified_time = 0


def load_config():
    global users, users_last_modified_time

    try:
        modified_time = os.stat(str(config_file), follow_symlinks=True).st_mtime_ns
        if modified_time > users_last_modified_time:
            app.logger.info("Started loading config file from filesystem")
            modified_users = yaml.load(config_file.read_text(encoding="UTF-8"))

            users = modified_users
            users_last_modified_time = modified_time

            app.logger.info("Completed loading config file from filesystem")
        else:
            app.logger.debug(
                "Skipped loading config file from filesystem because modified time is same (old: %s, latest: %s)",
                users_last_modified_time, modified_time)
    except FileNotFoundError:
        app.logger.exception("Failed loading config file because the file was not found: %s", config_file)
    except yaml.YAMLError as e:
        app.logger.exception("Failed loading config file because the YAML is invalid")

    th = threading.Timer(5.0, load_config)
    th.daemon = True
    th.start()


load_config()


def check_auth(username, password):
    user_data = users.get(username, None)
    if user_data:
        # Passwords in the users database are stored as base64 encoded sha256 to work around the fact bcrypt only
        # supports a maximum password length of 72 characters (yes that is very long). See the below link for more
        # detail.
        #
        # see "Maximum Password Length" -> https://pypi.python.org/pypi/bcrypt/3.1.0
        prepared_password = b64encode(sha256(password.encode("UTF-8")).digest())
        return bcrypt.checkpw(prepared_password, user_data.get("hashed_password", "").encode("UTF-8"))
    else:
        return False


def unauthorized():
    return Response(status=401)


def parse_token_from_authorization_header(value):
    try:
        (auth_type, auth_value) = re.split("\s+", value.strip())
        if auth_type.lower() == "bearer":
            return auth_value
        else:
            return None
    except ValueError:
        return None


def get_encoded_token():

    """Tokens are generally sent in HTTP 'Authorization' header but sometimes developers like to send them in cookies so
    we check for both.

    :return: the encoded JSON Web Token
    """

    token = None

    if "authorization" in request.headers:
        token = parse_token_from_authorization_header(request.headers["authorization"])
    elif "jwt" in request.cookies:
        token = request.cookies["jwt"]

    return token


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Favicon is the little icon associated with a domain in a web browser. Browsers issue a request for the
        # resource /favicon.ico alongside any other HTTP request which pollutes the logs with lots of 404 Not Found logs
        # because usually the favicon cannot be resolved. This tells the browser to go away; there is no favicon here.
        if request.path == "/favicon.ico":
            return Response(status=403)

        verified = False
        encoded_token = get_encoded_token()

        try:
            token = jwt.decode(encoded_token, config["key"], [config["algorithm"]])

        except jwt.ExpiredSignatureError:
            app.logger.exception("Token is expired!")

        if not verified:
            return unauthorized()

        return f(*args, **kwargs)

    return decorated


@app.errorhandler(404)
def not_found(e):
    return Response(status=404)


@app.route("/readyz", methods=["GET"])
def readyz():
    return "OK", 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return "OK", 200


@app.endpoint("handle_authorization")
@requires_auth
def handle_authorization(path):
    return Response(status=200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
