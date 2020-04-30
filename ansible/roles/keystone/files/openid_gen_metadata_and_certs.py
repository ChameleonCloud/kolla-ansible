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

# This module creates a list of cron intervals for a node in a group of nodes
# to ensure each node runs a cron in round robbin style.

import json
import re
import requests
import sys

if sys.version_info[0] < 3:
    from urllib import quote_plus
else:
    from urllib.parse import quote_plus


def main(argv):
    posargs = iter(argv)

    idp_url = next(posargs)
    client_id = next(posargs)
    client_secret = next(posargs)
    certificate = next(posargs, None)
    key_id = next(posargs, None)
    certificate_transformer = next(posargs, None)
    key_transformer = next(posargs, None)

    file_name = quote_plus(re.sub("https?://", "", idp_url))
    json_provider_url = idp_url + '/.well-known/openid-configuration'

    json_provider = json.dumps(requests.get(json_provider_url).json())
    # This variable is an empty json because we are not overriding any configuration
    # and the apache2 OIDC plugin needs an existing config file with a valid json,
    # even if this JSON is an empty one.
    json_conf = {}
    json_client = json.dumps({'client_id': client_id, 'client_secret': client_secret})

    if key_id and certificate:
        key_id = get_value_by_url(key_id)
        if key_transformer:
            key_id = eval(key_transformer)
        certificate = get_value_by_url(certificate)
        if certificate_transformer:
            certificate = eval(certificate_transformer)
    elif not (key_id or certificate):
        jwks_uri = json_provider.get("jwks_uri")
        if jwks_uri:
            key_id, certificate = fetch_jkws_key(jwks_uri)
    else
        raise ValueError(
            "Either both a key_id and a certificate must be specified, or else "
            "neither, in which case the values are automatically inferred from "
            "the IdP well-known metadata URL.")

    create_file("metadata", file_name, "provider", json_provider)
    create_file("metadata", file_name, "client", json_client)
    create_file("metadata", file_name, "conf", json_conf)

    if key_id and certificate:
        create_file("cert", key_id, "pem", certificate)
        print(key_id)


def fetch_jkws_key(jwks_uri):
    certs = json.dumps(requests.get(jwks_uri))
    keys = certs.get("keys")

    if not keys:
        return None, None

    return keys[0]["kid"], keys[0]["x5c"][0]


def create_file(file_path, file_name, extension, content):
    path = "%s/%s.%s" % (file_path, file_name, extension)
    with open(path, "w") as file:
        file.write(str(content))


def get_value_by_url(url):
    if 'http' in url:
        return requests.get(url)._content.decode("utf-8")
    if 'file' in url:
        with open(url.replace("file://",""), "r") as file:
            return file.read().decode("utf-8")

    return url


if __name__ == "__main__":
    main(sys.argv[1:])
