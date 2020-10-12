# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import yaml
from flask import redirect, request, jsonify, render_template, url_for, \
    make_response, session
from flask import Flask
import requests
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from requests_oauthlib import OAuth1

app = Flask(__name__, static_folder='../static')

useragent = 'SearchFilters (urbanecm@tools.wmflabs.org)'

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
)
app.register_blueprint(mwoauth.bp)

def logged():
    return mwoauth.get_current_user() is not None

def mw_request(data, url=None):
    if url is None:
        api_url = mwoauth.api_url
    else:
        api_url = url
    access_token = session.get('mwoauth_access_token', {})
    request_token_secret = access_token.get('secret').decode('utf-8')
    request_token_key = access_token.get('key').decode('utf-8')
    auth = OAuth1(app.config.get('CONSUMER_KEY'), app.config.get('CONSUMER_SECRET'), request_token_key, request_token_secret)
    data['format'] = 'json'
    return requests.post(api_url, data=data, auth=auth, headers={'User-Agent': useragent})

@app.before_request
def check_permissions():
    if not logged():
        return render_template('login.html')
    
    data = mw_request({
        "action": "query",
        "format": "json",
        "meta": "globaluserinfo",
        "guiprop": "rights"
    }).json()
    rights = data.get('query', {}).get('globaluserinfo', {}).get('rights', [])
    
    if 'abusefilter-view' not in rights or 'abusefilter-view-private' not in rights:
        return render_template('permission_denied.html')

def query_wiki(bare_url, pattern, type='normal'):
    api_url = bare_url + '/w/api.php'
    res = []
    data = mw_request({
        "action": "query",
        "format": "json",
        "list": "abusefilters",
        "abflimit": "max",
        "abfprop": "id|status|pattern|description"
    }, api_url).json()
    filters = data.get('query', {}).get('abusefilters', [])
    for filter in filters:
        if type == 'normal':
            found = pattern in filter['pattern']
        elif type == 'regex':
            found = pattern in filter['pattern'] # FIXME

        if found:    
            res.append({
                'id': filter['id'],
                'description': filter['description'],
                'enabled': 'enabled' in filter
            })
    return res

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
    
    print(request.form)

    data = mw_request({
        "action": "sitematrix",
        "format": "json"
    }).json()
    wikis = data.get('sitematrix', {})
    if 'count' in wikis:
        del wikis['count']
    
    result = {}
    for key in wikis:
        sites = wikis[key]['site']
        for site in sites:
            result[site["dbname"]] = query_wiki(site['url'], request.form.get('query'), request.form.get('type'))
    
    return render_template('result.html', data=result)

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
