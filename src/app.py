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
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__, static_folder='../static')

useragent = 'SearchFilters (tools.search-filters@tools.wmflabs.org; https://meta.wikimedia.org/wiki/User:Abusefilter_global_search_service_account)'

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Abusefilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wiki = db.Column(db.String(255))
    wiki_url = db.Column(db.String(255))
    filter_id = db.Column(db.Integer)
    description = db.Column(db.String(255))
    enabled = db.Column(db.Boolean)
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    private = db.Column(db.Boolean)
    pattern = db.Column(db.Text)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    # if this is set to true by a tool maintainer, it lets the person in,
    # even if they don't have the rights
    is_manually_authorized = db.Column(db.Boolean, default=False, nullable=False)

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
)
app.register_blueprint(mwoauth.bp)

def logged():
    return mwoauth.get_current_user() is not None

def mw_request(data, url=None, service=False):
    if url is None:
        api_url = mwoauth.api_url
    else:
        api_url = url
    if service:
        auth = OAuth1(
            app.config.get('SERVICE_ACCOUNT_CONSUMER_TOKEN'),
            app.config.get('SERVICE_ACCOUNT_CONSUMER_SECRET'),
            app.config.get('SERVICE_ACCOUNT_ACCESS_TOKEN'),
            app.config.get('SERVICE_ACCOUNT_ACCESS_SECRET')
        )
    else:
        access_token = session.get('mwoauth_access_token', {})
        request_token_secret = access_token.get('secret').decode('utf-8')
        request_token_key = access_token.get('key').decode('utf-8')
        auth = OAuth1(app.config.get('CONSUMER_KEY'), app.config.get('CONSUMER_SECRET'), request_token_key, request_token_secret)
    data['format'] = 'json'
    return requests.post(api_url, data=data, auth=auth, headers={'User-Agent': useragent})

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user()
    }

def get_user():
    if not logged():
        return None

    user = User.query.filter_by(username=mwoauth.get_current_user()).first()
    if user is None:
        user = User(username=mwoauth.get_current_user())
        db.session.add(user)
        db.session.commit()
    return user

@app.before_request
def check_permissions():
    if request.path.startswith('/login') or request.path.startswith('/oauth-callback'):
        return

    if not logged():
        return render_template('login.html')

    if get_user().is_manually_authorized:
        return # Do not check permissions if user is manually authorized

    data = mw_request({
        "action": "query",
        "format": "json",
        "meta": "globaluserinfo",
        "guiprop": "rights"
    }).json()
    rights = data.get('query', {}).get('globaluserinfo', {}).get('rights', [])

    if 'abusefilter-view' not in rights or 'abusefilter-view-private' not in rights:
        return render_template('permission_denied.html')

def service_account_autocreate(api_url):
    s = requests.Session()
    r = s.post(api_url, {
        'action': 'query',
        'format': 'json',
        'meta': 'tokens',
        'type': 'login'
    })
    data = r.json()
    token = data.get('query').get('tokens').get('logintoken')
    # TODO: Make this not abuse action=login - for some reason, using botpasswords can't be used to autocreate the account,
    # while login w/o passed 2FA can.
    r = s.post(api_url, {
        'action': 'login',
        'format': 'json',
        'lgname': app.config.get('SERVICE_ACCOUNT_NAME'),
        'lgpassword': app.config.get('SERVICE_ACCOUNT_PASS'),
        'lgtoken': token
    })

def fetch_filters_raw(api_url):
    return mw_request({
        "action": "query",
        "format": "json",
        "list": "abusefilters",
        "abflimit": "max",
        "abfprop": "id|status|private|pattern|description"
    }, api_url, True).json()

@app.cli.command('collect-filters')
def cli_collect_filters():
    # Truncate table
    db.session.query(Abusefilter).delete()
    db.session.commit()

    data = mw_request({
        "action": "sitematrix",
        "format": "json"
    }, None, True).json()
    wikis = data.get('sitematrix', {})
    if 'count' in wikis:
        del wikis['count']

    for key in wikis:
        try:
            sites = wikis.get(key, {}).get('site', [])
        except:
            sites = wikis.get(key, [])
        for site in sites:
            if 'private' in site:
                continue
            if 'closed' in site:
                continue
            api_url = site['url'] + '/w/api.php'
            data = fetch_filters_raw(api_url)
            if data.get('error', {}).get('code') == 'mwoauth-invalid-authorization-invalid-user':
                print('Autocreating %s account' % site['url'])
                service_account_autocreate(api_url)
                data = fetch_filters_raw(api_url)
            filters = data.get('query', {}).get('abusefilters', [])

            for filter in filters:
                af = Abusefilter(
                    wiki=site["dbname"],
                    wiki_url=site["url"],
                    filter_id=int(filter["id"]),
                    description=filter['description'],
                    enabled="enabled" in filter,
                    deleted="deleted" in filter,
                    private="private" in filter,
                    pattern=filter["pattern"]
                )
                db.session.add(af)
                db.session.commit()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')

    type = request.form.get('type')
    case = request.form.get('case')
    result = {}
    filters = []
    if type == 'normal' and case == 'sensitive':
        filters = Abusefilter.query.filter(Abusefilter.pattern.like("%%%s%%" % request.form.get('query'))).all()
    elif type == 'normal' and case == 'insensitive':
        filters = Abusefilter.query.filter(Abusefilter.pattern.ilike("%{query}%".format(query=request.form.get('query')))).all()
    for f in filters:
        if f.wiki not in result:
            result[f.wiki] = []

        result[f.wiki].append({
            'id': f.filter_id,
            'wiki_url': f.wiki_url,
            'description': f.description,
            'enabled': f.enabled,
            'private': f.private,
        })

    return render_template('result.html', data=result)

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
