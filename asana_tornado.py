#!/usr/bin/env python

class AsanaConnectMixin(OAuth2Mixin):
    """Asana Connect authentication using OAuth2."""
    _OAUTH_ACCESS_TOKEN_URL = "https://app.asana.com/-/oauth_token"
    _OAUTH_AUTHORIZE_URL = "https://app.asana.com/-/oauth_authorize"
    _OAUTH_NO_CALLBACKS = False
    _ASANA_BASE_URL = "https://app.asana.com/api/1.0/"

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback):
      http = self.get_auth_http_client()
      post_args = {
        "redirect_uri": redirect_uri,
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code"
        }

      http.fetch(self._oauth_request_token_url(),
                 self.async_callback(self._on_access_token, redirect_uri,
                 client_id, client_secret, callback),
                 body=urllib_parse.urlencode(post_args),
                 method="POST")

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         future, response):
      if response.error:
        future.set_exception(AuthError('Asana auth error: %s' % str(response)))
        return

      session = escape.json_decode(response.body)

      self.asana_request(
        path="users/me",
        callback=self.async_callback(self._on_get_user_info, future, session),
        access_token=session["access_token"])

    def _on_get_user_info(self, future, session, response):
      if response is None:
        future.set_result(None)
        return

      user = response.get('data')
      fieldmap = {}
      fields = ["id", "name", "email", "workspaces"]
      for field in fields:
        fieldmap[field] = user.get(field)
      fieldmap.update(session)
      future.set_result(fieldmap)

    @_auth_return_future
    def asana_request(self, path, callback, access_token=None,
                      post_args=None, **args):
      url = self._ASANA_BASE_URL + path
      headers = HTTPHeaders({"Authorization": "Bearer " + access_token})

      all_args = {}
      all_args.update(args)

      if all_args:
        url += "?" + urllib_parse.urlencode(all_args)
      callback = self.async_callback(self._on_asana_request, callback)
      http = self.get_auth_http_client()
      if post_args is not None:
        http.fetch(url, method="POST", headers=headers,
                   body=urllib_parse.urlencode(post_args),
                   callback=callback)
      else:
        http.fetch(url, callback=callback, headers=headers)

    def _on_asana_request(self, future, response):
      if response.error:
        future.set_exception(AuthError("Error response %s fetching %s" %
                                       (response.error, response.request.url)))
        return
      future.set_result(escape.json_decode(response.body))

    def get_auth_http_client(self):
      return httpclient.AsyncHTTPClient()


# Basic login handler for Tornado apps with authentication via Asana Connect
class AsanaLoginHandler(BaseHandler, tornado.auth.AsanaConnectMixin):
  @tornado.web.asynchronous
  @tornado.gen.coroutine
  def get(self):
    if self.get_argument("code", False):
      user = yield self.get_authenticated_user(
        redirect_uri='http://recruitana.com/auth/login',
        client_id=options["asana_client_id"],
        client_secret=options["asana_secret_key"],
        code=self.get_argument("code"))
       # Save the user with e.g. set_secure_cookie
      self.set_secure_cookie("asana_user", tornado.escape.json_encode(user))
      self.redirect(self.get_argument("next", "/workspace/set"))

    else:
      yield self.authorize_redirect(
        redirect_uri='http://recruitana.com/auth/login',
        client_id=options["asana_client_id"], client_secret=None,
        extra_params={"response_type": "code"})

# Basic logout handler for Tornado apps with authentication via Asana Connect
class AuthLogoutHandler(BaseHandler):
  def get(self):
    self.clear_cookie("asana_user")
    self.redirect(self.get_argument("next", "/"))



