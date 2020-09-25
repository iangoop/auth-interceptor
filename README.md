# auth-interceptor
AngularJS Http Interceptor for managing security tokens in an SPA Architecture.

#### The interceptor allows you to:
- include the CSRF token header in HTTP requests, via cookie, meta tag or module configuration
- include the Bearer token in HTTP requests, with its initial value set in the meta tag/configuration or retrieved through endpoint request
- redirect to login page in case of error on getting the auth token, keeping the current page on session storage
- redirect to error page when request is rejected for reasons other than repairable auth errors

## Installation
```
npm install --save angularjs-auth-interceptor
```

## Configuration
Import the minified script from ```dist/auth-interceptor.min.js``` to your page
```html
<script src="node_modules/angularjs-auth-interceptor/dist/auth-interceptor.min.js"></script>
```
Add the module ```authInterceptor``` as dependency of your main application module 
```js
angular.module('myapp', ['authInterceptor'])
```
By doing so, interceptor will be running using the default values, you can nevertheless configure parameters by two means
- Configuring through provider in your module config method
```js
angular.module('myapp', ['authInterceptor'])
    .config(['authProvider',function(authProvider) {
        var opts = {}
        //set parameters that you want to change, for example
        opts.redirectToLogin = true;
        authProvider.configure(opts)
    }])
```
- Include configuration in meta tags within token namespace
```html
<head>
    <meta name="token:csrf" content="your_csrf_token_here" />
    <meta name="token:auth" content="your_first_stage_auth_token_here" />
    <meta name="token:refreshUrl" content="/url-to-refresh-token" />
</head>
```
Check out the complete list of options in the [Options](#options) section below.

## Usage
Once configured, the interceptor will automatically capture the requests made via 
$http within the controllers, attaching a csrf token and a Bearer token, 
if the interceptor was configured to do so. If the request made returns an 
401 error, the interceptor will attempt to refresh the request, by making a 
new POST request to the url set in `refreshUrl` parameter, that must return a json containing 
the key `token`. If the request to the `refreshUrl` also returns an 401 error, 
the interceptor will store the current url in sessionStorage and can be configured 
to redirect the page to the login page. If any of the requests are rejected by other 
means, the interceptor can be configured to redirect to an error page.

#### Token request example (NodeJS)

```js
app.post('/token', (req, res) => {
  res.json({'token':'your_auth_token_here'});
});
```

## Options
The options available to be set are:
- `refreshUrl` (String): The url which will be called (via POST) in case of 401 error is thrown from the original request, 
that must return a json response containing the key `token` with the Bearer token to be attached in 
the original request. Default: `/token`
- `redirectToLogin` (Boolean): If it is set to true, the interceptor will redirect to the login page in case of 
the request to the `refreshUrl` returns an 401 error. Default `false`
- `loginUrl` (String): Url to the login page in case of `redirectToLogin` is true and is triggered. Default `/login`
- `csrfCookie` (String): The interceptor will attempt to retrieve the csrf token from the cookie parameter name set 
in this option, if the parameter is available in the cookie. Default `_csrf`
- `csrfKey` (String): The csrf will be attached to the request under the name set in this option. Default `csrf-token`
- `csrf` (String): The csrf token itself. Default `undefined`
- `auth` (String): The auth token itself, it is optional as it is managed through token request, even though it is wise 
to have it initially set to spare the request from an initial rejection. Default `undefined`
- `trackState` (Boolean): If it is set to true, the interceptor will store the current url to the session storage in case
of redirecting to the login page. Default `true`
- `stateKey` (String): Session storage's parameter name to hold the current url in case of `trackState` is set to true.
Default `state`
- `redirectToError` (Boolean): Redirects to error page in the case the interceptor could not resolve request rejection. 
Default `false`
- `errorUrl` (String): Url to be redirect to in case of `redirectToError` is set to true and is triggered. Default `/error`
- `httpMethods` (Array): List of HTTP methods to be intercepted. Default `['GET', 'PATCH', 'PUT', 'POST', 'DELETE']`

## Build

If you are cloning the repository you must have gulp globally installed and run the following commands 
in order to have the dist folder generated:

```
npm install
npm run build
```

## Testing

Tests are coded using [Karma](http://karma-runner.github.io) + [Jasmine](http://jasmine.github.io/). The easiest way to run these checks is the following

```
npm install
npm test
```
