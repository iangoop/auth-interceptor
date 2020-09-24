(function() {
    'use strict';
    angular.module('authInterceptor', [])
        .factory('BearerAuthInterceptor',BearerAuthInterceptor())
        .provider('auth', AuthProvider())
        .config(['$httpProvider',
            function($httpProvider) {
                $httpProvider.interceptors.push('BearerAuthInterceptor');
            }
        ])

    function AuthProvider() {
        return [function() {
            var parameters = {};
            var settings = {};
            var defaults = {
                refreshUrl: '/token',
                redirectToLogin: false,
                loginUrl: '/login',
                csrfCookie: '_csrf',
                csrfKey: 'csrf-token',
                trackState: true,
                stateKey: 'state',
                redirectToError:false,
                errorUrl:'/error',
                httpMethods: ['GET', 'PATCH', 'PUT', 'POST', 'DELETE']
            }

            function key(param) {
                return param.replace('token:','').replace(/^\s+|\s+$/g, '')
            }

            function _params() {
                var settings = {}
                angular.forEach(angular.element(document).find("meta"), function (meta) {
                    meta = angular.element(meta);
                    var name = meta.attr('name');
                    if (name && name.match(/^token:/g)) {
                        settings[key(meta.attr('name'))] = meta.attr('content');
                    }
                })
                return settings;
            }

            function configure(customSettings) {
                settings = customSettings;
            }

            function load() {
                parameters = angular.extend({}, settings, defaults);
                if (parameters.csrfCookie) {
                    parameters.csrf = cookie(parameters.csrfCookie);
                }
                angular.extend(parameters, _params())
            }

            function cookie(key) {
                var occurrences = document.cookie.match('(^|;)\\s*' + key + '\\s*=\\s*([^;]+)');
                return occurrences ? occurrences.pop() : null;
            }

            function getParameters() {
                return parameters;
            }

            function updateAuth(auth) {
                parameters.auth = auth;
                angular.element(document).find("meta[name='token:auth']").attr("content",auth);
            }

            function shouldBeIntercepted(method) {
                return parameters.httpMethods.indexOf(method.toUpperCase()) > -1;
            }

            return {
                configure: configure,
                $get: [function() {
                    return {
                        getParameters: getParameters,
                        updateAuth: updateAuth,
                        shouldBeIntercepted: shouldBeIntercepted,
                        load:load
                    }
                }]
            }
        }]
    }

    function BearerAuthInterceptor() {
        return ['$injector','$window','$location','$q','auth',function($injector,$window,$location,$q,auth) {

            function isInterceptorAttempt(rejection) {
                if (rejection.config && rejection.config.headers) {
                    return rejection.config.headers['X-Token-Request'] || rejection.config.headers['X-Retry-Attempt']
                }
                return false;
            }

            function isRetryRejection(rejection) {
                if (rejection.config && rejection.config.headers) {
                    return rejection.config.headers['X-Retry-Attempt']
                }
                return false;
            }

            function isTokenRejection(rejection) {
                if (rejection.config && rejection.config.headers) {
                    return rejection.config.headers['X-Token-Request']
                }
                return false;
            }

            function refresh() {
                var deferred = $q.defer();
                var parameters = auth.getParameters();
                var req = {
                    url: parameters.refreshUrl,
                    method: 'POST',
                    headers: {
                        'X-Token-Request':'1'
                    }
                }
                var $http = $injector.get('$http');
                $http(req).then(function(response) {
                    auth.updateAuth(response.data.token)
                    deferred.resolve(response.data.token);
                },function(response) {
                    deferred.reject(response);
                })
                return deferred.promise;
            }

            function retry(config) {
                config.headers['X-Retry-Attempt'] = '1';
                var $http = $injector.get('$http');
                return $http(config)
            }

            function attempt(rejection) {
                var deferred = $q.defer();
                refresh().then(function() {
                    retry(rejection.config).then(function(response) {
                        deferred.resolve(response);
                    },function(response) {
                        //has already been rejected in the outermost else
                        deferred.reject(response);
                    })
                },function(response) {
                    //has already been rejected in the outermost else
                    //and later in refresh function
                    deferred.reject(rejection)
                })
                return deferred.promise;
            }

            auth.load()
            return {
                request: function(config) {
                    if (auth.shouldBeIntercepted(config.method)) {
                        var parameters = auth.getParameters();
                        config.headers[parameters.csrfKey] = parameters.csrf;
                        if (parameters.auth) {
                            config.headers.Authorization = 'Bearer ' + parameters.auth;
                        }
                    }
                    return config;
                },
                response: function(response) {
                    return response || $q.when(response);
                },
                responseError: function(rejection) {
                    var parameters = auth.getParameters();
                    if (!isRetryRejection(rejection) && rejection.status === 401) {
                        if (isTokenRejection(rejection)) {
                            if (parameters.trackState) {
                                $window.sessionStorage[parameters.stateKey] = $location.url();
                            }
                            if (parameters.redirectToLogin) {
                                $window.location.href = parameters.loginUrl;
                                return $q.reject();
                            }
                        } else if (auth.shouldBeIntercepted(rejection.config.method)) {
                            return attempt(rejection)
                        }
                    }

                    if (parameters.redirectToError) {
                        $window.location.href = parameters.errorUrl;
                    }
                    return $q.reject(rejection);

                }
            }
        }];
    }

})()
