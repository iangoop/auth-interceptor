'use strict';
angular.module('testModule',['authInterceptor']).config(['authProvider',function(authProvider) {
    authProvider.configure({testSetting:true})
}])
describe('Testing requests', function() {
    var $window, $compile, $rootScope, httpProvider, $httpBackend, $http, auth, BearerAuthInterceptor, authRequestHandler;

    beforeEach(module('testModule', function($provide, $httpProvider) {
        $provide.value('$window',{ location: { href: ''}, sessionStorage: [] })
        httpProvider = $httpProvider;
    }));

    beforeEach(inject(function(_$window_,_$compile_, _$rootScope_, _$httpBackend_, _$http_, _auth_, _BearerAuthInterceptor_){
        // The injector unwraps the underscores (_) from around the parameter names when matching
        $window = _$window_;
        $compile = _$compile_;
        $rootScope = _$rootScope_;
        $httpBackend = _$httpBackend_;
        $http = _$http_;
        auth = _auth_;
        BearerAuthInterceptor = _BearerAuthInterceptor_;

        authRequestHandler = $httpBackend.when('POST', '/token').respond({token: 'AAA'})
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
        //cleaning eventual meta tag from token namespace added on tests
        angular.forEach(angular.element(document).find("meta"), function (meta) {
            meta = angular.element(meta);
            var name = meta.attr('name');
            if (name && name.match(/^token:/g)) {
                meta.remove();
            }
        })
        //cleaning eventual _csrf cookie set on tests
        document.cookie = "_csrf=;expires=Thu, 01 Jan 1970 00:00:01 GMT";
    });

    it('provider should contain the interceptor', function () {
        expect(httpProvider.interceptors).toContain('BearerAuthInterceptor');
    });

    it('custom setting should be retrieved from service',function() {
        expect(auth.getParameters().testSetting).toBeTrue();
    })

    it('http call should return valid response after refresh', function(done) {
        $httpBackend.expectPOST('/token');
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers.Authorization == 'Bearer AAA') {
                return [200,{'signal':'ok'}]
            }
            return [401,'']
        });
        $http.post('/need-token').then(function(response) {
            expect(response.data).toBeDefined();
            expect(response.data.signal).toMatch('ok')
            expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(3)
            done()
        })
        $httpBackend.flush();

    });

    it('http call with general error should not be refreshed', function() {
        $httpBackend.when('POST', '/need-token').respond(500,'');

        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected=false},function() {wasRejected=true})

        $httpBackend.flush();

        expect(wasRejected).toBeTrue();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(1)
    })

    it('http call with persistent Unauthorized error should be rejected', function() {
        $httpBackend.when('POST', '/need-token').respond(401,'');

        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected=false},function() {wasRejected=true})

        $httpBackend.flush();

        expect(wasRejected).toBeTrue();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(3);
    })

    it('token with unauthorized response should reject source call', function() {
        authRequestHandler.respond(401,'');
        $httpBackend.when('POST', '/need-token').respond(401,'');

        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var urlRejected;
        $http.post('/need-token').then(function() {urlRejected=''},function(rejection) {
            urlRejected=rejection.config.url
        })

        $httpBackend.flush();

        expect(urlRejected).toMatch('/need-token');
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(2);
    })

    it('token with unauthorized response and redirectToLogin to true should redirect to login page',function() {
        auth.getParameters().redirectToLogin = true;
        authRequestHandler.respond(401,'');
        $httpBackend.when('POST', '/need-token').respond(401,'');

        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected=false},function() {wasRejected=true})

        $httpBackend.flush();
        expect($window.location.href).toMatch('/login')
    })

    it('csrf token from cookie should be set on request for it not to be rejected', function() {
        document.cookie = '_csrf = bbb';
        auth.load();
        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers['csrf-token'] == 'bbb') {
                return [200,{'signal':'ok'}]
            }
            return [500,'']
        });
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected=false},function() {wasRejected=true})

        $httpBackend.flush();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(1);
        expect(wasRejected).toBeFalse();
    })

    it('csrf token from meta should be set on request for it not to be rejected', function() {
        var head = angular.element(document.querySelector('head'));
        head.append($compile("<meta name=\"token:csrf\" content=\"ccc\" />")($rootScope))

        auth.load();
        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers['csrf-token'] == 'ccc') {
                return [200,{'signal':'ok'}]
            }
            return [500,'']
        });
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected=false},function() {wasRejected=true})

        $httpBackend.flush();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(1);
        expect(wasRejected).toBeFalse();
    })

    it('auth token from meta should not be valid anymore and another one should be retrieved to the request', function() {
        var head = angular.element(document).find('head');
        head.append('<meta name="token:auth" content="DDD" />');
        $compile(head)($rootScope)
        auth.load();
        var bearerOld = false;
        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers.Authorization == 'Bearer AAA') {
                return [200,{'signal':'ok'}]
            } else if (headers.Authorization == 'Bearer DDD') {
                bearerOld = true;
            }
            return [401,'']
        });
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var urlAccepted, dataAccepted, tokenAccepted;
        $http.post('/need-token').then(function(response) {
            urlAccepted=response.config.url;
            dataAccepted=response.data;
            tokenAccepted=response.config.headers.Authorization
        },function() {urlAccepted=dataAccepted=tokenAccepted=false})
        $httpBackend.flush();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(3);
        expect(urlAccepted).toMatch('/need-token');
        expect(dataAccepted.signal).toMatch('ok');
        expect(tokenAccepted).toMatch('Bearer AAA');
        expect(bearerOld).toBeTrue();
    })

    it('auth token from meta should be valid to retrieve the request', function() {
        var head = angular.element(document).find('head');
        head.append('<meta name="token:auth" content="DDD" />');
        $compile(head)($rootScope)
        auth.load();

        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers.Authorization == 'Bearer DDD') {
                return [200,{'signal':'ok'}]
            }
            return [401,'']
        });
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var urlAccepted, dataAccepted, tokenAccepted;
        $http.post('/need-token').then(function(response) {
            urlAccepted=response.config.url;
            dataAccepted=response.data;
            tokenAccepted=response.config.headers.Authorization
        },function() {urlAccepted=dataAccepted=tokenAccepted=false})
        $httpBackend.flush();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(1);
        expect(urlAccepted).toMatch('/need-token');
        expect(dataAccepted.signal).toMatch('ok');
        expect(tokenAccepted).toMatch('Bearer DDD');
    })

    it('auth token should not be attached and a retry should not be executed by removing method from list', function() {
        auth.getParameters().httpMethods.splice(auth.getParameters().httpMethods.indexOf('POST'),1); //removing post from methods
        $httpBackend.when('POST', '/need-token').respond(function(method, url, data, headers, params) {
            if (headers.Authorization == 'Bearer AAA') {
                return [200,{'signal':'ok'}]
            }
            return [401,'']
        });
        spyOn(BearerAuthInterceptor, 'request').and.callThrough();
        var wasRejected;
        $http.post('/need-token').then(function() {wasRejected = false},function() {wasRejected=true})
        $httpBackend.flush();
        expect(BearerAuthInterceptor.request).toHaveBeenCalledTimes(1);
        expect(wasRejected).toBeTrue();
    })

})
