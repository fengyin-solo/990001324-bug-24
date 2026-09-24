(function() {
    'use strict';

    var STORAGE_KEY = 'community-board.admin-session';
    var LOGIN_URL = 'login.php?expired=1';
    var CHECK_URL = 'api.php?action=session';
    var CHECK_INTERVAL = 3000;

    var identity = window.ADMIN_AUTH_IDENTITY || null;
    var redirecting = false;
    var checking = null;
    var lastCheckAt = 0;

    function writeState(state) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
        } catch (e) {}
    }

    function readState() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
        } catch (e) {
            return null;
        }
    }

    function invalidatePage(reason) {
        if (redirecting) return;
        redirecting = true;

        try {
            document.documentElement.setAttribute('data-auth-invalid', '1');
            if (document.body) {
                document.body.setAttribute('inert', '');
                document.body.style.opacity = '0.5';
                document.body.style.pointerEvents = 'none';
            }
            window.name = '';
        } catch (e) {}

        var url = LOGIN_URL;
        if (reason) url += '&reason=' + encodeURIComponent(reason);
        window.location.replace(url);
    }

    function reloadForIdentityChange() {
        window.location.reload();
    }

    function localStateIsValid() {
        var state = readState();
        return !!(state && String(state.id) === String(identity.id));
    }

    function handleStorageEvent(event) {
        if (event.key && event.key !== STORAGE_KEY) return;
        var state = readState();

        if (!state || !state.id) {
            invalidatePage('logout');
            return;
        }

        if (identity && String(state.id) !== String(identity.id)) {
            reloadForIdentityChange();
        }
    }

    function checkSession(force) {
        var now = Date.now();
        if (!identity || redirecting) return Promise.resolve(false);
        if (!localStateIsValid()) {
            invalidatePage('logout');
            return Promise.resolve(false);
        }
        if (!force && checking) return checking;
        if (!force && now - lastCheckAt < CHECK_INTERVAL) return Promise.resolve(true);

        checking = fetch(CHECK_URL, {
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function(response) {
            lastCheckAt = Date.now();

            if (response.status === 401) {
                writeState(null);
                invalidatePage('expired');
                return false;
            }

            if (!response.ok) return true;

            return response.json().then(function(result) {
                if (result.code === 401) {
                    writeState(null);
                    invalidatePage('expired');
                    return false;
                }

                if (result.code === 0 && result.data) {
                    var latest = {
                        id: result.data.id,
                        name: result.data.name,
                        updatedAt: Date.now()
                    };

                    if (String(latest.id) !== String(identity.id) || latest.name !== identity.name) {
                        writeState(latest);
                        reloadForIdentityChange();
                        return false;
                    }

                    identity = latest;
                    writeState(latest);
                }

                return true;
            }).catch(function() {
                return localStateIsValid();
            });
        }).catch(function() {
            // 网络故障不应误退出；本地退出信号仍会立即拦截操作。
            return localStateIsValid();
        }).then(function(valid) {
            checking = null;
            return valid;
        });

        return checking;
    }

    function patchFetch() {
        var originalFetch = window.fetch;
        if (!originalFetch) return;

        window.fetch = function(input, init) {
            var url = typeof input === 'string' ? input : (input && input.url) || '';
            var isAdminApi = url.indexOf('api.php') !== -1;

            if (!isAdminApi) {
                return originalFetch.apply(this, arguments);
            }

            if (redirecting || !localStateIsValid()) {
                invalidatePage('logout');
                return new Promise(function() {});
            }

            return checkSession().then(function(valid) {
                if (!valid) return new Promise(function() {});

                return originalFetch.call(this, input, init).then(function(response) {
                    if (response.status === 401) {
                        writeState(null);
                        invalidatePage('expired');
                    }
                    return response;
                });
            }.bind(this));
        };
    }

    function bindLogoutLinks() {
        document.addEventListener('click', function(event) {
            var link = event.target.closest && event.target.closest('a[href$="logout.php"], a[href*="logout.php"]');
            if (!link) return;

            // 先广播退出，再让浏览器请求 logout.php；其他标签页无需等待请求完成。
            writeState(null);
        }, true);
    }

    document.addEventListener('DOMContentLoaded', function() {
        if (!identity) return;

        writeState({
            id: identity.id,
            name: identity.name,
            updatedAt: Date.now()
        });

        patchFetch();
        bindLogoutLinks();
        checkSession(true);
    });

    window.addEventListener('storage', handleStorageEvent);
    window.addEventListener('pageshow', function(event) {
        if (!identity) return;

        if (event.persisted || !localStateIsValid()) {
            checkSession(true);
        }
    });
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible' && identity) {
            checkSession(true);
        }
    });
    window.addEventListener('focus', function() {
        if (identity) checkSession();
    });
})();
