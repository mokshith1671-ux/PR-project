setImmediate(function () {
    Java.perform(function () {

        function logEvent(type, data) {
            console.log(JSON.stringify({
                ts: Date.now(),
                type: type,
                data: data
            }));
        }

        console.log("START");

        // logEvent("loaded", {
        //     app: "hook_started"
        // });

        // ---------- ACTIVITY ----------
        try {
            var Activity = Java.use("android.app.Activity");
            Activity.onResume.implementation = function () {
                logEvent("activity", {
                    name: this.getClass().getName()
                });
                return this.onResume();
            };
        } catch (e) {}

        // ---------- FILE ----------
        try {
            var File = Java.use("java.io.File");
            File.$init.overload('java.lang.String').implementation = function (path) {
                logEvent("file", { path: path });
                return this.$init(path);
            };
        } catch (e) {}

        // ---------- URL ----------
        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload('java.lang.String').implementation = function (url) {
                logEvent("network", { url: url });
                return this.$init(url);
            };
        } catch (e) {}

        // ---------- SHARED PREF ----------
        try {
            var SP = Java.use("android.app.SharedPreferencesImpl");
            SP.getString.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                logEvent("sp", { key: k });
                return this.getString(k, v);
            };
        } catch (e) {}

        // ---------- DEVICE ----------
        try {
            var Telephony = Java.use("android.telephony.TelephonyManager");
            Telephony.getDeviceId.overload().implementation = function () {
                logEvent("device", { action: "getDeviceId" });
                return this.getDeviceId();
            };
        } catch (e) {}

        // ---------- CRYPTO ----------
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.getInstance.overload('java.lang.String').implementation = function (algo) {
                logEvent("crypto", { algorithm: algo });
                return this.getInstance(algo);
            };
        } catch (e) {}

    });
});