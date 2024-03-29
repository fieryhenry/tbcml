let presents_url = "{{PRESENTS_URL}}"
let is_file = "{{IS_FILE}}"

let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhjS2_j" // 32 bit

if (is_64_bit()) {
    func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhmS2_m" // 64 bit
}

// Botan::PK_Verifier::verify_message(unsigned char const*, unsigned long, unsigned char const*, unsigned long)
Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
    onLeave: function (retval) {
        retval.replace(0x1)
    }
})

function get_nonce_from_url(url) {
    if (!url.toString().includes("nonce=")) {
        return null
    }
    let nonce = url.toString().split("nonce=")[1].split("&")[0]
    return nonce
}

function get_direct_byte_buffer_from_string(str) {
    let new_data_buffer = Java.array('byte', str.split('').map(function (c) {
        return c.charCodeAt(0);
    }));
    let new_data_directByteBuffer = Java.use("java.nio.DirectByteBuffer").allocateDirect(new_data_buffer.length);
    new_data_directByteBuffer.put(new_data_buffer);
    new_data_directByteBuffer.flip();
    return new_data_directByteBuffer
}

function get_headers() {
    let headers_obj = {
        "Content-Type": "application/json",
        "Nyanko-Signature": "A"
    }
    let headers = JSON.stringify(headers_obj)
    return headers

}

function readFile(path) {
    let File = Java.use("java.io.File");
    let FileInputStream = Java.use("java.io.FileInputStream");
    let InputStreamReader = Java.use("java.io.InputStreamReader");
    let BufferedReader = Java.use("java.io.BufferedReader");
    let file = File.$new(path);
    if (!file.exists()) {
        return null
    }
    let fileInputStream = FileInputStream.$new(file);
    let inputStreamReader = InputStreamReader.$new(fileInputStream);
    let bufferedReader = BufferedReader.$new(inputStreamReader);
    let stringBuilder = Java.use("java.lang.StringBuilder").$new();
    let line = null;
    while ((line = bufferedReader.readLine()) != null) {
        stringBuilder.append(line);
    }
    bufferedReader.close();
    return stringBuilder.toString();
}

function get_internal_storage_path() {
    let File = Java.use("java.io.File");
    let Environment = Java.use("android.os.Environment");
    let path = File.$new(Environment.getDataDirectory(), "data/" + getPackageName()).getAbsolutePath();
    return path
}

function download_file(url) {
    // download file and return string
    let URL = Java.use("java.net.URL");
    let BufferedReader = Java.use("java.io.BufferedReader");
    let InputStreamReader = Java.use("java.io.InputStreamReader");
    let StringBuilder = Java.use("java.lang.StringBuilder");
    let url_obj = URL.$new(url);
    let urlConnection = url_obj.openConnection();
    let inputStreamReader = InputStreamReader.$new(urlConnection.getInputStream());
    let bufferedReader = BufferedReader.$new(inputStreamReader);
    let stringBuilder = StringBuilder.$new();
    let inputLine = null;
    while ((inputLine = bufferedReader.readLine()) != null) {
        stringBuilder.append(inputLine);
    }
    bufferedReader.close();
    return stringBuilder.toString();
}

function get_lib_folder() {
    // get lib folder in /data/app/<package_name>-<random>/lib/arm64
    let context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    let applicationInfo = context.getApplicationInfo();
    let nativeLibraryDir = applicationInfo.nativeLibraryDir.value;
    return nativeLibraryDir
}

function get_presents_wrapper() {
    try {
        return get_presents()
    }
    catch (error) {
        logError(error.toString())
        return []
    }
}

function get_presents() {
    let data = null
    if (is_file == true || is_file.toLowerCase() == "true") {
        let path = get_lib_folder() + `/libpresents.json.so`
        data = readFile(path)
    }
    else {
        data = download_file(presents_url)
    }
    let presents = JSON.parse(data)

    return presents
}

function get_modified_response(url, payload) {
    let nonce = get_nonce_from_url(url)
    if (nonce == null) {
        return [null, null, null]
    }
    let timestamp = Date.now()
    let new_data = null

    if (payload != null) {
        let payload_string = JSON.stringify(payload)
        new_data = `{"statusCode":1,"nonce":"${nonce}","payload":${payload_string},"timestamp": ${timestamp}}`
    }
    else {
        new_data = `{"statusCode":1,"nonce":"${nonce}","timestamp": ${timestamp}}`
    }

    let headers = get_headers()
    let data = get_direct_byte_buffer_from_string(new_data)
    let response_code = 200

    return [headers, data, response_code]
}

Java.perform(function () {
    let MyActivity = Java.use("jp.co.ponos.battlecats.MyActivity");
    MyActivity["newResponse"].implementation = function (handle, response_code, url, headers, data, flag) {
        if (url.toString().includes("https://nyanko-items.ponosgames.com/v4/presents/count?")) {
            let payload = {
                "count": get_presents_wrapper().length
            }
            let response = get_modified_response(url, payload)
            headers = response[0]
            data = response[1]
            response_code = response[2]

        }
        else if (url.toString().includes("https://nyanko-items.ponosgames.com/v4/presents?")) {
            let payload = {
                "presents": get_presents_wrapper()
            }
            let response = get_modified_response(url, payload)
            headers = response[0]
            data = response[1]
            response_code = response[2]

        }
        else if (url.toString().includes("https://nyanko-items.ponosgames.com/v3/presents//reception?")) {
            let response = get_modified_response(url, null)
            headers = response[0]
            data = response[1]
            response_code = response[2]

        };
        this["newResponse"](handle, response_code, url, headers, data, flag);
    }
})