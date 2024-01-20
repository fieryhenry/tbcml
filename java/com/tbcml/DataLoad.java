package com.tbcml;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.StrictMode;
import android.util.Log;

public class DataLoad {
    public static void Start(final Context context) {
        new Thread(new Runnable() {
            public void run() {
                DataLoad.Extract(context);
            }
        }).start();
    }

    public static void Extract(Context context) {
        Exception e;
        String packageName = context.getPackageName();
        AssetManager assets = context.getAssets();
        String gameDataPath = "/data/data/" + packageName + "/";
        try {
            InputStream localInputStream1 = assets.open("data.zip");
            ZipInputStream zis = new ZipInputStream(localInputStream1);
            while (true) {
                try {
                    ZipEntry entry = zis.getNextEntry();
                    if (entry == null) {
                        zis.close();
                        return;
                    }

                    String entryName = entry.getName();
                    boolean alwaysCopy = entryName.endsWith(".alwayscopy");
                    entryName = entryName.replace(".alwayscopy", "");

                    Boolean isUrl = entryName.contains("$url_");
                    // file_name$url_base64url
                    String url = "";
                    if (isUrl) {
                        String burl = entryName.split("\\$url_")[1];
                        url = new String(Base64.getUrlDecoder().decode(burl));

                        entryName = entryName.split("\\$url_")[0];
                    }

                    File gameFile = new File(gameDataPath + entryName);
                    if (gameFile.exists() && !alwaysCopy) {
                        continue;
                    }

                    if (entry.isDirectory()) {
                        if (!gameFile.exists()) {
                            gameFile.mkdirs();
                        }
                        continue;
                    }

                    if (!isUrl) {
                        Log.d("tbcml", "Extracting " + entryName + " to " + gameFile.getAbsolutePath());
                        byte[] data = new byte[2048];
                        FileOutputStream fos = new FileOutputStream(gameFile);
                        BufferedOutputStream dest2 = new BufferedOutputStream(fos, 2048);
                        while (true) {
                            int count = zis.read(data, 0, 2048);
                            if (count == -1) {
                                break;
                            }
                            dest2.write(data, 0, count);
                        }
                        dest2.flush();
                        dest2.close();
                        fos.close();
                        continue;
                    }
                    StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
                    StrictMode.setThreadPolicy(policy);
                    Log.d("tbcml", "Downloading " + url + " to " + gameFile.getAbsolutePath());
                    URI uri = new URI(url);
                    InputStream localInputStream2 = uri.toURL().openStream();

                    byte[] data2 = new byte[2048];
                    FileOutputStream fos2 = new FileOutputStream(gameFile);
                    BufferedOutputStream dest22 = new BufferedOutputStream(fos2, 2048);
                    while (true) {
                        int count2 = localInputStream2.read(data2, 0, 2048);
                        if (count2 == -1) {
                            break;
                        }
                        dest22.write(data2, 0, count2);
                    }
                    dest22.flush();
                    dest22.close();
                    fos2.close();

                } catch (Exception e2) {
                    e = e2;
                    e.printStackTrace();
                    return;
                }
            }
        } catch (

        Exception e3) {
            e = e3;
        }
    }
}
