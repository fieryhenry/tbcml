package com.tbcml;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/* loaded from: /tmp/jadx-11619970748472039267.dex */
public class DataLoad {
    public static void Start(Context context) {
        Extract(context);
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
                    // if entryName ends with .alwayscopy
                    boolean alwaysCopy = entryName.endsWith(".alwayscopy");
                    entryName = entryName.replace(".alwayscopy", "");

                    File gameFile = new File(gameDataPath + entryName);
                    if (gameFile.exists() && !alwaysCopy) {
                        continue;
                    }

                    if (entry.isDirectory()) {
                        if (!gameFile.exists()) {
                            gameFile.mkdirs();
                        }
                    } else {
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
                    }
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
