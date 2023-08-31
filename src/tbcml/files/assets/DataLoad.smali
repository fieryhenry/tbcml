.class public Lcom/tbcml/DataLoad;
.super Ljava/lang/Object;
.source "DataLoad.java"


# direct methods
.method public constructor <init>()V
    .registers 1

    .prologue
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static Extract(Landroid/content/Context;)V
    .registers 11

    .prologue
    const/4 v9, -0x1

    .line 24
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    .line 25
    invoke-virtual {p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    .line 26
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "/data/data/"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v2, "/"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 28
    :try_start_22
    const-string v0, "data.zip"

    invoke-virtual {v1, v0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v0

    .line 29
    new-instance v3, Ljava/util/zip/ZipInputStream;

    invoke-direct {v3, v0}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_2d
    .catch Ljava/lang/Exception; {:try_start_22 .. :try_end_2d} :catch_ad

    .line 32
    :cond_2d
    :goto_2d
    :try_start_2d
    invoke-virtual {v3}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;

    move-result-object v4

    .line 33
    if-nez v4, :cond_37

    .line 34
    invoke-virtual {v3}, Ljava/util/zip/ZipInputStream;->close()V

    .line 112
    :goto_36
    return-void

    .line 38
    :cond_37
    invoke-virtual {v4}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    move-result-object v0

    .line 40
    const-string v1, ".alwayscopy"

    invoke-virtual {v0, v1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v5

    .line 41
    const-string v1, ".alwayscopy"

    const-string v6, ""

    invoke-virtual {v0, v1, v6}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v1

    .line 43
    const-string v0, "$url_"

    invoke-virtual {v1, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v6

    .line 45
    const-string v0, ""

    .line 46
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    if-eqz v7, :cond_7a

    .line 47
    const-string v0, "\\$url_"

    invoke-virtual {v1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    const/4 v7, 0x1

    aget-object v7, v0, v7

    .line 48
    new-instance v0, Ljava/lang/String;

    invoke-static {}, Ljava/util/Base64;->getUrlDecoder()Ljava/util/Base64$Decoder;

    move-result-object v8

    invoke-virtual {v8, v7}, Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B

    move-result-object v7

    invoke-direct {v0, v7}, Ljava/lang/String;-><init>([B)V

    .line 50
    const-string v7, "\\$url_"

    invoke-virtual {v1, v7}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v1

    const/4 v7, 0x0

    aget-object v1, v1, v7

    .line 53
    :cond_7a
    new-instance v7, Ljava/io/File;

    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v7, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 54
    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    move-result v1

    if-eqz v1, :cond_98

    if-eqz v5, :cond_2d

    .line 58
    :cond_98
    invoke-virtual {v4}, Ljava/util/zip/ZipEntry;->isDirectory()Z

    move-result v1

    if-eqz v1, :cond_af

    .line 59
    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    move-result v0

    if-nez v0, :cond_2d

    .line 60
    invoke-virtual {v7}, Ljava/io/File;->mkdirs()Z
    :try_end_a7
    .catch Ljava/lang/Exception; {:try_start_2d .. :try_end_a7} :catch_a8

    goto :goto_2d

    .line 101
    :catch_a8
    move-exception v0

    .line 103
    :try_start_a9
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V
    :try_end_ac
    .catch Ljava/lang/Exception; {:try_start_a9 .. :try_end_ac} :catch_ad

    goto :goto_36

    .line 107
    :catch_ad
    move-exception v0

    goto :goto_36

    .line 65
    :cond_af
    :try_start_af
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-nez v1, :cond_de

    .line 66
    const/16 v0, 0x800

    new-array v0, v0, [B

    .line 67
    new-instance v1, Ljava/io/FileOutputStream;

    invoke-direct {v1, v7}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 68
    new-instance v4, Ljava/io/BufferedOutputStream;

    const/16 v5, 0x800

    invoke-direct {v4, v1, v5}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V

    .line 70
    :goto_c5
    const/4 v5, 0x0

    const/16 v6, 0x800

    invoke-virtual {v3, v0, v5, v6}, Ljava/util/zip/ZipInputStream;->read([BII)I

    move-result v5

    .line 71
    if-ne v5, v9, :cond_d9

    .line 76
    invoke-virtual {v4}, Ljava/io/BufferedOutputStream;->flush()V

    .line 77
    invoke-virtual {v4}, Ljava/io/BufferedOutputStream;->close()V

    .line 78
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V

    goto/16 :goto_2d

    .line 74
    :cond_d9
    const/4 v6, 0x0

    invoke-virtual {v4, v0, v6, v5}, Ljava/io/BufferedOutputStream;->write([BII)V

    goto :goto_c5

    .line 82
    :cond_de
    new-instance v1, Landroid/os/StrictMode$ThreadPolicy$Builder;

    invoke-direct {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>()V

    invoke-virtual {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;->permitAll()Landroid/os/StrictMode$ThreadPolicy$Builder;

    move-result-object v1

    invoke-virtual {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;->build()Landroid/os/StrictMode$ThreadPolicy;

    move-result-object v1

    .line 83
    invoke-static {v1}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 84
    const-string v1, "tbcml"

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Downloading "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v5, " to "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v7}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v1, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 85
    new-instance v1, Ljava/net/URL;

    invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 86
    invoke-virtual {v1}, Ljava/net/URL;->openStream()Ljava/io/InputStream;

    move-result-object v0

    .line 87
    const/16 v1, 0x800

    new-array v1, v1, [B

    .line 88
    new-instance v4, Ljava/io/FileOutputStream;

    invoke-direct {v4, v7}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 89
    new-instance v5, Ljava/io/BufferedOutputStream;

    const/16 v6, 0x800

    invoke-direct {v5, v4, v6}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V

    .line 91
    :goto_12d
    const/4 v6, 0x0

    const/16 v7, 0x800

    invoke-virtual {v0, v1, v6, v7}, Ljava/io/InputStream;->read([BII)I

    move-result v6

    .line 92
    if-ne v6, v9, :cond_141

    .line 97
    invoke-virtual {v5}, Ljava/io/BufferedOutputStream;->flush()V

    .line 98
    invoke-virtual {v5}, Ljava/io/BufferedOutputStream;->close()V

    .line 99
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V

    goto/16 :goto_2d

    .line 95
    :cond_141
    const/4 v7, 0x0

    invoke-virtual {v5, v1, v7, v6}, Ljava/io/BufferedOutputStream;->write([BII)V
    :try_end_145
    .catch Ljava/lang/Exception; {:try_start_af .. :try_end_145} :catch_a8

    goto :goto_12d
.end method

.method public static Start(Landroid/content/Context;)V
    .registers 1

    .prologue
    .line 19
    invoke-static {p0}, Lcom/tbcml/DataLoad;->Extract(Landroid/content/Context;)V

    .line 20
    return-void
.end method
