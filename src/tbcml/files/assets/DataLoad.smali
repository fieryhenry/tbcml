.class public Lcom/tbcml/DataLoad;
.super Ljava/lang/Object;
.source "DataLoad.java"


# direct methods
.method public constructor <init>()V
    .registers 1

    .prologue
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static Extract(Landroid/content/Context;)V
    .registers 8

    .prologue
    .line 18
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    .line 19
    invoke-virtual {p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    .line 20
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

    move-result-object v0

    .line 22
    :try_start_21
    const-string v2, "data.zip"

    invoke-virtual {v1, v2}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v1

    .line 23
    new-instance v2, Ljava/util/zip/ZipInputStream;

    invoke-direct {v2, v1}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_2c
    .catch Ljava/lang/Exception; {:try_start_21 .. :try_end_2c} :catch_7b

    .line 27
    :cond_2c
    :goto_2c
    :try_start_2c
    invoke-virtual {v2}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;

    move-result-object v1

    .line 28
    if-nez v1, :cond_36

    .line 29
    invoke-virtual {v2}, Ljava/util/zip/ZipInputStream;->close()V

    .line 73
    :goto_35
    return-void

    .line 33
    :cond_36
    invoke-virtual {v1}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    move-result-object v3

    .line 35
    const-string v4, ".alwayscopy"

    invoke-virtual {v3, v4}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v4

    .line 36
    const-string v5, ".alwayscopy"

    const-string v6, ""

    invoke-virtual {v3, v5, v6}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v3

    .line 38
    new-instance v5, Ljava/io/File;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v5, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 39
    invoke-virtual {v5}, Ljava/io/File;->exists()Z

    move-result v3

    if-eqz v3, :cond_66

    if-eqz v4, :cond_2c

    .line 43
    :cond_66
    invoke-virtual {v1}, Ljava/util/zip/ZipEntry;->isDirectory()Z

    move-result v1

    if-eqz v1, :cond_7d

    .line 44
    invoke-virtual {v5}, Ljava/io/File;->exists()Z

    move-result v1

    if-nez v1, :cond_2c

    .line 45
    invoke-virtual {v5}, Ljava/io/File;->mkdirs()Z
    :try_end_75
    .catch Ljava/lang/Exception; {:try_start_2c .. :try_end_75} :catch_76

    goto :goto_2c

    .line 62
    :catch_76
    move-exception v0

    .line 64
    :try_start_77
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V
    :try_end_7a
    .catch Ljava/lang/Exception; {:try_start_77 .. :try_end_7a} :catch_7b

    goto :goto_35

    .line 68
    :catch_7b
    move-exception v0

    goto :goto_35

    .line 48
    :cond_7d
    const/16 v1, 0x800

    :try_start_7f
    new-array v1, v1, [B

    .line 49
    new-instance v3, Ljava/io/FileOutputStream;

    invoke-direct {v3, v5}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 50
    new-instance v4, Ljava/io/BufferedOutputStream;

    const/16 v5, 0x800

    invoke-direct {v4, v3, v5}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V

    .line 52
    :goto_8d
    const/4 v3, 0x0

    const/16 v5, 0x800

    invoke-virtual {v2, v1, v3, v5}, Ljava/util/zip/ZipInputStream;->read([BII)I

    move-result v3

    .line 53
    const/4 v5, -0x1

    if-ne v3, v5, :cond_9e

    .line 58
    invoke-virtual {v4}, Ljava/io/BufferedOutputStream;->flush()V

    .line 59
    invoke-virtual {v4}, Ljava/io/BufferedOutputStream;->close()V

    goto :goto_2c

    .line 56
    :cond_9e
    const/4 v5, 0x0

    invoke-virtual {v4, v1, v5, v3}, Ljava/io/BufferedOutputStream;->write([BII)V
    :try_end_a2
    .catch Ljava/lang/Exception; {:try_start_7f .. :try_end_a2} :catch_76

    goto :goto_8d
.end method

.method public static Start(Landroid/content/Context;)V
    .registers 1

    .prologue
    .line 13
    invoke-static {p0}, Lcom/tbcml/DataLoad;->Extract(Landroid/content/Context;)V

    .line 14
    return-void
.end method
