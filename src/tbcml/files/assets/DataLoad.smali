###### Class com.tbcml.DataLoad (com.tbcml.DataLoad)
.class public Lcom/tbcml/DataLoad;
.super Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static InternalDataRestore(Landroid/content/Context;)V
    .registers 24

    .prologue
    .line 40
    const/16 v4, 0x800

    .line 41
    .local v4, "BUFFER":I
    const-string v17, "/"

    .line 42
    .local v17, "t":Ljava/lang/String;
    const-string v18, "data"

    .line 44
    .line 45
    .local v18, "t1":Ljava/lang/String;
    .local p0, "t5":Ljava/lang/String;
    const-string v22, "data.zip"

    .line 46
    .local v22, "t3":Ljava/lang/String;
    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v5

    .line 47
    .local v5, "aa":Ljava/lang/String;
    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v6

    .line 48
    .local v6, "bb":Landroid/content/res/AssetManager;
    new-instance v20, Ljava/lang/StringBuilder;

    invoke-static/range {v17 .. v17}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v21

    invoke-direct/range {v20 .. v21}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    move-object/from16 v0, v20

    move-object/from16 v1, v18

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    move-object/from16 v0, v20

    move-object/from16 v1, v17

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    move-object/from16 v0, v20

    move-object/from16 v1, v18

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    move-object/from16 v0, v20

    move-object/from16 v1, v17

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    move-object/from16 v0, v20

    move-object v1, v5

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    move-object/from16 v0, v20

    move-object/from16 v1, v17

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    invoke-virtual/range {v20 .. v20}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v16

    .line 50
    .local v16, "logDir":Ljava/lang/String;
    const/4 v9, 0x0

    .line 54
    .local v9, "dest":Ljava/io/BufferedOutputStream;
    :try_start_4d
    move-object v0, v6

    move-object/from16 v1, v22

    invoke-virtual {v0, v1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v15

    .line 55
    .local v15, "localInputStream1":Ljava/io/InputStream;
    new-instance v19, Ljava/util/zip/ZipInputStream;

    move-object/from16 v0, v19

    move-object v1, v15

    invoke-direct {v0, v1}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_5c
    .catch Ljava/lang/Exception; {:try_start_4d .. :try_end_5c} :catch_d4

    .local v19, "zis":Ljava/util/zip/ZipInputStream;
    move-object v10, v9

    .line 58
    .end local v9    # "dest":Ljava/io/BufferedOutputStream;
    .local v10, "dest":Ljava/io/BufferedOutputStream;
    :cond_5d
    :goto_5d
    :try_start_5d
    invoke-virtual/range {v19 .. v19}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;

    move-result-object v12

    .local v12, "entry":Ljava/util/zip/ZipEntry;
    if-nez v12, :cond_67

    .line 85
    invoke-virtual/range {v19 .. v19}, Ljava/util/zip/ZipInputStream;->close()V

    .line 90
    .end local v10    # "dest":Ljava/io/BufferedOutputStream;
    .end local v12    # "entry":Ljava/util/zip/ZipEntry;
    .end local v15    # "localInputStream1":Ljava/io/InputStream;
    .end local v19    # "zis":Ljava/util/zip/ZipInputStream;
    :goto_66
    return-void

    .line 59
    .restart local v10    # "dest":Ljava/io/BufferedOutputStream;
    .restart local v12    # "entry":Ljava/util/zip/ZipEntry;
    .restart local v15    # "localInputStream1":Ljava/io/InputStream;
    .restart local v19    # "zis":Ljava/util/zip/ZipInputStream;
    :cond_67
    new-instance v13, Ljava/io/File;

    new-instance v20, Ljava/lang/StringBuilder;

    invoke-static/range {v16 .. v16}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v21

    invoke-direct/range {v20 .. v21}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v12}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    move-result-object v21

    invoke-virtual/range {v20 .. v21}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v20

    invoke-virtual/range {v20 .. v20}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v20

    move-object v0, v13

    move-object/from16 v1, v20

    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 62
    .local v13, "file":Ljava/io/File;
    invoke-virtual {v13}, Ljava/io/File;->exists()Z

    move-result v20

    if-nez v20, :cond_5d

    .line 66
    invoke-virtual {v12}, Ljava/util/zip/ZipEntry;->isDirectory()Z

    move-result v20

    if-eqz v20, :cond_a2

    .line 67
    invoke-virtual {v13}, Ljava/io/File;->exists()Z

    move-result v20

    if-nez v20, :cond_5d

    .line 68
    invoke-virtual {v13}, Ljava/io/File;->mkdirs()Z
    :try_end_99
    .catch Ljava/lang/Exception; {:try_start_5d .. :try_end_99} :catch_9a

    goto :goto_5d

    .line 86
    .end local v12    # "entry":Ljava/util/zip/ZipEntry;
    .end local v13    # "file":Ljava/io/File;
    :catch_9a
    move-exception v20

    move-object/from16 v11, v20

    move-object v9, v10

    .line 88
    .end local v10    # "dest":Ljava/io/BufferedOutputStream;
    .end local v15    # "localInputStream1":Ljava/io/InputStream;
    .end local v19    # "zis":Ljava/util/zip/ZipInputStream;
    .restart local v9    # "dest":Ljava/io/BufferedOutputStream;
    .local v11, "e":Ljava/lang/Exception;
    :goto_9e
    invoke-virtual {v11}, Ljava/lang/Exception;->printStackTrace()V

    goto :goto_66

    .line 74
    .end local v9    # "dest":Ljava/io/BufferedOutputStream;
    .end local v11    # "e":Ljava/lang/Exception;
    .restart local v10    # "dest":Ljava/io/BufferedOutputStream;
    .restart local v12    # "entry":Ljava/util/zip/ZipEntry;
    .restart local v13    # "file":Ljava/io/File;
    .restart local v15    # "localInputStream1":Ljava/io/InputStream;
    .restart local v19    # "zis":Ljava/util/zip/ZipInputStream;
    :cond_a2
    :try_start_a2
    new-array v8, v4, [B

    .line 77
    .local v8, "data":[B
    new-instance v14, Ljava/io/FileOutputStream;

    invoke-direct {v14, v13}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 78
    .local v14, "fos":Ljava/io/FileOutputStream;
    new-instance v9, Ljava/io/BufferedOutputStream;

    invoke-direct {v9, v14, v4}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V
    :try_end_ae
    .catch Ljava/lang/Exception; {:try_start_a2 .. :try_end_ae} :catch_9a

    .line 79
    .end local v10    # "dest":Ljava/io/BufferedOutputStream;
    .restart local v9    # "dest":Ljava/io/BufferedOutputStream;
    :goto_ae
    const/16 v20, 0x0

    :try_start_b0
    move-object/from16 v0, v19

    move-object v1, v8

    move/from16 v2, v20

    move v3, v4

    invoke-virtual {v0, v1, v2, v3}, Ljava/util/zip/ZipInputStream;->read([BII)I

    move-result v7

    .local v7, "count":I
    const/16 v20, -0x1

    move v0, v7

    move/from16 v1, v20

    if-ne v0, v1, :cond_c9

    .line 82
    invoke-virtual {v9}, Ljava/io/BufferedOutputStream;->flush()V

    .line 83
    invoke-virtual {v9}, Ljava/io/BufferedOutputStream;->close()V

    move-object v10, v9

    .end local v9    # "dest":Ljava/io/BufferedOutputStream;
    .restart local v10    # "dest":Ljava/io/BufferedOutputStream;
    goto :goto_5d

    .line 80
    .end local v10    # "dest":Ljava/io/BufferedOutputStream;
    .restart local v9    # "dest":Ljava/io/BufferedOutputStream;
    :cond_c9
    const/16 v20, 0x0

    move-object v0, v9

    move-object v1, v8

    move/from16 v2, v20

    move v3, v7

    invoke-virtual {v0, v1, v2, v3}, Ljava/io/BufferedOutputStream;->write([BII)V
    :try_end_d3
    .catch Ljava/lang/Exception; {:try_start_b0 .. :try_end_d3} :catch_d4

    goto :goto_ae

    .line 86
    .end local v7    # "count":I
    .end local v8    # "data":[B
    .end local v12    # "entry":Ljava/util/zip/ZipEntry;
    .end local v13    # "file":Ljava/io/File;
    .end local v14    # "fos":Ljava/io/FileOutputStream;
    .end local v15    # "localInputStream1":Ljava/io/InputStream;
    .end local v19    # "zis":Ljava/util/zip/ZipInputStream;
    :catch_d4
    move-exception v20

    move-object/from16 v11, v20

    goto :goto_9e
.end method

.method public static Start(Landroid/content/Context;)V
    .registers 3

    .prologue
    .line 1
    invoke-static {p0}, Lcom/tbcml/DataLoad;->InternalDataRestore(Landroid/content/Context;)V

    return-void
.end method

