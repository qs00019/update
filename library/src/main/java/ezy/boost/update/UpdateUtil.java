/*
 * Copyright 2016 czy1121
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ezy.boost.update;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.support.annotation.RequiresApi;
import android.support.v4.content.FileProvider;
import android.text.TextUtils;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Map;

public class UpdateUtil {
    private static final String TAG = "ezy.update";
    private static final String PREFS = "ezy.update.prefs";
    private static final String KEY_IGNORE = "ezy.update.prefs.ignore";
    private static final String KEY_UPDATE = "ezy.update.prefs.update";
    static boolean DEBUG = true;

    public static void log(String content) {
        if (DEBUG) {
            Log.i(TAG, content);
        }
    }

    public static void clean(Context context) {
        SharedPreferences sp = context.getSharedPreferences(PREFS, 0);
        File file = new File(context.getExternalCacheDir(), sp.getString(KEY_UPDATE, "") + ".apk");
        UpdateUtil.log("apk ==> " + file.toString());
        if (file.exists()) {
            file.delete();
        }
        sp.edit().clear().apply();
    }

    public static void setUpdate(Context context, String md5) {
        if (TextUtils.isEmpty(md5)) {
            return;
        }
        SharedPreferences sp = context.getSharedPreferences(PREFS, 0);
        String old = sp.getString(KEY_UPDATE, "");
        if (md5.equals(old)) {
            UpdateUtil.log("same md5");
            return;
        }
        File oldFile = new File(context.getExternalCacheDir(), old);
        if (oldFile.exists()) {
            oldFile.delete();
        }
        sp.edit().putString(KEY_UPDATE, md5).apply();
        File file = new File(context.getExternalCacheDir(), md5);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void ensureExternalCacheDir(Context context) {
        File file = context.getExternalCacheDir();
        if (file == null) {
            file = new File(context.getExternalFilesDir("").getParentFile(), "cache");
        }
        if (file != null) {
            file.mkdirs();
        }
    }

    public static void setIgnore(Context context, String md5) {
        context.getSharedPreferences(PREFS, 0).edit().putString(KEY_IGNORE, md5).apply();
    }

    public static boolean isIgnore(Context context, String md5) {
        return !TextUtils.isEmpty(md5) && md5.equals(context.getSharedPreferences(PREFS, 0).getString(KEY_IGNORE, ""));
    }

    public static void install(Context context, boolean force, int installRequestCode) {
        String md5 = context.getSharedPreferences(PREFS, 0).getString(KEY_UPDATE, "");
        File apk = new File(context.getExternalCacheDir(), md5 + ".apk");
        /*if (UpdateUtil.verify(apk, md5)) {
            install(context, apk, force);
        }*/
        install(context, apk, force, installRequestCode);
    }

    public static void install(Context context, File file, boolean force, int installRequestCode) {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O){
            //先判断是否有安装未知来源应用的权限
            boolean haveInstallPermission = context.getPackageManager().canRequestPackageInstalls();
            if(!haveInstallPermission){
                //弹框提示用户手动打开
                toInstallPermissionSettingIntent(context,installRequestCode);
                return;
            }
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            intent.setDataAndType(Uri.fromFile(file), "application/vnd.android.package-archive");
        } else {
            Uri uri = FileProvider.getUriForFile(context, context.getPackageName() + ".updatefileprovider", file);
            intent.setDataAndType(uri, "application/vnd.android.package-archive");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
        if (force) {
            System.exit(0);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private static void toInstallPermissionSettingIntent(Context context, int installRequestCode) {
        Uri packageURI = Uri.parse("package:"+ context.getPackageName());
        Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,packageURI);
        Activity activity = getCurrentActivity();
        if(activity != null){
            getCurrentActivity().startActivityForResult(intent, installRequestCode);
        }
    }

    private static Activity getCurrentActivity() {
        try {
            Class cls = Class.forName("android.app.ActivityThread");
            Object invoke = cls.getMethod("currentActivityThread", new Class[0]).invoke(null, new
                    Object[0]);
            Field declaredField = cls.getDeclaredField("mActivities");
            declaredField.setAccessible(true);
            for (Object invoke2 : ((Map) declaredField.get(invoke)).values()) {
                Class cls2 = invoke2.getClass();
                Field declaredField2 = cls2.getDeclaredField("paused");
                declaredField2.setAccessible(true);
                if (!declaredField2.getBoolean(invoke2)) {
                    declaredField = cls2.getDeclaredField("activity");
                    declaredField.setAccessible(true);
                    return (Activity) declaredField.get(invoke2);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verify(File apk, String md5,boolean isIgnoreMd5) {
        if (!apk.exists()) {
            return false;
        }
        if(isIgnoreMd5){
            return true;
        }
        else {
            String _md5 = md5(apk);
            if (TextUtils.isEmpty(_md5)) {
                return false;
            }
            boolean result = _md5 != null && _md5.equalsIgnoreCase(md5);
            if (!result) {
                apk.delete();
            }
            return result;
        }

    }


    public static String toCheckUrl(Context context, String url, String channel) {
        StringBuilder builder = new StringBuilder();
        builder.append(url);
        builder.append(url.indexOf("?") < 0 ? "?" : "&");
        builder.append("package=");
        builder.append(context.getPackageName());
        builder.append("&version=");
        builder.append(getVersionCode(context));
        builder.append("&channel=");
        builder.append(channel);
        return builder.toString();
    }

    public static int getVersionCode(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_META_DATA);
            return info.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            return 0;
        }
    }

    public static boolean checkWifi(Context context) {
        ConnectivityManager connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivity == null) {
            return false;
        }
        NetworkInfo info = connectivity.getActiveNetworkInfo();
        return info != null && info.isConnected() && info.getType() == ConnectivityManager.TYPE_WIFI;
    }

    public static boolean checkNetwork(Context context) {
        ConnectivityManager connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivity == null) {
            return false;
        }
        NetworkInfo info = connectivity.getActiveNetworkInfo();
        return info != null && info.isConnected();
    }

    public static boolean isDebuggable(Context context) {
        try {
            return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception e) {

        }
        return false;
    }

    public static String md5(File file) {
        MessageDigest digest = null;
        FileInputStream fis = null;
        byte[] buffer = new byte[1024];

        try {
            if (!file.isFile()) {
                return "";
            }

            digest = MessageDigest.getInstance("MD5");
            fis = new FileInputStream(file);

            while (true) {
                int len;
                if ((len = fis.read(buffer, 0, 1024)) == -1) {
                    fis.close();
                    break;
                }

                digest.update(buffer, 0, len);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        BigInteger var5 = new BigInteger(1, digest.digest());
        return String.format("%1$032x", new Object[]{var5});
    }


    public static String readString(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = input.read(buffer))) {
                output.write(buffer, 0, n);
            }
            output.flush();
        } finally {
            close(input);
            close(output);
        }
        return output.toString("UTF-8");
    }

    public static void close(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}