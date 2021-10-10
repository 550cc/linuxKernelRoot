package com.linux.permissionmanager;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.provider.Settings;

public class UsbDebugSwitchHelper {
    public static boolean checkUsbDebugSwitch(Context ctx) {
        //检查USB调试是否被打开
        boolean enableAdb = (Settings.Secure.getInt(ctx.getContentResolver(), Settings.Secure.ADB_ENABLED, 0) > 0);//判断adb调试模式是否打开
        return enableAdb;
    }

    /**
     * 打开开发者模式界面
     */
    public static void startDevelopmentActivity(Context ctx) {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            ctx.startActivity(intent);
        } catch (Exception e) {
            try {
                ComponentName componentName = new ComponentName("com.android.settings", "com.android.settings.DevelopmentSettings");
                Intent intent = new Intent();
                intent.setComponent(componentName);
                intent.setAction("android.intent.action.View");
                ctx.startActivity(intent);
            } catch (Exception e1) {
                try {
                    Intent intent = new Intent("com.android.settings.APPLICATION_DEVELOPMENT_SETTINGS");//部分小米手机采用这种方式跳转
                    ctx.startActivity(intent);
                } catch (Exception e2) {

                }

            }
        }
    }

}
