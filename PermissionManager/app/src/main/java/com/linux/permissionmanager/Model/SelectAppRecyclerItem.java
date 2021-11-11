package com.linux.permissionmanager.Model;

import android.graphics.drawable.Drawable;

public class SelectAppRecyclerItem {
    private Drawable icon=null;
    private String showName;
    private String packageName;
    private String suFolderHeadFlag;

    public SelectAppRecyclerItem(Drawable icon, String showName, String packageName, String suFolderHeadFlag){
        this.icon=icon;
        this.showName = showName;
        this.packageName = packageName;
        this.suFolderHeadFlag = suFolderHeadFlag;
    }

    public Drawable getIcon() {
        return icon;
    }

    public void setIcon(Drawable icon) {
        this.icon = icon;
    }

    public String getShowName() {
        return showName;
    }

    public void setShowName(String showName) {
        this.showName = showName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setSuFolderHeadFlag(String suFolderHeadFlag) {
        this.showName = showName;
    }

    public String getSuFolderHeadFlag() {
        return suFolderHeadFlag;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

}
