package com.linux.permissionmanager;

import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private long rootKey = 0x7F6766F8;
    //保存的本地配置信息
    private SharedPreferences m_shareSave;

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("root");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        m_shareSave = getSharedPreferences("zhcs", Context.MODE_PRIVATE);
        try{ rootKey = m_shareSave.getLong("rootKey",rootKey );}catch(Exception e){}

        //验证用户的KEY
        final EditText inputKey = new EditText(MainActivity.this);
        inputKey.setText(Long.toHexString(rootKey));
        inputKey.setSelection(inputKey.length(),0);
        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setTitle("请输入ROOT权限的KEY").setIcon(android.R.drawable.ic_dialog_info).setView(inputKey)
                .setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        rootKey = Long.valueOf(inputKey.getText().toString(),16);
                        //数值保存到本地
                        SharedPreferences.Editor mEdit = m_shareSave.edit();
                        mEdit.putLong("rootKey",rootKey);
                        mEdit.commit();
                    };
                });
        builder.show();



        Button show_myself_info_btn = findViewById(R.id.show_myself_info_btn);
        show_myself_info_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showConsoleMsg(getCapabilityInfo());
            }
        });

        Button get_root_btn = findViewById(R.id.get_root_btn);
        get_root_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int ret = getRoot(rootKey);
                showConsoleMsg("getRoot: " +ret);
            }
        });

        Button disable_selinux_btn = findViewById(R.id.disable_selinux_btn);
        disable_selinux_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int ret = disableSElinux(rootKey);
                showConsoleMsg("disableSElinux: " +ret);
            }
        });

        Button enable_selinux_btn = findViewById(R.id.enable_selinux_btn);
        enable_selinux_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int ret = enableSElinux(rootKey);
                showConsoleMsg("enableSElinux: " +ret);
            }
        });

        Button run_root_cmd_btn = findViewById(R.id.run_root_cmd_btn);
        run_root_cmd_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                    final EditText inputCMD = new EditText(MainActivity.this);
                    inputCMD.setText("id");
                    inputCMD.setSelection(inputCMD.length(),0);
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    builder.setTitle("输入ROOT命令").setIcon(android.R.drawable.ic_dialog_info).setView(inputCMD)
                            .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    dialog.dismiss();
                                }
                            });
                    builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            String text = inputCMD.getText().toString();
                            showConsoleMsg(text+"\n"+runRootCmd(rootKey, text));
                        };
                    });
                    builder.show();

            }
        });
        Button run_adb_shell_btn = findViewById(R.id.run_adb_shell_btn);
        run_adb_shell_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                    if(!guideOpenUsbDebugSwitch()) {
                        return;
                    }

                    final EditText inputShell = new EditText(MainActivity.this);
                    inputShell.setText("id");
                    inputShell.setSelection(inputShell.length(),0);
                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    builder.setTitle("输入shell命令").setIcon(android.R.drawable.ic_dialog_info).setView(inputShell)
                            .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    dialog.dismiss();
                                }
                            });
                    builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            String text = inputShell.getText().toString();
                            showConsoleMsg(text+"\n"+runAdbShell(rootKey, text,  false));
                        };
                    });
                    builder.show();

            }
        });

        Button keep_adb_root_btn = findViewById(R.id.keep_adb_root_btn);
        keep_adb_root_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if(!guideOpenUsbDebugSwitch()) {
                    return;
                }
                showConsoleMsg("id\n"+runAdbShell(rootKey, "id", true));
            }
        });
        Button su_install_btn = findViewById(R.id.su_install_btn);
        keep_adb_root_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {


            }
        });

        Button copy_info_btn = findViewById(R.id.copy_info_btn);
        copy_info_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copyConsoleMsg();
                Toast.makeText(v.getContext(), "复制成功" , Toast.LENGTH_SHORT).show();

            }
        });
        Button clean_info_btn = findViewById(R.id.clean_info_btn);
        clean_info_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                cleanConsoleMsg();
            }
        });
    }
    public void showConsoleMsg(String msg){
        EditText console_edit = findViewById(R.id.console_edit);
        StringBuffer txt = new StringBuffer();
        txt.append(console_edit.getText().toString());
        if (txt.length() != 0) {
            txt.append("\n");
        }
        txt.append(msg);
        txt.append("\n");
        console_edit.setText(txt.toString());
        console_edit.setSelection(txt.length());
    }
    public void cleanConsoleMsg(){
        EditText console_edit = findViewById(R.id.console_edit);
        console_edit.setText("");
    }
    public void copyConsoleMsg(){
        EditText console_edit = findViewById(R.id.console_edit);
        //获取剪贴板管理器：
        ClipboardManager cm = (ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
        // 创建普通字符型ClipData
        ClipData mClipData = ClipData.newPlainText("Label", console_edit.getText());
        // 将ClipData内容放到系统剪贴板里。
        cm.setPrimaryClip(mClipData);

    }

    public boolean guideOpenUsbDebugSwitch(){
        //检查USB调试开关是否打开
        if(!UsbDebugSwitchHelper.checkUsbDebugSwitch(MainActivity.this)){

            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this)
                    .setTitle("提示")
                    .setMessage("请先到开发者选项页面里打开【USB调试】开关（提示：在手机关于页面里连续点击系统版本号可启用开发者选项页面）")
                    .setOnDismissListener(new DialogInterface.OnDismissListener() {
                        @Override
                        public void onDismiss(DialogInterface dialog) {
                            dialog.dismiss();
                            UsbDebugSwitchHelper.startDevelopmentActivity(MainActivity.this); //转到开发者页面
                        }
                    })
                    .setNegativeButton("确定", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            UsbDebugSwitchHelper.startDevelopmentActivity(MainActivity.this); //转到开发者页面

                        }
                    });
            AlertDialog dialog = builder.create();
            dialog.show();
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(Color.BLACK);

            return false;
        }
        return true;
    }
    public boolean guideCloseUsbDebugSwitch(){
        //检查USB调试开关是否打开
        if(UsbDebugSwitchHelper.checkUsbDebugSwitch(MainActivity.this)){

            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this)
                    .setTitle("提示")
                    .setMessage("请先到开发者选项页面里关闭【USB调试】开关")
                    .setOnDismissListener(new DialogInterface.OnDismissListener() {
                        @Override
                        public void onDismiss(DialogInterface dialog) {
                            dialog.dismiss();
                            UsbDebugSwitchHelper.startDevelopmentActivity(MainActivity.this); //转到开发者页面
                        }
                    })
                    .setNegativeButton("确定", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            UsbDebugSwitchHelper.startDevelopmentActivity(MainActivity.this); //转到开发者页面

                        }
                    });
            AlertDialog dialog = builder.create();
            dialog.show();
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(Color.BLACK);
            return false;
        }
        return true;
    }

    public native String getCapabilityInfo();
    public native int getRoot(long rootKey);
    public native int disableSElinux(long rootKey);
    public native int enableSElinux(long rootKey);
    public native String runRootCmd(long rootKey,  String cmd);
    public native String runAdbShell(long rootKey,  String shell,boolean keepAdbRoot);
}