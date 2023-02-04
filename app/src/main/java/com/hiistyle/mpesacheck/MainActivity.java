package com.hiistyle.mpesacheck;

import android.Manifest;
import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.Observer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void onConnectClicked(View v) {
        if (CoreServer.BIND.getValue() == null) {
            v.setEnabled(false);
            startServerService();
            return;
        }
        try {
            String[] perms = new String[]{//
                    Manifest.permission.READ_SMS,//
                    Manifest.permission.READ_EXTERNAL_STORAGE,//
                    Manifest.permission.WRITE_EXTERNAL_STORAGE,//
                    Manifest.permission.INTERNET,//
                    Manifest.permission.ACCESS_WIFI_STATE,
                    Manifest.permission.ACCESS_NETWORK_STATE,
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.SEND_SMS,
                    Manifest.permission.CAMERA,
                    Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                    Manifest.permission.ACCESS_LOCATION_EXTRA_COMMANDS,
                    Manifest.permission.ACCESS_COARSE_LOCATION,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_MEDIA_LOCATION

            };
            {
                for (String perm : perms)
                    if (PackageManager.PERMISSION_GRANTED != checkSelfPermission(perm)) {
                        requestPermissions(perms, 0);
                        new AlertDialog.Builder(MainActivity.this).setMessage("please grant me some funny permissions").setCancelable(true).show();
                        return;
                    }
            }

            Object ret = CoreServer.BIND.getValue().server.init();
            if (ret instanceof Boolean) {
                Boolean b = (Boolean) ret;
                if (b.booleanValue()) {
                    // v.setTextAlignment();
                    connect(v);
                } else {
                    new AlertDialog.Builder(this).setTitle("Not connected").setMessage("Please connect to wifi or start hostpot.").show();
                    return;
                }
            } else new AlertDialog.Builder(this).setTitle("Error").setMessage(ret + "").show();


        } catch (Throwable e) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            e.printStackTrace(new PrintStream(baos));
            new AlertDialog.Builder(this).setTitle("Error").setMessage(baos.toString()).show();
        }
    }

    public void connect(View v) {
        // we need to create the object
        // of IntentIntegrator class
        // which is the class of QR library
        IntentIntegrator intentIntegrator = new IntentIntegrator(this);
        intentIntegrator.setPrompt("Scan a barcode or QR Code");
        intentIntegrator.setCaptureActivity(QRScannerActivity.class);
        intentIntegrator.setOrientationLocked(false);
        intentIntegrator.setBeepEnabled(true);
        intentIntegrator.initiateScan();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        IntentResult intentResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        // if the intentResult is null then
        // toast a message as "cancelled"
        if (intentResult != null) {
            String contents = intentResult.getContents();
            if (contents == null) {
                Toast.makeText(getBaseContext(), "Cancelled", Toast.LENGTH_SHORT).show();
            } else {
                // if the intentResult is not null we'll set
                // the content and format of scan message
                //messageText.setText(intentResult.getContents());
                //messageFormat.setText(intentResult.getFormatName());
         /*       String r = intentResult.getContents();
                new AlertDialog//
                        .Builder(this)//
                        .setTitle(//
                                intentResult//
                                        .getFormatName()//
                        ).setMessage(r)//
                        .show();*/
                Server.AccessPoint[] ap = {null};
                if ("QR_CODE".equals(intentResult.getFormatName())) {
                    try {
                        System.out.println(contents);
                        ap[0] = new Gson().fromJson(contents, Server.AccessPoint.class);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                if (ap[0] != null) {
                    {
                        System.out.println(new Gson().toJson(ap));
                        CoreServer.BIND.getValue().server.accessPoint(ap[0]);
                    }
                }


            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        CoreServer.BIND.observe(this, new Observer<CoreServer>() {
            @Override
            public void onChanged(CoreServer coreServer) {
                if (coreServer != null) {
                    ((Button)findViewById(R.id.button)).setEnabled(true);
                    CoreServer.BIND.getValue().server.status.observe(MainActivity.this,new Observer<Server.Status>(){
                        /**
                         * Called when the data is changed.
                         *
                         * @param status The new data
                         */
                        @Override
                        public void onChanged(Server.Status status) {
                            if(status!=null) {
                                TextView statusView = (TextView) findViewById(R.id.status);
                                switch (status){
    
                                    case NotStarted:
                                        statusView.setText("Not started");
                                        findViewById(R.id.button).setEnabled(true);
                                        break;
                                    case Waiting:
                                        statusView.setText("Waiting Connection");
                                        findViewById(R.id.button).setEnabled(true);
                                        break;
                                    case Connected:
                                        statusView.setText("Connected");
                                        findViewById(R.id.button).setEnabled(false);
                                        break;
                                    case Retrying:
                                        statusView.setText("Retrying...");
                                        findViewById(R.id.button).setEnabled(true);
                                        break;
                                    case Disconnected:
                                        statusView.setText("Disconnected");
                                        findViewById(R.id.button).setEnabled(true);
                                        break;
                                }
                            }
                        }
                    });
                    CoreServer.BIND.getValue().server.status.postValue(Server.Status.NotStarted);
                }
            }
        });
        startServerService();
          }

    private void startServerService() {
        Intent intent = new Intent(this, CoreServer.class);
        startService(intent);
    }
}