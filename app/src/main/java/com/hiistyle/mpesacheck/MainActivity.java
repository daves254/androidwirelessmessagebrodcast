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

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

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
    CoreServer serverService;
    class ServerConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            serverService=((CoreServerBinder)iBinder).getServer();
            if(serverService.server==null){
                serverService.server=new Server(MainActivity.this);
            }
            findViewById(R.id.button).setEnabled(true);
            ((TextView)findViewById(R.id.status)).setText("Service connected");
            serverService.server.activity=MainActivity.this;
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            serverService=null;

        }
    }
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void onConnectClicked(View v) {
        if(serverService==null){
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

            Object ret = serverService.server.init(this);
            if (ret instanceof Boolean) {
                Boolean b = (Boolean) ret;
                if (b.booleanValue()) {
                    Spinner spinner = findViewById(R.id.device);
                    ArrayAdapter<Server.AccessPoint> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, serverService.server.accessPoints);
                    spinner.setAdapter(adapter);
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

                    spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

                        @Override
                        public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                            Server.AccessPoint point = (Server.AccessPoint) adapterView.getItemAtPosition(i);
                            TextView tv = findViewById(R.id.host);
                            tv.setText(point.address.getHostAddress());
                            ((Button) v).setText("Connect");
                            v.setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View view) {
                                    serverService.server.selectDevice(i);
                                    try {
                                        serverService.server.setPort(Integer.parseInt(((TextView) findViewById(R.id.port)).getText().toString()));
                                        ((Button) v).setText("Disconnect");
                                        v.setOnClickListener(new View.OnClickListener() {
                                            @Override
                                            public void onClick(View view) {
                                                serverService.server.stop();
                                                System.exit(0);
                                            }
                                        });
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                        }

                        @Override
                        public void onNothingSelected(AdapterView<?> adapterView) {
                        }
                    });
                    // v.setTextAlignment();
                } else {
                    new AlertDialog.Builder(this).setTitle("Not connected").setMessage("Please connect to wifi").show();
                    return;
                }
            } else new AlertDialog.Builder(this).setTitle("Error").setMessage(ret + "").show();


        } catch (Throwable e) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            e.printStackTrace(new PrintStream(baos));
            new AlertDialog.Builder(this).setTitle("Error").setMessage(new String(baos.toByteArray())).show();
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        startServerService();
    }

    private void startServerService() {
        Intent intent=new Intent(this,CoreServer.class);
        bindService(intent,new ServerConnection(),Context.BIND_AUTO_CREATE);
    }
}