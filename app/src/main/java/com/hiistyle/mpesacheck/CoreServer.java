package com.hiistyle.mpesacheck;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;

public class CoreServer extends Service {
    public Server server;
    IBinder binder=new CoreServerBinder(this);

    @Override
    public void onCreate() {
        super.onCreate();
        if(server==null)server=new Server(this);
        new Thread(server).start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }
}