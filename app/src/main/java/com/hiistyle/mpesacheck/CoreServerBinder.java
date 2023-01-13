package com.hiistyle.mpesacheck;

import android.os.Binder;

import java.net.ServerSocket;

public class CoreServerBinder extends Binder {
    private CoreServer server;

    public CoreServerBinder(CoreServer server) {
        this.server = server;
    }

    CoreServer getServer() {
        return server;
    }

    int port;
    String hostName;
    ServerSocket serverSocket;
}
