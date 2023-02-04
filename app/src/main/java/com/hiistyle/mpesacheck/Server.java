package com.hiistyle.mpesacheck;

import android.app.Activity;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
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
import java.util.HashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class Server implements Runnable {
enum Status{
    NotStarted,Waiting,Connected, Retrying, Disconnected
}
    final MutableLiveData<AccessPoint> ap_bind = new MutableLiveData<>();

    static class User {
        String currentAuthorizationToken;
        String password;
        String username;
    }

    static final HashMap<String, User> users = new HashMap<>();

    static {
        User user = new User();
        user.username = "admin";
        user.password = "1101101001";
        users.put("admin", user);
    }
    final MutableLiveData<Status> status=new MutableLiveData<>(Status.Disconnected);
    private boolean started;
    public final MutableLiveData<Socket> socket_ = new MutableLiveData<>();
    private HashMap<String, Socket> sessions = new HashMap<>();
    Context ctx;

    public Server(CoreServer coreService) {
        this.ctx = coreService;
        ap_bind.observe(coreService, new Observer<AccessPoint>() {
            @Override
            public void onChanged(AccessPoint accessPoint) {
                if (accessPoint != null)
                    new Thread(() -> {
                        try {
                            CoreServer.BIND.getValue().server.socket_.postValue(new Socket(ap_bind.getValue().address, ap_bind.getValue().port));
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }).start();
            }
        });
    }

    public void accessPoint(AccessPoint ap) {
        this.ap_bind.postValue(ap);
    }


    public void stop() {
        if (socket_.getValue() != null) {
            if (!socket_.getValue().isClosed()) {
                try {
                    socket_.getValue().close();
                } catch (Exception err) {
                    // Swallow the error!
                }
            }
            socket_.postValue(null);
        }
    }

    static class HeaderUtils {
        final static String START_HEADER = "start-header";
        final static String END_HEADER = "end-header";
    }

    static class ResponseChannel {
        OutputStream os;

        public ResponseChannel(OutputStream os) {
            this.os = Objects.requireNonNull(os);
        }

        public void startHeader() throws IOException {
            os.write(HeaderUtils.START_HEADER.getBytes());
            endl();
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        public void sendException(Throwable ex) throws IOException {
            ex.printStackTrace();
            byte[] stackTraceContent;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ex.printStackTrace(new PrintStream(bos));
            stackTraceContent = bos.toByteArray();
            bos.close();
            writeContent("An error occured.", null, false, stackTraceContent, "json");
        }

        public void endHeader() throws IOException {
            os.write(HeaderUtils.END_HEADER.getBytes());
            endl();
        }

        private void endl() throws IOException {
            os.write("\n".getBytes());
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        public void messageBase64(String message) throws IOException {
            os.write(("message-base64 :" + Base64.getEncoder().encodeToString(message.getBytes())).getBytes());
            endl();
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        public void writeContent(String message, String response, boolean ok, byte[] content, String type) throws IOException {
            startHeader();
            if (response != null)
                response(response);
            if (message != null)
                messageBase64(message);
            setOk(ok);
            content(content.length, type);
            endHeader();
            os.write(content);
        }

        private void response(String response) throws IOException {
            os.write(("response:" + response).getBytes());
            endl();
        }

        private void content(int content_length, String type) throws IOException {
            os.write(("content-length:" + content_length).getBytes());
            endl();
            os.write(("content-type:" + type).getBytes());
            endl();
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        public void auth(String auth) throws IOException {
            os.write(("auth : " + auth).getBytes());
            endl();
        }

        public void setOk(boolean ok) throws IOException {

            os.write(("ok :" + ok).getBytes());
            endl();

        }
    }

    static class AccessPoint {
        int port;
        String address;
        String name;

        @Override
        public String toString() {
            return address + ":" + port;
        }
    }

    static final Pattern KEY_VALUE_PATTERN = Pattern.compile("(?<key>[A-Za-z0-9= /\\-]+):(?<value>[A-Za-z0-9= /\\-]+)");
    static final Gson gson = new GsonBuilder().create();

    static class ContentAccess {
        String type;
        String[] projection;
        String selectionClause;
        String[] selectionArgs;
        String selectionOrder;
    }

    static class XRequest {
        String uri;
        String[] projection;
        String selectionClause;
        String[] selectionArgs;
        String selectionOrder;

        public XRequest(Server.ContentAccess access) {
            projection = access.projection;
            selectionClause = access.selectionClause;
            ;
            selectionArgs = access.selectionArgs;
            selectionOrder = access.selectionOrder;
        }

        @Override
        public String toString() {
            return "Request{" +
                    "uri='" + uri + '\'' +
                    ", projection=" + Arrays.toString(projection) +
                    ", selectionClause='" + selectionClause + '\'' +
                    ", selectionArgs=" + Arrays.toString(selectionArgs) +
                    ", selectionOrder='" + selectionOrder + '\'' +
                    '}';
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    public void run() {
        int[] trials = {0};
        status.postValue(Status.Waiting);

        while (listen(trials)) {
            AccessPoint ap = ap_bind.getValue();
            if (trials[0] >= 1000) {
                status.postValue(Status.Disconnected);
                ap_bind.postValue(null);
                trials[0] = 0;
            } else if (ap != null) {
                status.postValue(Status.Retrying);
                trials[0]++;
                ap_bind.postValue(ap);
            }else {
                status.postValue(Status.Disconnected);
                trials[0]=0;
            }


        }
        status.postValue(Status.Disconnected);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private boolean listen(int[] trials) {
        while (socket_.getValue() == null) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return false;
            }
        }

        {
            Socket s = socket_.getValue();
            if(s.isClosed())return true;
            try {
                InputStream in = s.getInputStream();
                //
                status.postValue(Status.Connected);
                ResponseChannel responseChannel;
                {
                    OutputStream os = s.getOutputStream();
                    responseChannel = new ResponseChannel(os);
                }
                    /*
                    responseChannel.startHeader();
                    responseChannel.messageBase64("Success");
                    responseChannel.setOk(true);
                    responseChannel.endHeader();
                    */

                byte[] buffer = new byte[2048];
                int len;
                StringBuilder sb = new StringBuilder();
                boolean inside_header = false;
                HashMap<String, String> map = new HashMap<>();
                int iter = 0;
                CONNECTION:
                while ((len = in.read(buffer)) != -1) {
                    iter++;
                    int offset = 0;
                    READING:
                    while (true) {
                        if (offset >= len) {
                            continue CONNECTION;
                        }
                        int eolIndx = -1;
                        for (; offset < len; offset++) {
                                /*if (buffer[offset] < 0) {
                                    responseChannel.startHeader();
                                    responseChannel.setOk(false);
                                    responseChannel.messageBase64("Invalid character encoding detected");
                                    responseChannel.endHeader();
                                    map.clear();
                                    inside_header = false;
                                    continue READING;
                                }*/

                            if (buffer[offset] == '\n') {
                                eolIndx = offset++;
                                break;
                            }
                            if (buffer[offset] != '\r') sb.append((char) buffer[offset]);
                        }

                        if (eolIndx == -1) {
                            continue READING;
                        }
                        String header = sb.toString().trim();
                        System.out.println("HEADER: " + header);
                        sb.delete(0, sb.length());

                        Matcher m;
                        if (inside_header && (m = KEY_VALUE_PATTERN.matcher(header)).matches()) {
                            {
                                {
                                        /*responseChannel.startHeader();
                                        responseChannel.messageBase64(header);
                                        responseChannel.endHeader();*/
                                    String key = m.group("key").trim();
                                    String value = m.group("value").trim();
                                    map.put(key, value);
                                    System.out.println(map.toString());
                                }
                            }
                        } else//
                            if (inside_header && header.equals(HeaderUtils.END_HEADER)) {
                                inside_header = false;
                                System.out.println(map.toString());
                                String auth = map.get("auth");
                                System.out.println("Auth: " + auth);
                                if (auth == null || !isAuthorized(auth, s)) {
                                    String req = map.get("request");
                                    if (req != null && req.equals("authorize-session")) {
                                        String username = map.get("username");
                                        String password = map.get("password");
                                        //
                                        boolean authorized;
                                        if (username == null || password == null || username.isEmpty() || password.isEmpty()) {
                                            responseChannel.startHeader();
                                            responseChannel.setOk(authorized = false);
                                            responseChannel.messageBase64("Password or Username cannot be empty or null");
                                            responseChannel.endHeader();
                                            map.clear();
                                        } else {
                                            password = new String(Base64.getDecoder().decode(password));
                                            username = new String(Base64.getDecoder().decode(username));
                                            Object u = authorize(username, password, s);
                                            responseChannel.startHeader();
                                            if (u instanceof User) {
                                                responseChannel.setOk(authorized = true);
                                                responseChannel.auth(((User) u).currentAuthorizationToken);
                                            } else {
                                                responseChannel.setOk(authorized = false);
                                                if (u != null) {
                                                    responseChannel.messageBase64(u.toString());
                                                }
                                            }
                                            responseChannel.endHeader();

                                        }
                                        if (!authorized) {
                                            //Disconnect
                                            s.close();
                                            map.clear();
                                            return true;
                                        }
                                    }
                                    map.clear();
                                    continue READING;
                                }
                                int read = 0;
                                String callRequest = null;
                                for (Map.Entry e : map.entrySet()) {
                                    String key = (String) e.getKey();
                                    String value = (String) e.getValue();
                                    if (key.equals("request")) {
                                        callRequest = value;
                                    } else if (!(key.equals("content-length") || key.equals("content-type") || key.equals("message-base64") || key.equals("ok") || key.equals("auth"))) {
                                        responseChannel.sendException(new NoSuchElementException("No header handler found" + key));
                                    }
                                }

                                /////////////////////////////////////////////////////////////////////////////
                                if (callRequest != null) {
                                    switch (callRequest) {
                                        case "messages": {
                                            String cl = map.get("content-length");
                                            try {
                                                int content_length = Integer.parseInt(cl);
                                                int last_offset = content_length + offset;
                                                int final_len = Math.min(buffer.length, last_offset);
                                                byte[] content = new byte[content_length];
                                                int i = 0;
                                                for (; offset < final_len; offset++) {
                                                    content[i++] = buffer[offset];
                                                }
                                                if (i < content_length) {
                                                    offset = 0;
                                                    do {
                                                        len = in.read(buffer);
                                                        if (len == -1) break CONNECTION;
                                                        final_len = Math.min(buffer.length, content_length - i);
                                                        for (; offset < final_len; offset++)
                                                            content[i++] = buffer[offset];
                                                    } while (i < content_length);
                                                }
                                                String json = new String(content);
                                                System.out.println(json);
                                                ContentAccess access = gson.fromJson(json, ContentAccess.class);
                                                switch (access.type) {
                                                    case "message-inbox": {
                                                        XRequest req = new XRequest(access);
                                                        req.uri = "content://sms/inbox/";
                                                        Uri uri = Uri.parse(req.uri);
                                                        String[] projection = access.projection;
                                                        String selectionClause = access.selectionClause;
                                                        String[] selectionArgs = access.selectionArgs;
                                                        String selectionOrder = access.selectionOrder;
                                                        ContentResolver resolver = ctx.getContentResolver();
                                                        Cursor c = resolver.query(uri, projection, selectionClause, selectionArgs, selectionOrder);
                                                        c.getColumnCount();
                                                        Map<String, Object>[] results = new Map[c.getCount()];
                                                        if (results.length > 0) {
                                                            c.moveToFirst();
                                                            for (int j = 0; j < results.length; j++) {
                                                                Map<String, Object> result = results[j] = new TreeMap<>();
                                                                int columnCount = c.getColumnCount();
                                                                for (int k = 0; k < columnCount; k++) {
                                                                    switch (c.getType(k)) {
                                                                        case Cursor.FIELD_TYPE_BLOB: {
                                                                            result.put(c.getColumnName(k), c.getBlob(k));
                                                                        }
                                                                        break;
                                                                        case Cursor.FIELD_TYPE_FLOAT: {
                                                                            result.put(c.getColumnName(k), c.getDouble(k));
                                                                        }
                                                                        break;
                                                                        case Cursor.FIELD_TYPE_INTEGER: {
                                                                            result.put(c.getColumnName(k), c.getLong(k));
                                                                        }
                                                                        break;
                                                                        case Cursor.FIELD_TYPE_NULL: {
                                                                        }
                                                                        break;
                                                                        case Cursor.FIELD_TYPE_STRING: {
                                                                            result.put(c.getColumnName(k), c.getString(k));
                                                                        }
                                                                        break;
                                                                    }
                                                                    results[j].put(c.getColumnName(k), c.getString(k));
                                                                }
                                                                c.moveToNext();
                                                            }

                                                        }
                                                        {
                                                            // -----------------------------
                                                            responseChannel.writeContent(req.toString(), "messages", true, gson.toJson(results).getBytes(), "json");
                                                            //-----------------------------
                                                        }

                                                    }
                                                    break;
                                                    default: {
                                                        responseChannel.sendException(new NoSuchElementException("Command isn't found:" + access.type));
                                                        break;
                                                    }
                                                }
                                            } catch (Exception ex) {
                                                responseChannel.sendException(ex);
                                            }
                                        }
                                        break;
                                        case "execute": {
                                            //Never implement! Risky.
                                        }
                                        default:
                                            responseChannel.sendException(new NoSuchElementException("No request definition found."));
                                            break;

                                    }
                                }
                                ////////////////////////////////////////////////////////////////////////////
                                if (map.isEmpty())
                                    responseChannel.sendException(new NullPointerException("Header is null or empty"));
                                map.clear();
                            } else//
                                if (header.equals(HeaderUtils.START_HEADER) && (!inside_header)) {
                                    inside_header = true;
                                } else//
                                    if (!header.isEmpty()) {
                                        responseChannel.startHeader();
                                        responseChannel.setOk(false);
                                        responseChannel.messageBase64("Your request couldn't be understood.");
                                        responseChannel.endHeader();
                                        map.clear();
                                    }
                    }
                }
            } catch (IOException e) {
                try {
                    s.close();
                } catch (Exception error) {
                }
                e.printStackTrace();
            }
        }
        socket_.postValue(null);
        trials[0] = 0;
        return true;
    }

    private Object authorize(String username, String password, Socket s) {
        User user = users.get(username);
        if (user.password.equals(password)) {
            String auth = sha256String(username + password + "!!!" + System.currentTimeMillis());
            if (user.currentAuthorizationToken != null) {
                sessions.remove(user.currentAuthorizationToken);
            }
            user.currentAuthorizationToken = auth;
            sessions.put(auth, s);
            return user;
        }
        return "Not authorized";
    }

    public static String sha256String(String source) {
        byte[] hash = null;
        String hashCode = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(source.getBytes());
        } catch (NoSuchAlgorithmException e) {
            Log.wtf("DIGEST", "Can't calculate SHA-256");
        }

        if (hash != null) {
            StringBuilder hashBuilder = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(hash[i]);
                if (hex.length() == 1) {
                    hashBuilder.append("0");
                    hashBuilder.append(hex.charAt(hex.length() - 1));
                } else {
                    hashBuilder.append(hex.substring(hex.length() - 2));
                }
            }
            hashCode = hashBuilder.toString();
        }

        return hashCode;
    }

    private boolean isAuthorized(String auth, Socket s) {
        Socket socket = sessions.get(auth);
        System.out.println("Auth:" + auth + " socket:" + s);
        System.out.println("Auth: " + auth);
        return socket == s;
    }

    public Object init() {
        {
            try {
                Enumeration<NetworkInterface> net_interfaces = NetworkInterface.getNetworkInterfaces();
                for (; net_interfaces.hasMoreElements(); ) {
                    NetworkInterface e = net_interfaces.nextElement();

                    Enumeration<InetAddress> ips = e.getInetAddresses();
                    {
                        String interfaceName = e.getName();
                        boolean wifi = interfaceName.matches("wlan\\d.*");
                        boolean hotspot = interfaceName.matches("ap\\d.*");
                        if (wifi || hotspot) {
                            for (; ips.hasMoreElements(); ) {
                                InetAddress ip = ips.nextElement();
                                if (!ip.isLoopbackAddress() && (ip instanceof Inet4Address)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable e) {
                e.printStackTrace();
                return e;
            }
            return false;
        }

    }

}


