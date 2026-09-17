import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import nc.bs.framework.comn.NetObjectInputStream;

/** 解码某条 dispatcher 请求，并反射展开参数对象的结构(字段/值)，用于"看明文结构"。 */
public final class NcStructDump {

    public static void main(String[] args) throws Exception {
        File clientHome = new File(args[2]);
        URLClassLoader loader = new URLClassLoader(findJars(clientHome),
                Thread.currentThread().getContextClassLoader());
        System.getProperties().put("nc.classLoader", loader);

        byte[] raw = readAll(new File(args[0]));
        int msgNo = Integer.parseInt(args[1]);
        int cur = 0;
        byte[] payload = null;
        int offset = 0;
        while (offset < raw.length) {
            int sep = indexOf(raw, new byte[]{13,10,13,10}, offset);
            if (sep < 0) break;
            String headers = new String(raw, offset, sep - offset, "ISO-8859-1");
            int clen = contentLength(headers);
            int bodyStart = sep + 4;
            if (clen < 0 || bodyStart + clen > raw.length) break;
            if (headers.indexOf("ServiceDispatcherServlet") >= 0) {
                cur++;
                if (cur == msgNo) {
                    int inner = readInt(raw, bodyStart);
                    int fs = bodyStart + 4;
                    payload = java.util.Arrays.copyOfRange(raw, fs, fs + inner);
                    break;
                }
            }
            offset = bodyStart + clen;
        }
        if (payload == null) { System.out.println("没找到第 " + msgNo + " 条"); return; }

        NetObjectInputStream in = new NetObjectInputStream(new ByteArrayInputStream(payload));
        Object v = in.readObject();
        in.close();

        Method gs = v.getClass().getMethod("getServiceName");
        Method gm = v.getClass().getMethod("getMethodName");
        Method gp = v.getClass().getMethod("getParameters");
        System.out.println("服务: " + gs.invoke(v) + " # " + gm.invoke(v));
        Object[] params = (Object[]) gp.invoke(v);
        if (params != null) for (int i = 0; i < params.length; i++) {
            System.out.println("\n==== 参数[" + i + "] 类型: " +
                    (params[i] == null ? "null" : params[i].getClass().getName()) + " ====");
            dump(params[i], "    ", 2);
        }
    }

    static void dump(Object o, String ind, int depth) {
        if (o == null) { System.out.println(ind + "= null"); return; }
        Class<?> c = o.getClass();
        if (c.isArray()) {
            int n = Array.getLength(o);
            System.out.println(ind + "数组 len=" + n);
            if (n > 0 && depth > 0) dump(Array.get(o, 0), ind + "  [0] ", depth - 1);
            return;
        }
        if (c.getName().startsWith("java.") || c.getName().startsWith("javax.") || c.getName().equals("int") || c.getName().equals("double") || c.getName().equals("boolean") || c.getName().equals("long") || c.getName().equals("float")) {
            String s = String.valueOf(o);
            System.out.println(ind + (s.length() > 220 ? s.substring(0, 220) + "..." : s));
            return;
        }
        // 打印对象字段
        List<Field> fields = new ArrayList<Field>();
        for (Class<?> cc = c; cc != null && cc != Object.class; cc = cc.getSuperclass())
            for (Field f : cc.getDeclaredFields()) fields.add(f);
        System.out.println(ind + "(" + fields.size() + " 个字段)");
        if (depth <= 0) return;
        for (Field f : fields) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
            try {
                f.setAccessible(true);
                Object val = f.get(o);
                String name = f.getName();
                String type = f.getType().getSimpleName();
                if (val instanceof java.util.Map) {
                    System.out.println(ind + name + " (Map) 共 " + ((java.util.Map<?,?>)val).size() + " 项:");
                    int k = 0;
                    for (java.util.Map.Entry<?,?> e : ((java.util.Map<?,?>)val).entrySet()) {
                        if (k++ >= 40) { System.out.println(ind + "  ...(更多省略)"); break; }
                        String v = String.valueOf(e.getValue());
                        if (v.length() > 140) v = v.substring(0, 140) + "...";
                        System.out.println(ind + "  [" + e.getKey() + "] = " + v);
                    }
                }
                else if (val == null) { System.out.println(ind + name + " (" + type + ") = null"); }
                else if (type.equals("String") || Number.class.isAssignableFrom(val.getClass()) || type.equals("boolean") || type.equals("UFBoolean")) {
                    String s = String.valueOf(val);
                    System.out.println(ind + name + " (" + type + ") = " + (s.length() > 200 ? s.substring(0,200)+"..." : s));
                } else if (val.getClass().isArray()) {
                    System.out.println(ind + name + " (" + type + "[]) len=" + Array.getLength(val));
                } else {
                    System.out.println(ind + name + " (" + type + ") = " + val.getClass().getSimpleName());
                }
            } catch (Exception e) { }
        }
    }

    static int contentLength(String h) {
        java.util.regex.Matcher m = Pattern.compile("(?i)Content-Length:\\s*(\\d+)").matcher(h);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }
    static int indexOf(byte[] a, byte[] b, int from) {
        outer: for (int i = from; i + b.length <= a.length; i++) {
            for (int j = 0; j < b.length; j++) if (a[i + j] != b[j]) continue outer;
            return i;
        }
        return -1;
    }
    static int readInt(byte[] a, int o) {
        return ((a[o] & 0xff) << 24) | ((a[o+1] & 0xff) << 16) | ((a[o+2] & 0xff) << 8) | (a[o+3] & 0xff);
    }
    static byte[] readAll(File f) throws Exception {
        FileInputStream in = new FileInputStream(f);
        byte[] b = new byte[(int) f.length()];
        int n = 0;
        while (n < b.length) { int r = in.read(b, n, b.length - n); if (r < 0) break; n += r; }
        in.close();
        return b;
    }
    static URL[] findJars(File root) throws Exception {
        List<URL> urls = new ArrayList<URL>();
        collect(root, urls);
        return urls.toArray(new URL[0]);
    }
    static void collect(File f, List<URL> urls) throws Exception {
        if (!f.exists()) return;
        if (f.isFile()) { if (f.getName().toLowerCase().endsWith(".jar")) urls.add(f.toURI().toURL()); return; }
        for (File c : f.listFiles()) collect(c, urls);
    }
}
