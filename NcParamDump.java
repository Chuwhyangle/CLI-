import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import nc.bs.framework.comn.NetObjectInputStream;

/** 解码 dispatcher 请求，并打印每个参数的"内容"(String/String[]/简单toString)，用于复刻入参。 */
public final class NcParamDump {

    private static final byte[] MAGIC = new byte[] {0x72, 0x71, (byte) 0x89};

    public static void main(String[] args) throws Exception {
        File clientHome = new File(args[1]);
        URLClassLoader loader = new URLClassLoader(findJars(clientHome),
                Thread.currentThread().getContextClassLoader());
        System.getProperties().put("nc.classLoader", loader);

        byte[] raw = readAll(new File(args[0]));
        int offset = 0, msgNo = 0;
        while (offset < raw.length) {
            int sep = indexOf(raw, new byte[]{13,10,13,10}, offset);
            if (sep < 0) break;
            String headers = new String(raw, offset, sep - offset, Charset.forName("ISO-8859-1"));
            int clen = contentLength(headers);
            int bodyStart = sep + 4;
            if (clen < 0 || bodyStart + clen > raw.length) break;
            if (headers.indexOf("ServiceDispatcherServlet") >= 0) {
                msgNo++;
                System.out.println("========== MESSAGE " + msgNo + " ==========");
                try {
                    if (clen < 8) throw new Exception("too short");
                    int inner = readInt(raw, bodyStart);
                    if (inner < 4 || inner > clen - 4) throw new Exception("bad inner len " + inner);
                    int fs = bodyStart + 4;
                    NetObjectInputStream in = new NetObjectInputStream(new ByteArrayInputStream(
                            java.util.Arrays.copyOfRange(raw, fs, fs + inner)));
                    Object v = in.readObject();
                    if (v.getClass().getName().contains("InvocationInfo")) {
                        Method gs = v.getClass().getMethod("getServiceName");
                        Method gm = v.getClass().getMethod("getMethodName");
                        System.out.println("  service=" + gs.invoke(v) + "." + gm.invoke(v));
                        Method gp = v.getClass().getMethod("getParameters");
                        Object[] params = (Object[]) gp.invoke(v);
                        if (params == null) { System.out.println("  (无参数)"); }
                        else for (int i = 0; i < params.length; i++) {
                            System.out.println("  --- 参数[" + i + "] " +
                                    (params[i] == null ? "null" : params[i].getClass().getName()));
                            System.out.println(truncate(stringOf(params[i]), 1500));
                        }
                    } else {
                        System.out.println("  OBJECT=" + v.getClass().getName());
                    }
                    in.close();
                } catch (Throwable e) {
                    System.out.println("  DECODE_ERR " + e + (e.getMessage()==null?"":(": "+e.getMessage())));
                }
            }
            offset = bodyStart + clen;
        }
    }

    static String stringOf(Object o) {
        if (o == null) return "null";
        if (o.getClass().isArray()) {
            int n = Array.getLength(o);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < n; i++) {
                if (i > 0) sb.append(", ");
                sb.append(stringOf(Array.get(o, i)));
            }
            return sb.append("]").toString();
        }
        return String.valueOf(o);
    }

    static String truncate(String s, int n) {
        s = s.replace("\r", " ").replace("\n", " ");
        return s.length() <= n ? s : s.substring(0, n) + "...(len=" + s.length() + ")";
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
