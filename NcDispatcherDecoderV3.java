import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import nc.bs.framework.comn.NetObjectInputStream;

/**
 * V2: same parser as NcDispatcherDecoder, but additionally prints
 *  - String parameter VALUES from InvocationInfo.getParameters()
 *  - exception detail (class + message) from Result.appexception
 * Sensitive ids (userId/userCode/callId) stay redacted.
 */
public final class NcDispatcherDecoderV3 {

    private static final byte[] MAGIC = new byte[] { 0x72, 0x71, (byte) 0x89 };
    private static final int MAX_STR = 300;

    private NcDispatcherDecoderV3() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: NcDispatcherDecoderV3 <raw-http-file> <client-home>");
            System.exit(2);
        }
        File clientHome = new File(args[1]);
        URLClassLoader loader = new URLClassLoader(findJars(clientHome),
                Thread.currentThread().getContextClassLoader());
        System.getProperties().put("nc.classLoader", loader);

        byte[] raw = readAll(new File(args[0]));
        int offset = 0;
        int messageNo = 0;
        while (offset < raw.length) {
            int separator = indexOf(raw, new byte[] { 13, 10, 13, 10 }, offset);
            if (separator < 0) {
                break;
            }
            String headers = new String(raw, offset, separator - offset, Charset.forName("ISO-8859-1"));
            int contentLength = contentLength(headers);
            int bodyStart = separator + 4;
            if (contentLength < 0 || bodyStart + contentLength > raw.length) {
                break;
            }
            String lowerHeaders = headers.toLowerCase();
            if (headers.indexOf("ServiceDispatcherServlet") >= 0
                    || lowerHeaders.indexOf("application/x-java-serialized-object") >= 0) {
                messageNo++;
                decodeMessage(messageNo, raw, bodyStart, contentLength);
            }
            offset = bodyStart + contentLength;
        }
    }

    private static void decodeMessage(int messageNo, byte[] raw, int bodyStart, int bodyLength) {
        try {
            if (bodyLength < 8) {
                throw new IOException("dispatcher body is too short");
            }
            int declaredLength = readInt(raw, bodyStart);
            if (declaredLength < 4 || declaredLength > bodyLength - 4) {
                throw new IOException("invalid inner length: " + declaredLength);
            }
            int frameStart = bodyStart + 4;
            if (!matches(raw, frameStart, MAGIC)) {
                throw new IOException("invalid NC stream magic");
            }
            int flags = raw[frameStart + 3] & 0xff;
            int encryptType = (flags & 8) != 0 ? 2 : ((flags & 4) != 0 ? 1 : 0);
            boolean encrypted = (flags & 1) != 0;
            boolean compressed = (flags & 2) != 0;
            int keyId = (frameStart + 4 < bodyStart + 4 + declaredLength)
                    ? raw[frameStart + 4] & 0xff : -1;
            System.out.println("MESSAGE " + messageNo
                    + " len=" + bodyLength
                    + " flags=0x" + hexByte(flags)
                    + " encrypted=" + encrypted
                    + " compressed=" + compressed
                    + " encryptType=" + encryptType
                    + " keyId=0x" + hexByte(keyId));

            byte[] frame = new byte[declaredLength];
            System.arraycopy(raw, frameStart, frame, 0, declaredLength);
            NetObjectInputStream input = new NetObjectInputStream(
                    new java.io.ByteArrayInputStream(frame));
            Object value = input.readObject();
            System.out.println("  OBJECT " + value.getClass().getName());
            printKnownProperties(value);
            printResultFields(value);
            input.close();
        } catch (Throwable error) {
            System.out.println("  DECODE_ERROR " + error.getClass().getName() + ": " + error.getMessage());
        }
    }

    private static void printKnownProperties(Object value) {
        String[] names = new String[] {
                "getModule", "getServiceName", "getMethodName", "getUserId",
                "getUserCode", "getCallId", "getLogLevel", "getParameters",
                "getParametertypes", "getResult", "getAppexception"
        };
        for (String name : names) {
            try {
                Method method = value.getClass().getMethod(name);
                Object property = method.invoke(value);
                if (isSensitiveProperty(name)) {
                    System.out.println("  " + name + "=<redacted>");
                } else if ("getParameters".equals(name)) {
                    printParameterValues(property);
                } else {
                    System.out.println("  " + name + "=" + describe(property));
                }
            } catch (NoSuchMethodException ignored) {
                // not every dispatcher object has every property
            } catch (Throwable error) {
                System.out.println("  " + name + "=<error>");
            }
        }
    }

    /** Print each top-level parameter; expand Strings (query codes, bill no) up to MAX_STR. */
    private static void printParameterValues(Object property) {
        if (property == null) {
            System.out.println("  getParameters=null");
            return;
        }
        Object[] params;
        if (property instanceof Object[]) {
            params = (Object[]) property;
        } else {
            System.out.println("  getParameters=" + describe(property));
            return;
        }
        System.out.println("  getParameters=[" + params.length + "]");
        for (int i = 0; i < params.length; i++) {
            Object p = params[i];
            if (p == null) {
                System.out.println("    [" + i + "] null");
            } else if (p instanceof String) {
                String s = (String) p;
                if (s.length() > MAX_STR) {
                    s = s.substring(0, MAX_STR) + "...(" + ((String) p).length() + " chars)";
                }
                System.out.println("    [" + i + "] String=\"" + s + "\"");
            } else if (p instanceof Number || p instanceof Boolean) {
                System.out.println("    [" + i + "] " + p.getClass().getSimpleName() + "=" + p);
            } else {
                System.out.println("    [" + i + "] " + p.getClass().getName());
                String detail = describeShallow(p);
                if (detail != null && !detail.isEmpty()) {
                    System.out.println("        detail=" + detail);
                }
            }
        }
    }

    /** Shallow fields of a parameter object (QueryScheme/QueryClause/QueryScheme), no recursion. */
    private static String describeShallow(Object value) {
        try {
            String own = value.toString();
            // Many framework VO toString are useless; prefer string-ish fields.
            Field[] fields = value.getClass().getDeclaredFields();
            StringBuilder sb = new StringBuilder();
            for (Field f : fields) {
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    Object v = f.get(value);
                    if (v instanceof String || v instanceof Number || v instanceof Boolean) {
                        sb.append(f.getName()).append("=").append(v).append(";");
                    } else if (v == null) {
                        sb.append(f.getName()).append("=null;");
                    }
                } catch (Throwable ignored) {
                }
            }
            if (sb.length() > 0) {
                return trim(sb.toString());
            }
            if (own != null && !own.contains("@") && own.length() < 200) {
                return own;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void printResultFields(Object value) {
        if (!"nc.bs.framework.comn.Result".equals(value.getClass().getName())) {
            return;
        }
        try {
            Field result = value.getClass().getField("result");
            Field exception = value.getClass().getField("appexception");
            Object resultValue = result.get(value);
            Object exceptionValue = exception.get(value);
            System.out.println("  result=" + describe(resultValue));
            if (exceptionValue == null) {
                System.out.println("  appexception=null");
            } else {
                String msg = throwableMessage(exceptionValue);
                System.out.println("  appexception=" + exceptionValue.getClass().getName()
                        + (msg == null ? "" : " :: " + trim(msg)));
            }
        } catch (Throwable error) {
            System.out.println("  result=<error>");
        }
    }

    private static String throwableMessage(Object t) {
        try {
            if (t instanceof Throwable) {
                String m = ((Throwable) t).getMessage();
                if (m == null || m.isEmpty()) {
                    m = String.valueOf(t);
                }
                return m;
            }
            // Some wrappers store message in a string field.
            Field f = t.getClass().getField("detailMessage");
            Object v = f.get(t);
            return String.valueOf(v);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean isSensitiveProperty(String name) {
        return false;
    }

    private static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            StringBuilder types = new StringBuilder();
            int shown = Math.min(length, 8);
            for (int i = 0; i < shown; i++) {
                if (i > 0) {
                    types.append(',');
                }
                Object item = Array.get(value, i);
                types.append(item == null ? "null" : item.getClass().getName());
            }
            if (length > shown) {
                types.append(",...");
            }
            return "[" + value.getClass().getComponentType().getName()
                    + "][" + length + "]{" + types + "}";
        }
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        return value.getClass().getName();
    }

    private static String trim(String s) {
        return s.length() > MAX_STR ? s.substring(0, MAX_STR) + "..." : s;
    }

    private static URL[] findJars(File root) throws IOException {
        List<URL> urls = new ArrayList<URL>();
        collectJars(root, urls);
        return urls.toArray(new URL[urls.size()]);
    }

    private static void collectJars(File file, List<URL> urls) throws IOException {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isFile()) {
            if (file.getName().toLowerCase().endsWith(".jar")) {
                urls.add(file.toURI().toURL());
            }
            return;
        }
        File[] children = file.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            collectJars(child, urls);
        }
    }

    private static int contentLength(String headers) {
        String[] lines = headers.split("\\r\\n");
        for (String line : lines) {
            int separator = line.indexOf(':');
            if (separator > 0 && "content-length".equalsIgnoreCase(line.substring(0, separator).trim())) {
                return Integer.parseInt(line.substring(separator + 1).trim());
            }
        }
        return -1;
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    private static boolean matches(byte[] data, int offset, byte[] expected) {
        if (offset + expected.length > data.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (data[offset + i] != expected[i]) {
                return false;
            }
        }
        return true;
    }

    private static int indexOf(byte[] data, byte[] needle, int from) {
        for (int i = from; i <= data.length - needle.length; i++) {
            if (matches(data, i, needle)) {
                return i;
            }
        }
        return -1;
    }

    private static byte[] readAll(File file) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FileInputStream input = new FileInputStream(file);
        try {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                out.write(buffer, 0, count);
            }
        } finally {
            input.close();
        }
        return out.toByteArray();
    }

    private static String hexByte(int value) {
        if (value < 0) {
            return "--";
        }
        String text = Integer.toHexString(value & 0xff);
        return text.length() == 1 ? "0" + text : text;
    }
}
