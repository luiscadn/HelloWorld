import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class ServerUtils {

    private ServerUtils() {}

    // ====== 2a) Fibonacci y factores primos ======
    public static List<Long> fibonacci(int n) {
        if (n < 0) throw new IllegalArgumentException("n debe ser >= 0");
        if (n > 92) throw new IllegalArgumentException("n máximo 92 (long)");
        List<Long> seq = new ArrayList<>(n);
        if (n == 0) return seq;
        long a = 0L, b = 1L;
        seq.add(a);
        if (n == 1) return seq;
        seq.add(b);
        for (int i = 2; i < n; i++) {
            long c = a + b;
            seq.add(c);
            a = b; b = c;
        }
        return seq;
    }

    public static String primeFactorization(long n) {
        if (n <= 1) return String.valueOf(n);
        StringBuilder sb = new StringBuilder();
        long num = n;
        int count;

        count = 0;
        while ((num & 1) == 0) { num >>= 1; count++; }
        if (count > 0) appendFactor(sb, 2, count);

        for (long f = 3; f * f <= num; f += 2) {
            count = 0;
            while (num % f == 0) { num /= f; count++; }
            if (count > 0) appendFactor(sb, f, count);
        }
        if (num > 1) appendFactor(sb, num, 1);

        return sb.toString();
    }

    private static void appendFactor(StringBuilder sb, long factor, int exp) {
        if (sb.length() > 0) sb.append(" * ");
        sb.append(factor);
        if (exp > 1) sb.append("^").append(exp);
    }

    // ====== 2b) listifs ======
    public static String listInterfaces() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            if (ifs == null) return "No hay interfaces";
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                boolean up = false;
                try { up = ni.isUp(); } catch (Exception ignored) {}
                sb.append(ni.getName()).append(" (").append(ni.getDisplayName()).append(") - ");
                sb.append(up ? "UP" : "DOWN");
                sb.append("\n");
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress ia = addrs.nextElement();
                    String ver = (ia instanceof Inet4Address) ? "IPv4" :
                                 (ia instanceof Inet6Address) ? "IPv6" : "IP";
                    sb.append("  ").append(ver).append(": ").append(ia.getHostAddress()).append("\n");
                }
            }
        } catch (Exception e) {
            return "Error listando interfaces: " + e.getMessage();
        }
        return sb.toString().trim();
    }

    // ====== 2c) listports <IPv4> ======
    private static final Pattern IPV4 =
            Pattern.compile("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$");

    public static String scanTcpPorts(String ip, int start, int end, int timeoutMs) {
        if (ip == null || !IPV4.matcher(ip).matches()) {
            return "IPv4 inválida";
        }
        if (start < 1 || end > 1024 || start > end) {
            return "Rango de puertos inválido (use 1–1024)";
        }
        if (timeoutMs < 200 || timeoutMs > 5000) {
            return "Timeout inválido (200–5000 ms)";
        }
        Map<Integer, String> wellKnown = wellKnownPorts();
        StringBuilder sb = new StringBuilder();
        for (int port = start; port <= end; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), timeoutMs);
                socket.close();
                sb.append(port);
                String svc = wellKnown.get(port);
                if (svc != null) sb.append(" (").append(svc).append(")");
                sb.append(" OPEN\n");
            } catch (Exception ignored) {
            }
        }
        if (sb.length() == 0) return "No se detectaron puertos abiertos en el rango.";
        return sb.toString().trim();
    }

    private static Map<Integer, String> wellKnownPorts() {
        Map<Integer, String> m = new HashMap<>();
        m.put(20, "FTP-data"); m.put(21, "FTP"); m.put(22, "SSH"); m.put(23, "Telnet");
        m.put(25, "SMTP"); m.put(53, "DNS"); m.put(67, "DHCP"); m.put(68, "DHCP");
        m.put(80, "HTTP"); m.put(110, "POP3"); m.put(123, "NTP"); m.put(143, "IMAP");
        m.put(161, "SNMP"); m.put(389, "LDAP"); m.put(443, "HTTPS"); m.put(631, "IPP");
        m.put(993, "IMAPS"); m.put(995, "POP3S");
        return m;
    }

    // ====== 2d) !comando (whitelist, sin shell) ======
    private static final Set<String> CMD_WHITELIST = Set.of(
            "whoami", "uname", "uptime", "date", "id", "hostname", "ls",
            "ver", "whoami.exe", "hostname.exe", "ipconfig.exe"
    );

    private static final Pattern FORBIDDEN_TOKENS = Pattern.compile("[;&|><`$]");

    public static String execWhitelisted(String cmdLine, Duration timeout) {
        if (cmdLine == null || cmdLine.isBlank()) return "Comando vacío";
        if (FORBIDDEN_TOKENS.matcher(cmdLine).find()) return "Token peligroso detectado";

        String[] tokens = cmdLine.trim().split("\\s+");
        String cmd = tokens[0];
        if (!CMD_WHITELIST.contains(cmd)) {
            return "Comando no permitido: " + cmd;
        }
        List<String> args = new ArrayList<>();
        args.add(cmd);
        for (int i = 1; i < tokens.length; i++) {
            if (tokens[i].length() > 128) return "Argumento demasiado largo";
            args.add(tokens[i]);
        }

        ProcessBuilder pb = new ProcessBuilder(args);
        Map<String, String> env = pb.environment();
        env.putIfAbsent("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

        pb.redirectErrorStream(true);
        StringBuilder out = new StringBuilder();
        try {
            Process p = pb.start();
            boolean finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                return "Timeout ejecutando comando";
            }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (out.length() + line.length() > 2000) { 
                        out.append("\n...[truncado]...");
                        break;
                    }
                    out.append(line).append("\n");
                }
            }
            int code = p.exitValue();
            out.append("(exitcode=").append(code).append(")");
            return out.toString().trim();
        } catch (Exception e) {
            return "Error ejecutando comando: " + e.getMessage();
        }
    }
}
