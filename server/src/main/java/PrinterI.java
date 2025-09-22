import Demo.Response;
import com.zeroc.Ice.Current;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrinterI implements Demo.Printer {

    private static final Pattern INT_POS = Pattern.compile("^\\d+$");
    private static final Pattern LISTPORTS = Pattern.compile("^listports\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})\\s*$");
    private static final Pattern IPV4 =
            Pattern.compile("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$");
    private static final Set<String> CMD_WHITELIST = Set.of(
            "whoami","uname","uptime","date","id","hostname","ls",
            "ver","whoami.exe","hostname.exe","ipconfig.exe"
    );
    private static final Pattern FORBIDDEN_TOKENS = Pattern.compile("[;&|><`$]");

    @Override
    public Response printString(String s, Current current) {
        long t0 = System.nanoTime();
        String value;
        try {
            Parsed p = parsePrefixedPayload(s);
            String prefix = p.username + ":" + p.hostname + ":";
            String payload = p.payload;

            if (INT_POS.matcher(payload).matches()) {
                int n = Integer.parseInt(payload);
                if (n < 0) throw new IllegalArgumentException("n debe ser >= 0");
                if (n > 92) throw new IllegalArgumentException("n máximo 92");
                java.util.List<Long> fib = fibonacci(n);
                long ln = Long.parseLong(payload);
                String factors = primeFactorization(ln);
                System.out.println(prefix + " " + fib);
                value = "Factores primos de " + ln + ": " + factors;

            } else if (payload.startsWith("listifs")) {
                String ifs = listInterfaces();
                System.out.println(prefix + " " + summarize(ifs));
                value = ifs;

            } else if (payload.startsWith("listports")) {
                Matcher m = LISTPORTS.matcher(payload);
                if (!m.matches()) value = "Uso: listports <IPv4>";
                else {
                    String ip = m.group(1);
                    String report = scanTcpPorts(ip, 1, 1024, 1000);
                    System.out.println(prefix + " " + summarize(report));
                    value = report;
                }

            } else if (payload.startsWith("!")) {
                String cmd = payload.substring(1).trim();
                String out = execWhitelisted(cmd, Duration.ofSeconds(3));
                System.out.println(prefix + " " + summarize(out));
                value = out;

            } else {
                value = "Echo: " + payload + "\nComandos: <n>, listifs, listports <IPv4>, !<cmd>";
                System.out.println(prefix + " " + summarize(payload));
            }

        } catch (Exception e) {
            value = "Error: " + e.getMessage();
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        Response r = new Response();
        r.value = value;
        r.responseTime = elapsedMs;
        return r;
    }

    // ===== Helpers =====
    private static class Parsed { final String username, hostname, payload;
        Parsed(String u, String h, String p) { this.username=u; this.hostname=h; this.payload=p; } }

    private static Parsed parsePrefixedPayload(String s) {
        if (s == null) throw new IllegalArgumentException("Mensaje vacío");
        int i1 = s.indexOf(':'); int i2 = (i1 >= 0) ? s.indexOf(':', i1 + 1) : -1;
        if (i1 < 0 || i2 < 0) throw new IllegalArgumentException("Formato inválido. Se espera username:hostname:payload");
        String user = s.substring(0, i1), host = s.substring(i1 + 1, i2), payload = s.substring(i2 + 1).trim();
        if (user.isBlank() || host.isBlank()) throw new IllegalArgumentException("Prefijo inválido (username/hostname vacíos)");
        return new Parsed(user, host, payload);
    }

    private static String summarize(String text) {
        if (text == null) return "";
        String one = text.replace("\r","").replace("\n"," ");
        return one.length() > 120 ? one.substring(0,117) + "..." : one;
    }

    private static java.util.List<Long> fibonacci(int n) {
        java.util.List<Long> seq = new java.util.ArrayList<>(n);
        if (n == 0) return seq;
        long a = 0L, b = 1L; seq.add(a); if (n == 1) return seq; seq.add(b);
        for (int i = 2; i < n; i++) { long c = a + b; seq.add(c); a = b; b = c; }
        return seq;
    }

    private static String primeFactorization(long n) {
        if (n <= 1) return String.valueOf(n);
        StringBuilder sb = new StringBuilder(); long num = n; int count;
        count = 0; while ((num & 1) == 0) { num >>= 1; count++; } if (count > 0) appendFactor(sb, 2, count);
        for (long f = 3; f * f <= num; f += 2) {
            count = 0; while (num % f == 0) { num /= f; count++; }
            if (count > 0) appendFactor(sb, f, count);
        }
        if (num > 1) appendFactor(sb, num, 1);
        return sb.toString();
    }
    private static void appendFactor(StringBuilder sb, long factor, int exp) {
        if (sb.length() > 0) sb.append(" * "); sb.append(factor); if (exp > 1) sb.append("^").append(exp);
    }

    private static String listInterfaces() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            if (ifs == null) return "No hay interfaces";
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                boolean up = false; try { up = ni.isUp(); } catch (Exception ignored) {}
                sb.append(ni.getName()).append(" (").append(ni.getDisplayName()).append(") - ").append(up ? "UP" : "DOWN").append("\n");
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress ia = addrs.nextElement();
                    String ver = (ia instanceof Inet4Address) ? "IPv4" : (ia instanceof Inet6Address) ? "IPv6" : "IP";
                    sb.append("  ").append(ver).append(": ").append(ia.getHostAddress()).append("\n");
                }
            }
        } catch (Exception e) { return "Error listando interfaces: " + e.getMessage(); }
        return sb.toString().trim();
    }

    private static String scanTcpPorts(String ip, int start, int end, int timeoutMs) {
        if (ip == null || !IPV4.matcher(ip).matches()) return "IPv4 inválida";
        if (start < 1 || end > 1024 || start > end) return "Rango inválido 1–1024";
        if (timeoutMs < 200 || timeoutMs > 5000) return "Timeout inválido (200–5000 ms)";
        Map<Integer, String> wellKnown = wellKnownPorts();
        StringBuilder sb = new StringBuilder();
        for (int port = start; port <= end; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), timeoutMs);
                sb.append(port);
                String svc = wellKnown.get(port);
                if (svc != null) sb.append(" (").append(svc).append(")");
                sb.append(" OPEN\n");
            } catch (Exception ignored) {}
        }
        return sb.length() == 0 ? "No se detectaron puertos abiertos en el rango." : sb.toString().trim();
    }

    private static Map<Integer, String> wellKnownPorts() {
        Map<Integer, String> m = new HashMap<>();
        m.put(20,"FTP-data"); m.put(21,"FTP"); m.put(22,"SSH"); m.put(23,"Telnet"); m.put(25,"SMTP"); m.put(53,"DNS");
        m.put(67,"DHCP"); m.put(68,"DHCP"); m.put(80,"HTTP"); m.put(110,"POP3"); m.put(123,"NTP"); m.put(143,"IMAP");
        m.put(161,"SNMP"); m.put(389,"LDAP"); m.put(443,"HTTPS"); m.put(631,"IPP"); m.put(993,"IMAPS"); m.put(995,"POP3S");
        return m;
    }

    private static String execWhitelisted(String cmdLine, Duration timeout) {
        if (cmdLine == null || cmdLine.isBlank()) return "Comando vacío";
        if (FORBIDDEN_TOKENS.matcher(cmdLine).find()) return "Token peligroso detectado";
        String[] tokens = cmdLine.trim().split("\\s+");
        String cmd = tokens[0];
        if (!CMD_WHITELIST.contains(cmd)) return "Comando no permitido: " + cmd;
        java.util.List<String> args = new java.util.ArrayList<>(); args.add(cmd);
        for (int i=1;i<tokens.length;i++){ if(tokens[i].length()>128) return "Argumento demasiado largo"; args.add(tokens[i]); }
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.environment().putIfAbsent("PATH","/usr/bin:/bin:/usr/sbin:/sbin");
        pb.redirectErrorStream(true);
        StringBuilder out = new StringBuilder();
        try {
            Process p = pb.start();
            boolean finished = p.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
            if (!finished) { p.destroyForcibly(); return "Timeout ejecutando comando"; }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line; while ((line = br.readLine()) != null) {
                    if (out.length() + line.length() > 2000) { out.append("\n...[truncado]..."); break; }
                    out.append(line).append("\n");
                }
            }
            out.append("(exitcode=").append(p.exitValue()).append(")");
            return out.toString().trim();
        } catch (Exception e) { return "Error ejecutando comando: " + e.getMessage(); }
    }
}
