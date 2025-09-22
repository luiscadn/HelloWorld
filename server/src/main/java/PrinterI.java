import Demo.Response;
import Demo.Printer;
import com.zeroc.Ice.Current;
import java.time.Duration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class PrinterI implements Printer {

    private static final Pattern INT_POS = Pattern.compile("^\\d+$");
    private static final Pattern LISTPORTS = Pattern.compile("^listports\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})\\s*$");
    private static final int DEFAULT_PORT_START = 1;
    private static final int DEFAULT_PORT_END = 1024;
    private static final int DEFAULT_TIMEOUT_MS = 1000;

    @Override
    public Response printString(String s, Current current) {
        long t0 = System.nanoTime();
        String value;
        try {
            Parsed p = parsePrefixedPayload(s);
            String prefix = p.username + ":" + p.hostname + ":";
            String payload = p.payload;

            if (INT_POS.matcher(payload).matches()) {
                // 2a) entero positivo
                int n = safeParseInt(payload);
                if (n < 0) throw new IllegalArgumentException("n debe ser >= 0");
                if (n > 92) throw new IllegalArgumentException("n máximo 92");

                List<Long> fib = ServerUtils.fibonacci(n);
                String fibStr = fib.toString();

                long ln = Long.parseLong(payload);
                String factors = ServerUtils.primeFactorization(ln);

                System.out.println(prefix + " " + fibStr);

                value = "Factores primos de " + ln + ": " + factors;

            } else if (payload.startsWith("listifs")) {
                // 2b) interfaces
                String ifs = ServerUtils.listInterfaces();
                System.out.println(prefix + " " + summarize(ifs));
                value = ifs;

            } else if (payload.startsWith("listports")) {
                // 2c) escaneo de puertos
                Matcher m = LISTPORTS.matcher(payload);
                if (!m.matches()) {
                    value = "Uso: listports <IPv4>";
                } else {
                    String ip = m.group(1);
                    String report = ServerUtils.scanTcpPorts(ip, DEFAULT_PORT_START, DEFAULT_PORT_END, DEFAULT_TIMEOUT_MS);
                    System.out.println(prefix + " " + summarize(report));
                    value = report;
                }

            } else if (payload.startsWith("!")) {
                // 2d) comando whitelisteado
                String cmd = payload.substring(1).trim();
                String out = ServerUtils.execWhitelisted(cmd, Duration.ofSeconds(3));
                System.out.println(prefix + " " + summarize(out));
                value = out;

            } else {
                value = "Echo: " + payload + "\n" +
                        "Comandos: <n>, listifs, listports <IPv4>, !<cmd>";
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

    private static int safeParseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            throw new IllegalArgumentException("Entero inválido");
        }
    }

    private static String summarize(String text) {
        if (text == null) return "";
        String one = text.replace("\r", "").replace("\n", " ");
        return one.length() > 120 ? one.substring(0, 117) + "..." : one;
    }

    private static class Parsed {
        final String username;
        final String hostname;
        final String payload;
        Parsed(String u, String h, String p) { this.username = u; this.hostname = h; this.payload = p; }
    }

    /**
     * Espera "username:hostname:payload".
     * Tolerante a colones extra en payload (solo separa los **primeros dos** ':').
     */
    private static Parsed parsePrefixedPayload(String s) {
        if (s == null) throw new IllegalArgumentException("Mensaje vacío");
        int i1 = s.indexOf(':');
        int i2 = (i1 >= 0) ? s.indexOf(':', i1 + 1) : -1;
        if (i1 < 0 || i2 < 0) {
            throw new IllegalArgumentException("Formato inválido. Se espera username:hostname:payload");
        }
        String user = s.substring(0, i1);
        String host = s.substring(i1 + 1, i2);
        String payload = s.substring(i2 + 1).trim();
        if (user.isBlank() || host.isBlank()) {
            throw new IllegalArgumentException("Prefijo inválido (username/hostname vacíos)");
        }
        return new Parsed(user, host, payload);
    }
}
