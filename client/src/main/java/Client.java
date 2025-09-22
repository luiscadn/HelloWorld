import Demo.Response;
import Demo.PrinterPrx;
import com.zeroc.Ice.Communicator;
import com.zeroc.Ice.Util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;

public class Client {
    private static String resolveHostname() {
        try { return InetAddress.getLocalHost().getHostName(); }
        catch (Exception e) { String env = System.getenv("HOSTNAME"); return (env != null && !env.isBlank()) ? env : "unknown-host"; }
    }

    public static void main(String[] args) {
        int status = 0;
        try (Communicator communicator = Util.initialize(args)) {
            // Carga Printer.Proxy desde --Ice.Config=client/src/main/resources/config.client
            com.zeroc.Ice.ObjectPrx base = communicator.propertyToProxy("Printer.Proxy");
            PrinterPrx service = PrinterPrx.checkedCast(base);
            if (service == null) throw new Error("Invalid proxy");

            final String prefix = System.getProperty("user.name", "unknown-user") + ":" + resolveHostname() + ":";

            System.out.println("Client ready. Type commands; 'exit' to quit.");
            System.out.println("Prefix: " + prefix);

            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
                while (true) {
                    System.out.print("> ");
                    String line = br.readLine();
                    if (line == null || "exit".equalsIgnoreCase(line.trim())) break;
                    Response r = service.printString(prefix + line);
                    System.out.printf("Response:%n%s%n(%.2f ms)%n", r.value, (double) r.responseTime);
                }
            }
        } catch (Exception e) { e.printStackTrace(); status = 1; }
        System.exit(status);
    }
}
