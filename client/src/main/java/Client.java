import Demo.Response;
import Demo.PrinterPrx;
import com.zeroc.Ice.Communicator;
import com.zeroc.Ice.Util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;

public class Client {
    private static String resolveHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            String env = System.getenv("HOSTNAME");
            return (env != null && !env.isBlank()) ? env : "unknown-host";
        }
    }

    public static void main(String[] args) {
        int status = 0;
        try (Communicator communicator = Util.initialize(args)) {

            com.zeroc.Ice.ObjectPrx base = communicator.propertyToProxy("Printer.Proxy");
            PrinterPrx printer = PrinterPrx.checkedCast(base);
            if (printer == null) {
                throw new Error("Invalid proxy");
            }

            final String username = System.getProperty("user.name", "unknown-user");
            final String hostname = resolveHostname();
            final String prefix = username + ":" + hostname + ":";

            System.out.println("Cliente listo. Escribe mensajes; 'exit' para salir.");
            System.out.println("Prefijo automático: " + prefix);

            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
                while (true) {
                    System.out.print("> ");
                    String line = br.readLine();
                    if (line == null) break;
                    if ("exit".equalsIgnoreCase(line.trim())) {
                        System.out.println("Saliendo…");
                        break;
                    }
                    String payload = prefix + line;
                    Response r = printer.printString(payload);
                    double ms = (double) r.responseTime; 
                    System.out.printf("Respuesta:\n%s\n(%.2f ms)\n", r.value, ms);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            status = 1;
        }
        System.exit(status);
    }
}
