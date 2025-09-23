package demo;
import com.zeroc.Ice.*;

public class Server {
    public static void main(String[] args) {
        int status = 0;
        try (Communicator communicator = Util.initialize(args)) {
            ObjectAdapter adapter = communicator.createObjectAdapter("SimplePrinter");
            adapter.add(new PrinterI(), Util.stringToIdentity("SimplePrinter"));
            adapter.activate();
            System.out.println("Servidor listo.");
            communicator.waitForShutdown();
        } catch (java.lang.Exception e) {
            e.printStackTrace();
            status = 1;
        }
        System.exit(status);
    }
}
