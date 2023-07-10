package Snmp;

import org.snmp4j.*;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException; // importing the necessary classes and packages...

public class TrapReceiver implements CommandResponder { // creating class  called trap receiver that impliments the commandResponder interface


    public synchronized void listen(UdpAddress address) throws IOException {

        DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping((UdpAddress) address);


        ThreadPool threadPool = ThreadPool.create("Trap", 10);
        MessageDispatcher mDispathcher = new MultiThreadedMessageDispatcher(
                threadPool, new MessageDispatcherImpl());

        mDispathcher.addMessageProcessingModel(new MPv2c());

        SecurityProtocols.getInstance().addDefaultProtocols();

        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));

        Snmp snmp = new Snmp( transport);
        snmp.addCommandResponder(this);

        transport.listen();
        System.out.println("Listening on " + address);

        try {
            this.wait();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }


    @Override
    public  synchronized void processPdu(CommandResponderEvent cmdRespEvent) {
        PDU pdu = cmdRespEvent.getPDU();
        if (pdu != null) {
            System.out.println("Trap Type = " + pdu.getType());
            System.out.println("Variables = " + pdu.getVariableBindings());
        }
    }

}
