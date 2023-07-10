package Snmp;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.io.IOException;
import java.util.*;

public class SnmpWalk {
    public SnmpWalk() {

    }

    public Set<String> snmpgetScalarV2(String ip, int port, String version, String oid, String communityString) {
        Set<String> res = new HashSet<>();
        Address address = GenericAddress.parse("udp:" + ip + "/" + port);
        CommunityTarget communityTarget = new CommunityTarget();// method creation  for communityTarget object
        communityTarget.setCommunity(new OctetString(communityString));
        communityTarget.setAddress(address);
        communityTarget.setVersion(1);

        communityTarget.setTimeout(2500L);
        communityTarget.setRetries(2);

        ResponseEvent responseEvent = null;

        try {
            Snmp snmp = null;
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oid)));
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            snmp.listen();
            pdu.setType(PDU.GET);
            responseEvent = snmp.send(pdu, communityTarget);
            PDU response = responseEvent.getResponse();
            if (response != null) {
                Iterator iterator = response.getVariableBindings().iterator();

                while (iterator.hasNext()) {
                    VariableBinding vb = (VariableBinding) iterator.next();
                    res.add(vb.getVariable().toString());
                }
            } else {
                System.out.println("Error");
            }
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception : --->" + e);
        }
        return res;
    }


    public Map<String, String> snmpGetTabularV2(String ip, int port, String oid, String communityString) {
        Address address = GenericAddress.parse("udp:" + ip + "/" + port);
        CommunityTarget communityTarget = new CommunityTarget();
        communityTarget.setCommunity(new OctetString(communityString));
        communityTarget.setAddress(address);
        communityTarget.setVersion(1);

        communityTarget.setTimeout(2500L);
        communityTarget.setRetries(2);
        Snmp snmp = null;
        LinkedHashMap res = new LinkedHashMap();

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
        } catch (Exception e) {
            System.out.println("Socket Exception");
        }

        try {
            snmp.listen();
        } catch (Exception e) {
            System.out.println("IO Exception");
        }

        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
        List events = treeUtils.getSubtree(communityTarget, new OID(oid));

        try {
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (events != null && events.size() != 0) {
            Iterator iterator = events.iterator();

            while (true) {
                while (true) {
                    TreeEvent event;
                    do {
                        if (!iterator.hasNext()) {
                            return res;
                        }

                        event = (TreeEvent) iterator.next();
                    } while (event == null);
                    if (event.isError()) {
                        System.out.println("OID Error " + oid + event.getErrorMessage());
                    } else {
                        VariableBinding[] variableBindings = event.getVariableBindings();
                        if (variableBindings != null && variableBindings.length != 0) {
                            VariableBinding[] variableBindings1 = variableBindings;
                            int var = variableBindings.length;

                            for (int var2 = 0; var2 < var; ++var2) {
                                VariableBinding var3 = variableBindings1[var2];
                                if (var3 != null) {
                                    res.put("\n" + var3.getOid().toString() + " ", " " + var3.getVariable().toString());
                                }
                            }
                        }
                    }

                }
            }
        } else {
            System.out.println("Error reading DATA");
            return res;
        }
    }

    public Set<String> snmpGetScalarV3(String ip, int port, String oid, String userName, String authPassphrase, String privPassphrase) {
        String targetAddress = "udp:" + ip + "/" + port;
        OID authProtocol = AuthSHA.ID;
        OID privProtocol = PrivAES128.ID;
        ScopedPDU reqPDU = new ScopedPDU();
        reqPDU.add(new VariableBinding(new OID(oid)));
        reqPDU.setType(PDU.GET);
        UserTarget target = new UserTarget();
        target.setTimeout(3000L);
        target.setVersion(3);
        Set<String> res = new HashSet<>();

        target.setAddress(GenericAddress.parse(targetAddress));
        target.setSecurityLevel(3);
        target.setSecurityName(new OctetString(userName));

        ResponseEvent responseEvent = null;

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);

            snmp.getUSM().addUser(new OctetString(userName), new UsmUser(new OctetString(userName), authProtocol, new OctetString(authPassphrase), privProtocol, new OctetString(privPassphrase)));

            transport.listen();

            responseEvent = snmp.send(reqPDU, target);
            PDU response = responseEvent.getResponse();
            if (response != null) {
                Iterator iterator = response.getVariableBindings().iterator();

                while (iterator.hasNext()) {
                    VariableBinding vb = (VariableBinding) iterator.next();
                    res.add(vb.getVariable().toString());
                }
            } else {
                System.out.println("Error");
            }
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception : --->" + e);
        }
        return res;
    }

    public Map<String, String> snmpGetTabularV3(String ip, int port, String oid, String userName, String authPassphrase, String privPassphrase, String auth_type, String priv_type) {
        String targetAddress = "udp:" + ip + "/" + port;
        OID authProtocol = null;
        OID privProtocol = null;

        if (auth_type.equalsIgnoreCase("sha")) {
            authProtocol = AuthSHA.ID;
        } else if (auth_type.equalsIgnoreCase("md5")) {
            authProtocol = AuthMD5.ID;

        }
        if (priv_type.equalsIgnoreCase("des")) {
            privProtocol = PrivDES.ID;
        } else {
            privProtocol = PrivAES128.ID;
        }


        UserTarget target = new UserTarget();
        target.setVersion(3);
        target.setTimeout(5000L);
        target.setAddress(GenericAddress.parse(targetAddress));
        target.setSecurityLevel(3);
        target.setSecurityName(new OctetString(userName));
        Map<String, String> res = new HashMap<>();

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);

            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            snmp.getUSM().addUser(new OctetString(userName), new UsmUser(new OctetString(userName), authProtocol, new OctetString(authPassphrase), privProtocol, new OctetString(privPassphrase)));

            transport.listen();
            TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory(PDU.GET));
            List events = treeUtils.getSubtree(target, new OID(oid));
            snmp.close();
            if (events == null || events.size() == 0) {
                System.out.println("Error: Unable to read table...");
            }

            Iterator iterator = events.iterator();
            while (true) {
                while (true) {
                    TreeEvent event;
                    do {
                        if (!iterator.hasNext()) {
                            return res;
                        }

                        event = (TreeEvent) iterator.next();
                    } while (event == null);

                    if (event.isError()) {
                        System.out.println("OID Error " + event.getErrorMessage());
                    } else {
                        VariableBinding[] varBindings = event.getVariableBindings();
                        if (varBindings != null && varBindings.length != 0) {
                            VariableBinding[] var1 = varBindings;
                            int var = varBindings.length;

                            for (int var2 = 0; var2 < var; ++var2) {
                                VariableBinding variableBinding = var1[var2];
                                if (variableBinding != null) {
                                    res.put("\n" + variableBinding.getOid().toString() + " ", " " + variableBinding.getVariable().toString());
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return res;
        }
    }

    public Map<String, String> doBulkforV2(String ip, int port, String communityString, String vbs, int count) throws IOException {

        OID oid = new OID(vbs);
        Map<String, String> result = new HashMap<>();

        Snmp snmp = null;

        try {
            Address address = GenericAddress.parse("udp:" + ip + "/" + port);

            CommunityTarget communityTarget = new CommunityTarget();
            communityTarget.setCommunity(new OctetString(communityString));
            communityTarget.setAddress(address);
            communityTarget.setVersion(1);
            communityTarget.setTimeout(3000L);
            communityTarget.setRetries(3);

            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            transport.listen();
            PDU pdu = new PDU();
            pdu.setType(PDU.GETBULK);
            pdu.setMaxRepetitions(count);
            pdu.setNonRepeaters(0);
            pdu.add(new VariableBinding(oid));
            ResponseEvent responseEvent = snmp.send(pdu, communityTarget);
            PDU response = responseEvent.getResponse();
            if (response != null) {
                Iterator iterator = response.getVariableBindings().iterator();

                while (iterator.hasNext()) {
                    VariableBinding variableBinding = (VariableBinding) iterator.next();
                    result.put("\n" + variableBinding.getOid().toString() + " ", " " + variableBinding.getVariable().toString());

                }
            } else {
                System.out.println("Error");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (snmp != null)
                snmp.close();
        }

        return result;
    }


    public Map<String,String> doBulkforV3(String ip, int port, String userName, String authPassphrase, String privPassphrase, String auth_type, String priv_type,String vbs,int count) {
        OID oid = new OID(vbs);
        Map<String, String> result = new HashMap<>();

        String address = "udp:" + ip + "/" + port;

        OID authProtocol = null;
        OID privProtocol = null;

        if (auth_type.equalsIgnoreCase("sha")) {
            authProtocol = AuthSHA.ID;
        } else {
            authProtocol = AuthMD5.ID;
        }

        if (priv_type.equalsIgnoreCase("des")) {
            privProtocol = PrivDES.ID;
        } else {
            privProtocol = PrivAES128.ID;
        }

        UserTarget target = new UserTarget();
        target.setTimeout(5000L);
        target.setVersion(3);
        target.setAddress(GenericAddress.parse(address));
        target.setSecurityLevel(3);
        target.setSecurityName(new OctetString(userName));

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            snmp.getUSM().addUser(new OctetString(userName), new UsmUser(new OctetString(userName), authProtocol, new OctetString(authPassphrase), privProtocol, new OctetString(privPassphrase)));

            transport.listen();
            PDU pdu = new ScopedPDU();
            pdu.setType(PDU.GETBULK);
            pdu.setMaxRepetitions(count);
            pdu.setNonRepeaters(0);
            pdu.add(new VariableBinding(oid));
            ResponseEvent responseEvent = snmp.send(pdu, target);
            PDU response = responseEvent.getResponse();

            if (response != null) {
                Iterator iterator = response.getVariableBindings().iterator();

                while (iterator.hasNext()) {
                    VariableBinding variableBinding = (VariableBinding) iterator.next();
                    result.put("\n" + variableBinding.getOid().toString() + " ", " " + variableBinding.getVariable().toString());

                }
            } else {
                System.out.println("Error");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
}
