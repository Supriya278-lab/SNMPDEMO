package Snmp;


import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.util.TreeEvent;

import java.io.IOException;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class MainClass {

    public static void main(String[] args) throws IOException {
//        Scanner s = new Scanner(System.in);
//        SnmpWalk snmpWalk = new SnmpWalk();
//        System.out.println("Results for SNMP V2C");
//        System.out.println("***************************************************");
//        Set<String> getV2=snmpWalk.snmpgetScalarV2("10.2.40.50",161,"2c","1.3.6.1.2.1.1.5.0","public");
//        System.out.println("cisco snmp"+getV2);
//        Map<String,String> getV2Tabular=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1","public");
//        System.out.println(getV2Tabular);
//          Map<String,String> getV2Tabular7=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.3","public");
//        System.out.println(getV2Tabular7);
//
//      Map<String,String> getV2Tabular2=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.2","public");
//       System.out.println(getV2Tabular2);
//       Map<String,String> getV2Tabular6=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.8","public");
//       System.out.println(getV2Tabular6);
//       Map<String,String> getV2Tabular3=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1.3.6.1.2.1.17.4.3.1.1","public");
//     System.out.println(getV2Tabular3);
//       Map<String,String> getV2Tabular4=snmpWalk.snmpGetTabularV2("10.2.40.50",161,"1.3.6.1.2.1.17.4.3.1.2","public");
//        System.out.println(getV2Tabular4);
//
//       Map<String,String> getV2Tabular5=snmpWalk.snmpGetTabularV2("10.2.40.50",161,".1.3.6.1.2.1.17.1.4.1.2","public");
//        System.out.println(getV2Tabular5);
//        //.....................................
//       System.out.println("***************************************************");
//       System.out.println();
//       System.out.println("Results for SNMP V3");
//       System.out.println("***************************************************");
//        Set<String> getV3 = snmpWalk.snmpGetScalarV3("10.2.40.50",161,"1.3.6.1.2.1.1.5.0","testuser","Password123","Password123");
//        System.out.println(getV3);
//        Map<String,String> getV3Tabular=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.1","testuser","Password123","Password123","md5","des");
//       System.out.println(getV3Tabular);
//       Map<String,String> getV3Tabular2=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.2","testuser","Password123","Password123","md5","des");
//       System.out.println(getV3Tabular2);
//        Map<String,String> getV3Tabular3=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.2.2.1.8","testuser","Password123","Password123","md5","des");
//        System.out.println(getV3Tabular3);
//        Map<String,String> getV3Tabular4=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.17.4.3.1.1","testuser","Password123","Password123","sha","aes");
//        System.out.println(getV3Tabular4);
//        Map<String,String> getV3Tabular5=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.17.4.3.1.2","testuser","Password123","Password123","sha","aes");
//       System.out.println(getV3Tabular5);
//        Map<String,String> getV3Tabular6=snmpWalk.snmpGetTabularV3("10.2.40.50",161,"1.3.6.1.2.1.17.1.4.1.2","testuser","Password123","Password123","sha","aes");
//        System.out.println(getV3Tabular6);
//
//        System.out.println("***************************************************");
//
//      Map<String,String> bulkgetV2 = snmpWalk.doBulkforV2("10.2.40.50",161,"public","1",10);
//      System.out.println("Results for bulk Version 2 \n \n"+bulkgetV2);
//      System.out.println("***************************************************");
//
//    Map<String,String> bulkgetV3 = snmpWalk.doBulkforV3("10.2.40.50",161,"testuser","Password123","Password123","md5","des","1",15);
//       System.out.println("Results for bulk Version 3 with MD5 And DES \n \n"+bulkgetV3);
//       System.out.println("***************************************************");
//     Map<String,String> bulkgetV3sha = snmpWalk.doBulkforV3("10.2.40.50",161,"testuser","Password123","Password123","sha","aes","1",15);
//       System.out.println("Results for bulk Version 3 with SHA And AES \n \n"+bulkgetV3sha);
//       System.out.println("***************************************************");


     TrapReceiver snmp4jTrapReceiver = new TrapReceiver();
   try {
        snmp4jTrapReceiver.listen(new UdpAddress("192.168.60.100/162"));
  } catch (IOException e) {
        e.printStackTrace();
    }


    }
}
