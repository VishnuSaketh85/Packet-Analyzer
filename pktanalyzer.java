import java.io.IOException;
import java.nio.file.*;
import java.util.Map;

//0a00 07eb 7b54 10dc 4817 0303 00c3 0000       '....{T..H.......'
/**
 * The pktanalyzer program implements an application that
 * reads in a packet(binary file) and produces a detailed
 * summary of that packet. That packet can be with ICMP, TCP or UDP.
 *
 * @author  Byreddy Vishnu
 * @version 1.0
 * @since   2020-09-04
 */
public class pktanalyzer {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray(); // a hex map where index represents the
    // value of the character present at that index
    private final static Map<Integer, String> protocolMap = Map.of(1, "ICMP", 6, "TCP", 17,
            "UDP");
    static int optionsLength = 0; // to check if options exist in IP header
    static int tcpOptionsLength = 0; // to check if options exits in TCP header

    /**
     * This is the main method reads in a packet and stores it in byte array. It then converts the
     * byte array to a hex string. It then calls several other methods to print the different headers
     * of the packet.
     * @param args input file name.
     * @return void
     * @exception IOException On input error
     */
    public static void main(String[] args){
        String inputFile = args[0];
        try {
            byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
            String data = bytesToHex(inputBytes);
            printEtherHeader(data, inputBytes);
            int protocol = printIPHeader(data);
            if(protocolMap.get(protocol).equals("ICMP")){
                printICMP(data);
            }
            else if(protocolMap.get(protocol).equals("TCP")){
                printTCPHeader(data);
                printData(data, 108 + (optionsLength*2), "TCP:   ");
            }
            else if(protocolMap.get(protocol).equals("UDP")){
                printUDPHeader(data);
                printData(data, 84 + (optionsLength*2), "UDP:   ");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is converts a byte array to hex string using binary operations
     * @param inputBytes the entire data in bytes
     * @return string which represents the input bytes in hex.
     */
    public static String bytesToHex(byte[] inputBytes) {
        char[] hexChars = new char[inputBytes.length * 2];
        for ( int j = 0; j < inputBytes.length; j++ ) {
            hexChars[j * 2] = hexArray[(inputBytes[j] >> 4) & 0xF];
            hexChars[j * 2 + 1] = hexArray[inputBytes[j] & 0xF];
        }
        return new String(hexChars);
    }

    /**
     * This method is used to print the ICMP header.
     * @param data the entire data in hex
     * @return void.
     */
    public static void printICMP(String data){
        String icmpHeader = data.substring(68 + (optionsLength*2), 76 + (optionsLength*2)).toLowerCase();
        System.out.println("ICMP:   ----- ICMP Header -----");
        System.out.println("ICMP:");
        System.out.println("ICMP:   Type = " + hexToDecimal(icmpHeader.substring(0, 2)) );
        System.out.println("ICMP:   Code = " + hexToDecimal(icmpHeader.substring(2, 4)) );
        System.out.println("ICMP:   Checksum = 0x" + icmpHeader.substring(4, 8) );
        System.out.println("ICMP:");
    }

    /**
     * This method is used to print the UDP header.
     * @param data the entire data in hex
     * @return void.
     */
    public static void printUDPHeader(String data){
        String udpHeader = data.substring(68 + (optionsLength*2), 84 + (optionsLength*2)).toLowerCase();
        System.out.println("UDP:   ----- UDP Header -----");
        System.out.println("UDP:");
        System.out.println("UDP:   Source port = " + hexToDecimal(udpHeader.substring(0, 4)));
        System.out.println("UDP:   Destination port = " + hexToDecimal(udpHeader.substring(4, 8)));
        System.out.println("UDP:   Length = " + hexToDecimal(udpHeader.substring(8, 12)));
        System.out.println("UDP:   Checksum = 0x" + udpHeader.substring(12, 16));
        System.out.println("UDP:");
        System.out.println("UDP:   Data: (first 64 bytes)");
    }

    /**
     * This method is used to print the TCP header.
     * @param data the entire data in hex
     * @return void.
     */
    public static void printTCPHeader(String data){
        String tcpHeader = data.substring(68 + (optionsLength*2), 108 + (optionsLength*2)).toLowerCase();
        System.out.println("TCP:   ----- TCP Header -----");
        System.out.println("TCP:");
        System.out.println("TCP:   Source port = " + hexToDecimal(tcpHeader.substring(0, 4)));
        System.out.println("TCP:   Destination port = " + hexToDecimal(tcpHeader.substring(4, 8)));

        System.out.println("TCP:   Sequence number = " + hexToDecimal(tcpHeader.substring(8, 16)));
        System.out.println("TCP:   Acknowledgement number = " + hexToDecimal(tcpHeader.substring(16, 24)));
        int[] bits = decToBinary(hexToDecimal(tcpHeader.substring(26, 28)));
        int offset = Integer.parseInt(tcpHeader.substring(24,25));
        if(offset > 5){
            tcpOptionsLength = offset - 5;
        }
        System.out.println("TCP:   Data offset = " + tcpHeader.substring(24,25) + " bytes");
        System.out.println("TCP:   Flags = 0x" + tcpHeader.substring(26,28));
        printFlagsTCP(bits);
        System.out.println("TCP:   Window = " + hexToDecimal(tcpHeader.substring(28, 32)));
        System.out.println("TCP:   Checksum = 0x" + tcpHeader.substring(32, 36));
        System.out.println("TCP:   Urgent Pointer = " + hexToDecimal(tcpHeader.substring(36,40)));
        if(tcpOptionsLength > 0){
            System.out.println("TCP:   Options available");
        }
        else{
            System.out.println("TCP:   No options");
        }
        System.out.println("TCP:");

        System.out.println("TCP:   Data: (first 64 bytes)");
    }

    /**
     * This method is used to print the data of the packets. Only ascii values greater than 30 and less that 127
     * are printed. The rest are represented as periods.
     * @param data the entire data in hex
     * @param start int represents the start index of data.
     * @return void.
     */
    public static void printData(String data, int start, String type){
        String packetData = data.substring(start + (tcpOptionsLength*2)).toLowerCase();

        if(packetData.length() > 128){
            packetData = packetData.substring(0, 128);
        }
        int n = packetData.length()/32;
        int i = 0;
        boolean flag = false;
        if(n != 4){
            flag = true;
        }
        while(n > 0){
            String subData = packetData.substring(i,32 + i);
            StringBuilder dataToPrint = new StringBuilder();
            for(int j = 0; j < subData.length(); j += 4){
                dataToPrint.append(subData, j, 4 + j);
                dataToPrint.append(" ");
            }
            System.out.println(type  + dataToPrint + "      " + hexToAscii(subData) );
            i += 32;
            n--;
        }
        if(flag){
            String subData = packetData.substring(i);
            StringBuilder dataToPrint = new StringBuilder();
            for(int j = 0; j < subData.length(); j += 4){
                if(4 + j > subData.length()){
                    dataToPrint.append(subData.substring(j));
                    continue;
                }
                dataToPrint.append(subData, j, 4 + j);
                dataToPrint.append(" ");
            }
            while(dataToPrint.length() != 39){
                dataToPrint.append(" ");
            }
            System.out.println(type + dataToPrint + "       " + hexToAscii(subData) );
        }
    }


    /**
     * This method is used to print convert the hex data to ascii characters and return the string.
     * @param data the 0-16 bytes in length
     * @return void.
     */
    public static String hexToAscii(String data){
        StringBuilder ascii = new StringBuilder();
        ascii.append("'");
        char toAdd = ' ';
        for(int i = 0; i < data.length(); i += 2){
            long n = hexToDecimal(data.substring(i, 2 + i));
            if(n > 32 && n < 127){
                toAdd = (char)n;
            }
            else{
                toAdd = '.';
            }
            ascii.append(toAdd);
        }
        ascii.append("'");
        return ascii.toString();
    }

    /**
     * This method is used to print the ether header - 14 bytes of the packet.
     * @param data the entire data in hex
     * @param inputBytes the data in bytes
     * @return void.
     */
    public static void printEtherHeader(String data, byte[] inputBytes){
        String header = data.substring(0,28).toLowerCase();
        System.out.println("ETHER:   ----- Ether Header -----");
        System.out.println("ETHER:");
        System.out.println("ETHER:   Packet size = " + inputBytes.length + " bytes");
        StringBuilder destination = new StringBuilder();
        StringBuilder source = new StringBuilder();
       for(int i = 0, j = 12; i <=11; i+=2, j+=2){
           if(i == 10){
               destination.append(header.charAt(i)).append(header.charAt(i + 1)).append(",");
               source.append(header.charAt(j)).append(header.charAt(j + 1)).append(",");
               continue;
           }
           destination.append(header.charAt(i)).append(header.charAt(i + 1)).append(":");
           source.append(header.charAt(j)).append(header.charAt(j + 1)).append(":");
       }
        System.out.println("ETHER:   Destination = " + destination);
        System.out.println("ETHER:   Source      = " + source);
        System.out.println("ETHER:   Ethertype   = " + header.substring(24) + "(IP)");
        System.out.println("ETHER:");
    }


    /**
     * This method is used to print the IP header - 20 bytes of the packet.
     * @param data the entire data in hex
     * @return int which represents the protocol of the packet i.e, ICMP, UDP, TCP.
     */
    public static int printIPHeader(String data){
        String IPHeader = data.substring(28,68).toLowerCase();
        System.out.println("IP:   -----IP Header -----");
        System.out.println("IP:");
        System.out.println("IP:   Version = " + IPHeader.charAt(0));
        int headerLength = (Character.getNumericValue(IPHeader.charAt(1)) * 4);
        System.out.println("IP:   Header length = " + headerLength + " bytes");

        System.out.println("IP:   Differentiated Services Field = 0x" + IPHeader.substring(2,4));
        int[] bits = decToBinary(hexToDecimal(IPHeader.substring(2,4)));
        System.out.println("IP:        " + bits[0] + bits[1] + bits[2] + bits[3] + " " + bits[4] + bits[5] + ".. = DSCP");
        System.out.println("IP:        .... .." + bits[6] + bits[7] +  " = ECN");
        System.out.println("IP:   Total length = " + hexToDecimal(IPHeader.substring(4,8)) + " bytes");
        System.out.println("IP:   Identification = " + hexToDecimal(IPHeader.substring(8,12)));

        bits = decToBinary16(hexToDecimal(IPHeader.substring(12,14)));
        StringBuilder flag = new StringBuilder();
        for(int i = 0; i < 3; i++){
            flag.append(bits[i]);
        }
        bits = decToBinary16(hexToDecimal(IPHeader.substring(12,16)));
        StringBuilder fragOffset = new StringBuilder();
        for(int i = 3; i < bits.length; i++){
            fragOffset.append(bits[i]);
        }
        System.out.println("IP:   Flags = 0x" + IPHeader.substring(12,14));
        printFlagsIP(flag.toString());
        System.out.println("IP:   Fragment Offset = " + binToDecimal(fragOffset.toString()) +  " bytes");
        System.out.println("IP:   Time to live = " + hexToDecimal(IPHeader.substring(16,18)) + " seconds/hops");
        long protocol = hexToDecimal(IPHeader.substring(18, 20));
        System.out.println("IP:   Protocol = " + protocol + "(" + protocolMap.get((int)protocol) + ")");
        System.out.println("IP:   Header checksum = 0x" + IPHeader.substring(20,24));
        String sourceIP =  hexToDecimal(IPHeader.substring(24,26)) + "." + hexToDecimal(IPHeader.substring(26,28)) + "."
                + hexToDecimal(IPHeader.substring(28,30)) + "." + hexToDecimal(IPHeader.substring(30,32));
        System.out.println("IP:   Source address = " + sourceIP);
        String destinationIP = hexToDecimal(IPHeader.substring(32,34)) + "." + hexToDecimal(IPHeader.substring(34,36)) + "."
                + hexToDecimal(IPHeader.substring(36,38)) + "." + hexToDecimal(IPHeader.substring(38,40));
        System.out.println("IP:   Destination address = " + destinationIP);
        if(headerLength <= 20){
            System.out.println("IP:   No Options");
        }
        else{
            optionsLength =  headerLength - 20;
            System.out.println("IP:   Options available");
        }
        System.out.println("IP:");
        return (int)protocol;
    }

    /**
     * This method is used to print the the flags in TCP header.
     * @param bits data in binary
     * @return void
     */
    public static void printFlagsTCP(int[] bits){
        if(bits[2] == 0){
            System.out.println("TCP:        ..0. .... = No urgent pointer");
        }
        else{
            System.out.println("TCP:        ..1. .... = Urgent pointer");
        }
        if(bits[3] == 0){
            System.out.println("TCP:        ...0 .... = No acknowledgement");
        }
        else{
            System.out.println("TCP:        ...1 .... = Acknowledgement");
        }
        if(bits[4] == 0){
            System.out.println("TCP:        .... 0... = Don't push");
        }
        else{
            System.out.println("TCP:        .... 1... = Push");
        }
        if(bits[5] == 0){
            System.out.println("TCP:        .... .0.. = No reset");
        }
        else{
            System.out.println("TCP:        .... .1.. = Reset");
        }
        if(bits[6] == 0){
            System.out.println("TCP:        .... ..0. = No syn");
        }
        else{
            System.out.println("TCP:        .... ..1. = Syn");
        }
        if(bits[7] == 0){
            System.out.println("TCP:        .... ...0 = No Fin");
        }
        else{
            System.out.println("TCP:        .... ...1 = Fin");
        }
    }

    /**
     * This method is used to print the the flags in IP header.
     * @param flag data in binary
     * @return void
     */
    public static void printFlagsIP(String flag){
        if(flag.charAt(1) == '0'){
            System.out.println("IP:        .0.. .... = OK to fragment");
        }
        else{
            System.out.println("IP:        .1.. .... = do not fragment");
        }
        if(flag.charAt(2) == '0'){
            System.out.println("IP:        ..0. .... = last fragment");
        }
        else{
            System.out.println("IP:        ..1. .... = more fragments");
        }
    }



    /**
     * This method is used to convert hexadecimal to decimal value
     * @param hex data in hexadecimal
     * @return decimal value of input string
     */
    public static long hexToDecimal(String hex){
        String hexMap = "0123456789ABCDEF";
        hex =  hex.toUpperCase();
        long val = 1;
        long res = 0;
        for(int i = hex.length() - 1; i >=0; i--){
            char c = hex.charAt(i);
            long index = hexMap.indexOf(c);
            res += (val * index);
            val = val * 16;
        }
        return res;
    }

    /**
     * This method is used to convert binary to decimal value
     * @param bin data in binary
     * @return decimal value of input string
     */
    public static long binToDecimal(String bin){
        long val = 1;
        long res = 0;
        for(int i = bin.length() - 1; i >=0; i--){
            res += (val * (bin.charAt(i) -'0'));
            val = val * 2;
        }
        return res;
    }
    /**
     * This method is used to convert decimal to binary
     * @param num data in decimal
     * @return an array of bits of length 8
     */
    public static int[] decToBinary(long num){
        int[] binNum = new int[8];
        int i = 7;
        while(num > 0 && i >= 0){
            binNum[i] = (int) (num % 2);
            num =  num / 2;
            i--;
        }
        return binNum;
    }

    /**
     * This method is used to decimal to binary
     * @param num data in decimal
     * @return an array of bits of length 16
     */
    public static int[] decToBinary16(long num){
        int[] binNum = new int[16];
        int i = 7;
        while(num > 0 && i >= 0){
            binNum[i] = (int) (num % 2);
            num =  num / 2;
            i--;
        }
        return binNum;
    }
}
//pktanalyzer
