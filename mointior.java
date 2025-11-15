import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.IOException;
import java.util.logging.*;

public class NetworkMonitor {

    private static final Logger logger = Logger.getLogger("NetworkMonitorLog");
    private static int packetCount = 0;

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        setupLogger();

        PcapNetworkInterface nif = Pcaps.findAllDevs().get(0);
        System.out.println("[+] Using Interface: " + nif.getName());

        int snapshotLength = 65536;
        int readTimeout = 50;

        PcapHandle handle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);

        PacketListener listener = packet -> {
            packetCount++;
            System.out.println("\n[#] Packet #" + packetCount);

            // Ethernet Layer
            if (packet.contains(EthernetPacket.class)) {
                EthernetPacket eth = packet.get(EthernetPacket.class);
                System.out.println("[*] Ether: " + eth.getHeader().getSrcAddr() + " -> " + eth.getHeader().getDstAddr() 
                                   + " | Type: " + eth.getHeader().getType());
                logger.info("Ether Layer: " + eth.getHeader().getSrcAddr() + " -> " + eth.getHeader().getDstAddr());
            }

            // IP Layer
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ip = packet.get(IpV4Packet.class);
                System.out.println("[*] IP: " + ip.getHeader().getSrcAddr() + " -> " + ip.getHeader().getDstAddr() 
                                   + " | Protocol: " + ip.getHeader().getProtocol());
                logger.info("IP Layer: " + ip.getHeader().getSrcAddr() + " -> " + ip.getHeader().getDstAddr() 
                            + ", Protocol: " + ip.getHeader().getProtocol());
            }

            // TCP
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcp = packet.get(TcpPacket.class);
                System.out.println("    [TCP] " + tcp.getHeader().getSrcPort() + " -> " + tcp.getHeader().getDstPort() 
                                   + " | Seq: " + tcp.getHeader().getSequenceNumber());
            }

            // UDP
            if (packet.contains(UdpPacket.class)) {
                UdpPacket udp = packet.get(UdpPacket.class);
                System.out.println("    [UDP] " + udp.getHeader().getSrcPort() + " -> " + udp.getHeader().getDstPort());
            }

            // ICMP
            if (packet.contains(IcmpV4CommonPacket.class)) {
                System.out.println("    [ICMP] Packet detected");
            }
        };

        try {
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            handle.close();
        }
    }

    private static void setupLogger() {
        try {
            Handler fileHandler = new FileHandler("network_monitor.log");
            logger.addHandler(fileHandler);
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// this file will be the main mointior file 
// not completed yet

