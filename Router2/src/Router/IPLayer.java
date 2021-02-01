package Router;

import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    final static int IP_HEAD_SIZE = 20; 

    byte[] ip_head = new byte[IP_HEAD_SIZE];
    byte[] ip_sourceIP = new byte[4];
    byte[] ip_destinationIP = new byte[4];
    byte[] ip_data; 

    int interfaceNumber;

    IPLayer otherIPLayer;

    RoutingTable[] routingTable;

    public IPLayer(String layerName) {
        pLayerName = layerName;


    }

    void setOtherIPLayer(IPLayer other) {
        otherIPLayer = other;
    }

    void setInterfaceNumber(int number) {
        interfaceNumber = number;
    }

    void setRoutingTable(RoutingTable[] routingTable) {
        this.routingTable = routingTable;
    }

    void setSourceIpAddress(byte[] sourceAddress) {
        for (int i = 0; i < 4; i++)
            ip_sourceIP[i] = sourceAddress[i];
    }

    void setDestinationIPAddress(byte[] destinationAddress) {
        for (int i = 0; i < 4; i++)
            ip_destinationIP[i] = destinationAddress[i];
    }

    boolean receiveIP(byte[] data) {
        ip_data = new byte[data.length];
        byte[] frame_dst_ip = new byte[4];
        frame_dst_ip[0] = data[16];
        frame_dst_ip[1] = data[17];
        frame_dst_ip[2] = data[18];
        frame_dst_ip[3] = data[19];
        System.arraycopy(data, 0, ip_data, 0, data.length);
        int check = 0;

        for (int i = 0; i < ((ApplicationLayer) this.GetUpperLayer(0)).routingIndex; i++) {
            byte[] destination = routingTable[i].getDestination();
            for (int j = 0; j < 4; j++) {
                byte[] netMask = routingTable[i].getNetMask();
                if (destination[j] != (netMask[j] & frame_dst_ip[j])) {
                    check = 0;
                    break;
                } else
                    check = 1;
            }
            if (check == 1) { //목적지가 일치하는 destination찾았을 경우
                if (interfaceNumber == routingTable[i].getInterface()) {
                    ((ARPLayer) this.GetUnderLayer(0)).send(ip_data, routingTable[i].getGateway());

                } else {
                    ((ARPLayer) otherIPLayer.GetUnderLayer(0)).send(ip_data, routingTable[i].getGateway());
                }

                return true;
            }
        }

        return false;
    }
    public static int byte2Int(byte[] src)
    {
        int s1 = src[0] & 0xFF;
        int s2 = src[1] & 0xFF;

        return ((s1 << 8) + (s2 << 0));
    }
    
    boolean receiveARP(byte[] data) {
        int check = 1;
        for (int i = 0; i < 4; i++) {
            if (ip_sourceIP[i] != data[i + 24]) {
                check = 0;
                break;
            }
        }
        if (check == 1) {
        	System.out.println("IPLayer : 나 이제 에이알피로 내려가고 있어요");
            ((ARPLayer) this.GetUnderLayer(0)).ARP_reply_send(data);
            return true;
        }
        check = 0;
        for (int i = 0; i < ((ApplicationLayer) this.GetUpperLayer(0)).routingIndex; i++) {
            byte[] destination = routingTable[i].getDestination();
            for (int j = 0; j < 4; j++) {
                byte[] netMask = routingTable[i].getNetMask();
                if (destination[j] != (netMask[j] & data[j + 24])) {
                    check = 0;
                    break;
                } else
                    check = 1;
            }
            if (check == 1) {
                if (interfaceNumber != routingTable[i].getInterface()) {
                    ((ARPLayer) this.GetUnderLayer(0)).ARP_reply_send(data);
                    ((ARPLayer) otherIPLayer.GetUnderLayer(0)).ARP_request_send(routingTable[i].getGateway());
                } else {
                    ((ARPLayer) this.GetUnderLayer(0)).ARP_reply_send(data);
                }
                return true;
            }
        }
        ((ARPLayer) this.GetUnderLayer(0)).ARP_reply_send(data);
        return false;
    }
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_aUnderLayer.add(nUnderLayerCount++, pUnderLayer);
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
        // nUpperLayerCount++;
    }

    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer(int nindex) {
        if (nindex < 0 || nindex > m_nUnderLayerCount || m_nUnderLayerCount < 0)
            return null;
        return p_aUnderLayer.get(nindex);
    }
    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);

    }
}