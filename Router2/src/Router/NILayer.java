package Router;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class NILayer implements BaseLayer {
	public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
    int m_iNumAdapter;
    public Pcap m_AdapterObject; 
    public PcapIf device;
    public ArrayList<PcapIf> m_pAdapterList; 
    StringBuilder errbuf = new StringBuilder(); 
    long start;
    
    public NILayer(String pName) {
        pLayerName = pName;

        m_pAdapterList = new ArrayList<PcapIf>();
        m_iNumAdapter = 0;
        setAdapterList(); 
    }
    
    public void packetStartDriver() {
        int snaplength = 64 * 1024; 
        int flags = Pcap.MODE_PROMISCUOUS; 
        int timeout = 1 * 1000; 
        m_AdapterObject = Pcap.openLive(m_pAdapterList.get(m_iNumAdapter).getName(), 
        		snaplength, flags, timeout, errbuf);
    }
    
    public PcapIf GetAdapterObject(int iIndex) {
		return m_pAdapterList.get(iIndex);
	}
    
    public void SetAdapterNumber(int iNum) {
		m_iNumAdapter = iNum;
		packetStartDriver();
		Receive();
	}
    
    public void setAdapterList() {
    	int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
		if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
    }
    
    boolean send(byte[] data, int length) {
    	 ByteBuffer buffer = ByteBuffer.wrap(data); // 상위레이어에서 전달받은 데이터를 byte
         // buffer에 저장
         start = System.currentTimeMillis();
         // 네트워크 어뎁터의 sendPacket 함수를 통해 데이터 전송
         if (m_AdapterObject.sendPacket(buffer) != Pcap.OK) {
            System.err.println(m_AdapterObject.getErr()); // 패킷 전송 실패시 에러메시지 출력
            return false;
         }
         return true;
    }
    
    synchronized boolean receive() {
        Receive_Thread thread = new Receive_Thread(m_AdapterObject, (EthernetLayer) this.GetUpperLayer(0));
        Thread object = new Thread(thread); 
        object.start();
        try {
            object.join(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return false;
    }

    public ArrayList<PcapIf> getAdapterList() {
        return m_pAdapterList;
    }

    public void setAdapterNumber(int iNumber) {
        m_iNumAdapter = iNumber;
        packetStartDriver(); 
        receive();
    }

    String[] getNICDescription() {
        String[] descriptionArray = new String[m_pAdapterList.size()];

        for (int i = 0; i < m_pAdapterList.size(); i++)
            descriptionArray[i] = m_pAdapterList.get(i).getDescription();

        return descriptionArray;
    }
    
    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_aUnderLayer.add(nUnderLayerCount++, pUnderLayer);
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
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

class Receive_Thread implements Runnable {
	byte[] data;
	Pcap AdapterObject;
	EthernetLayer UpperLayer;

	public Receive_Thread(Pcap m_AdapterObject, EthernetLayer m_UpperLayer) {
		// TODO Auto-generated constructor stub
		AdapterObject = m_AdapterObject;
		UpperLayer = m_UpperLayer;
	}

	@Override
	   public void run() {
	      while (true) {
	         // 패킷 수신을 위한 라이브러리 함수
	         PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {
	            /**
	             * nextPacket 함수는 수신된 패킷의 정보를 확인한 뒤 상위레이어(EthernetLayer)로 보내는
	             * 역할을 한다.
	             * 
	             * @param packet
	             * @param user
	             */
	            public void nextPacket(PcapPacket packet, String user) {
	               data = packet.getByteArray(0, packet.size()); // 수신된 패킷의
	               if ((data[12] == 8 && data[13] == 0) || (data[12] == 8 && data[13] == 6))
	                  UpperLayer.receive(data); // 수신된 데이터를
	            }
	         };
	         AdapterObject.loop(1000, packetHandler, ""); // 패킷 수신을 위한 라이브러리 함수를
	         // 무한으로 반복
	      }
	}
}