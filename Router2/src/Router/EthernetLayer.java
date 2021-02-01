package Router;

import java.util.ArrayList;
import java.util.Arrays;

public class EthernetLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public int nUnderLayerCount = 0;
	public String pLayerName = null;
	public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	final static int ETHERNET_MAX_SIZE = 1514;
	final static int ETHERNET_HEAD_SIZE = 14;
	final static int ETHERNET_MAX_DATA = ETHERNET_MAX_SIZE - ETHERNET_HEAD_SIZE; 

	byte[] Ethernet_type;
	byte[] Ethernet_sourceAddress;
	byte[] Ethernet_data;

	public EthernetLayer(String pName) {
		pLayerName = pName;
		resetHeader();
	}

	void resetHeader() {
		Ethernet_sourceAddress = new byte[6]; 
		Ethernet_type = new byte[2];
		Ethernet_data = new byte[ETHERNET_MAX_SIZE];
	}

	void setSourceAddress(byte[] sourceAddress) {
		for (int i = 0; i < 6; i++) {
			Ethernet_sourceAddress[i] = sourceAddress[i];
			Ethernet_data[i + 6] = sourceAddress[i];
		}
	}

	void setDestinationAddress(byte[] destinationAddress) {
		for (int i = 0; i < 6; i++)
			Ethernet_data[i] = destinationAddress[i];
	}

	void setFrameType(byte[] frameType) {
		for (int i = 0; i < 2; i++)
			Ethernet_data[i + 12] = frameType[i];
	}

	boolean sendIP(byte[] data, byte[] destinationAddress) {
		int length = data.length;
		byte[] type = { (byte) 0x08, 0x00 };
		Ethernet_data = new byte[data.length + ETHERNET_HEAD_SIZE];
		setFrameType(type);
		setSourceAddress(Ethernet_sourceAddress);
		setDestinationAddress(destinationAddress);

		for (int i = 0; i < length; i++)
			Ethernet_data[i + ETHERNET_HEAD_SIZE] = data[i];
		if (((NILayer) this.GetUnderLayer(0)).send(Ethernet_data, Ethernet_data.length))
			return true;
		else
			return false;
	}

	boolean sendARP(byte[] data) {
		int length = data.length;
		byte[] destinationAddress = new byte[6];
		Ethernet_data = new byte[data.length + ETHERNET_HEAD_SIZE];
		byte[] type = { 0x08, 0x06 };
		setFrameType(type);
		setSourceAddress(Ethernet_sourceAddress);

		if (data[7] == 2) {
			for (int i = 0; i < 6; i++)
				destinationAddress[i] = data[i + 18];
			setDestinationAddress(destinationAddress);
		} else {
			for (int i = 0; i < 6; i++)
				destinationAddress[i] = (byte) 0xff;
			setDestinationAddress(destinationAddress);
		}

		for (int i = 0; i < length; i++)
			Ethernet_data[i + ETHERNET_HEAD_SIZE] = data[i];
		if (((NILayer)this.GetUnderLayer(0)).send(Ethernet_data, Ethernet_data.length))
			return true;
		else
			return false;
	}

//////////////////////////////////////////////////////////////
	synchronized boolean receive(byte[] data) {
		byte[] destinationMAC = new byte[6];
		byte[] sourceMAC = new byte[6];
		byte[] broadcast = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
		System.arraycopy(data, 0, destinationMAC, 0, 6);
		System.arraycopy(data, 6, sourceMAC, 0, 6);
		
		// 받아온 source가 내 source와 같은지 비교 (내가 보낸 것인지 확인) -> 내가 보낸 것이 맞다면 false
		if (java.util.Arrays.equals(Ethernet_sourceAddress, sourceMAC))
			return false;
		// 받은 패킷의 목적지가 브로드캐스트가 아니거나 목적지의 주소가 자신의 주소가 아니면 false
		if (!(java.util.Arrays.equals(broadcast, destinationMAC) || java.util.Arrays.equals(Ethernet_sourceAddress, destinationMAC)))
			return false;
		
		//헤더를 뺀 진짜 데이터
		byte[] dataFrame = new byte[data.length - ETHERNET_HEAD_SIZE];
		dataFrame = Arrays.copyOfRange(data, ETHERNET_HEAD_SIZE, data.length);
		
		//ip
		if (data[12] == 8 && data[13] == 0) {
			((IPLayer) this.GetUpperLayer(1)).receiveIP(dataFrame);
		}
		//arp
		if (data[12] == 8 && data[13] == 6) {
			((IPLayer) this.GetUpperLayer(1)).receiveARP(dataFrame);
		}

		return true;
	}


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