package Router;

import java.util.ArrayList;
import java.util.Arrays;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public int nUnderLayerCount = 0;
	public String pLayerName = null;
	public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	final static int ARP_MAX_SIZE = 28; 
	final static int ARP_IP_SIZE = 4;
	final static int ARP_MAC_SIZE = 6;
	final static int ARP_STATE_SIZE = 1;
	final static int ARP_TABLE_SIZE = ARP_IP_SIZE + ARP_MAC_SIZE + ARP_STATE_SIZE;
	final static int ARP_DEVICE_NAME = 10;
	final static int ARP_PROXY_TOTALSIZE = ARP_IP_SIZE + ARP_MAC_SIZE + ARP_DEVICE_NAME;
	final static int ARP_PROXY_SIZE = ARP_IP_SIZE + ARP_MAC_SIZE + ARP_STATE_SIZE;

	byte[] ARP_mactype; 
	byte[] ARP_iptype; 
	byte[] ARP_macsize; 
	byte[] ARP_ipsize;
	byte[] ARP_OP; 
	byte[] ARP_senderMacAddr;
	byte[] ARP_senderIPAddr; 
	byte[] ARP_targetMacAddr;
	byte[] ARP_targetIPAddr;

	byte[][] ARPCacheTable;
	byte[][] ARPProxyTable = new byte[255][ARP_PROXY_TOTALSIZE];

	static int ARPCacheTableCount = 0;
	static int ARPProxyTable_count = 0;

	public ARPLayer(String layerName) {
		pLayerName = layerName;
		resetARP(); 
	}

	public void set_ARPTable(byte[][] ARPCacheTable) {
		this.ARPCacheTable = ARPCacheTable;
	}

	public void resetARP() {
		ARP_mactype = new byte[2]; 
		ARP_mactype[0] = 0x00;
		ARP_mactype[1] = 0x01;
		ARP_iptype = new byte[2]; 
		ARP_iptype[0] = 0x08;
		ARP_iptype[1] = 0x00;
		ARP_OP = new byte[2];
		ARP_OP[0] = 0x00;
		ARP_OP[1] = 0x01;
		ARP_macsize = new byte[1];
		ARP_macsize[0] = 0x06;
		ARP_ipsize = new byte[1];
		ARP_ipsize[0] = 0x04;
		ARP_senderMacAddr = new byte[6];
		ARP_senderIPAddr = new byte[4];
		ARP_targetMacAddr = new byte[6];
		ARP_targetIPAddr = new byte[4];
	}

	void setARPCacheTable(byte[] IP_Address, byte[] Mac_Address, byte state) {
		int index = findARPCacheTable(IP_Address);
		if (Arrays.equals(IP_Address, ARP_senderIPAddr))
			return;
		if (index == -1) {
			System.arraycopy(IP_Address, 0, ARPCacheTable[ARPCacheTableCount], 0, 4);
			System.arraycopy(Mac_Address, 0, ARPCacheTable[ARPCacheTableCount], 4, 6);
			ARPCacheTable[ARPCacheTableCount][10] = state;
			ARPCacheTableCount++;
		} else {
			System.arraycopy(Mac_Address, 0, ARPCacheTable[index], 4, 6);
			ARPCacheTable[index][10] = state;
		}
	}

	byte[] getARPCacheTable(byte[] IP_Address) {
		int index = findARPCacheTable(IP_Address);
		if (index != -1)
			return ARPCacheTable[index];
		return null;
	}

	private int findARPCacheTable(byte[] IP_Address) {
		byte[] temp = new byte[4];
		for (int i = 0; i < ARPCacheTableCount; i++) {
			System.arraycopy(ARPCacheTable[i], 0, temp, 0, 4);
			if (java.util.Arrays.equals(IP_Address, temp)) {
				return i;
			}
		}
		return -1;
	}

	void setARPProxyTable(String Device_name, String ip, String Mac) {
		byte[] byte_name = Device_name.getBytes();
		byte[] byte_ip = new byte[4];
		byte[] byte_mac = new byte[6];

		byte_ip[0] = ((byte) Integer.parseInt(ip.substring(0, 3)));
		byte_ip[1] = ((byte) Integer.parseInt(ip.substring(3, 6)));
		byte_ip[2] = ((byte) Integer.parseInt(ip.substring(6, 9)));
		byte_ip[3] = ((byte) Integer.parseInt(ip.substring(9, 12)));

		for (int i = 0, j = 0; i < 12; i += 2, j++) {
			byte_mac[j] = Integer.valueOf(Mac.substring(i, i + 2), 16).byteValue();
		}
		if (find_ARPProxyTable(byte_ip) == -1) {
			System.arraycopy(byte_ip, 0, ARPProxyTable[ARPProxyTable_count], 0, 4);
			System.arraycopy(byte_mac, 0, ARPProxyTable[ARPProxyTable_count], 4, 6);
			System.arraycopy(byte_name, 0, ARPProxyTable[ARPProxyTable_count], 10,
					byte_name.length > 10 ? 10 : byte_name.length);
			ARPProxyTable_count++;
		}
	}

	int find_ARPProxyTable(byte[] IP_address) {

		byte[] temp = new byte[4];

		for (int i = 0; i < ARPProxyTable_count; i++) {
			System.arraycopy(ARPProxyTable[i], 0, temp, 0, 4);
			if (java.util.Arrays.equals(IP_address, temp)) {
				return i;
			}
		}
		return -1;
	}

	byte[] get_ARPProxyTable(int index) {
		byte[] Mac_Address = new byte[6];
		for (int i = 0; i < 6; i++) {
			Mac_Address[i] = ARPProxyTable[index][i + 4];
		}
		return Mac_Address;
	}

	boolean Gratuious_ARP_Send(byte[] byte_Mac) {
		byte[] send_arp_data = new byte[ARP_MAX_SIZE];
		System.arraycopy(ARP_mactype, 0, send_arp_data, 0, 2);
		System.arraycopy(ARP_iptype, 0, send_arp_data, 2, 2);
		send_arp_data[4] = ARP_macsize[0];
		send_arp_data[5] = ARP_ipsize[0];
		send_arp_data[6] = 0;
		send_arp_data[7] = 1;

		for (int i = 0; i < 6; i++) {
			ARP_targetMacAddr[i] = byte_Mac[i];
		}

		System.arraycopy(ARP_targetMacAddr, 0, send_arp_data, 8, 6);
		System.arraycopy(ARP_senderIPAddr, 0, send_arp_data, 14, 4);
		System.arraycopy(ARP_targetMacAddr, 0, send_arp_data, 18, 6);
		for (int i = 0; i < 4; i++) {
			send_arp_data[24 + i] = 0;
		}

		byte[] frame_type = new byte[2];
		frame_type[0] = 0x08;
		frame_type[1] = 0x06;

		if (((EthernetLayer) this.GetUnderLayer(0)).sendARP(send_arp_data)) {
			return true;
		} else {
			return false;
		}
	}

	boolean send(byte[] send_ip_data, byte[] dest_ip_address) {
		byte[] send_arp_data = new byte[send_ip_data.length + ARP_MAX_SIZE];

		if ((findARPCacheTable(dest_ip_address) == -1)) {//

			ARP_request_send(dest_ip_address);

		while (true) {
			try {
				Thread.sleep(100);
				if (findARPCacheTable(dest_ip_address) != -1 && ARPCacheTable[findARPCacheTable(dest_ip_address)][10] != 0) {
					byte[] dest_mac_address = new byte[6];

					dest_mac_address[0] = getARPCacheTable(dest_ip_address)[4];
					dest_mac_address[1] = getARPCacheTable(dest_ip_address)[5];
					dest_mac_address[2] = getARPCacheTable(dest_ip_address)[6];
					dest_mac_address[3] = getARPCacheTable(dest_ip_address)[7];
					dest_mac_address[4] = getARPCacheTable(dest_ip_address)[8];
					dest_mac_address[5] = getARPCacheTable(dest_ip_address)[9];

					return ((EthernetLayer) this.GetUnderLayer(0)).sendIP(send_ip_data, dest_mac_address);
				}
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		} else {
			byte[] dest_mac_address = new byte[6];

			dest_mac_address[0] = getARPCacheTable(dest_ip_address)[4];
			dest_mac_address[1] = getARPCacheTable(dest_ip_address)[5];
			dest_mac_address[2] = getARPCacheTable(dest_ip_address)[6];
			dest_mac_address[3] = getARPCacheTable(dest_ip_address)[7];
			dest_mac_address[4] = getARPCacheTable(dest_ip_address)[8];
			dest_mac_address[5] = getARPCacheTable(dest_ip_address)[9];

			return ((EthernetLayer) this.GetUnderLayer(0)).sendIP(send_ip_data, dest_mac_address);
		}
	}

	boolean ARP_request_send(byte[] dest_ip_address) {
		byte[] send_arp_data = new byte[ARP_MAX_SIZE];
		byte[] temp = new byte[6];
		System.arraycopy(ARP_mactype, 0, send_arp_data, 0, 2);
		System.arraycopy(ARP_iptype, 0, send_arp_data, 2, 2);
		send_arp_data[4] = ARP_macsize[0];
		send_arp_data[5] = ARP_ipsize[0];
		send_arp_data[6] = 0;
		send_arp_data[7] = 1;

		for (int i = 0; i < 6; i++) {
			ARP_targetMacAddr[i] = 0;
			temp[i] = (byte) 0xff;
		}

		System.arraycopy(ARP_senderMacAddr, 0, send_arp_data, 8, 6);
		System.arraycopy(ARP_senderIPAddr, 0, send_arp_data, 14, 4);
		System.arraycopy(ARP_targetMacAddr, 0, send_arp_data, 18, 6);
		System.arraycopy(dest_ip_address, 0, send_arp_data, 24, 4);

		if (findARPCacheTable(dest_ip_address) == -1)
			setARPCacheTable(dest_ip_address, temp, (byte) 0);

		return ((EthernetLayer) this.GetUnderLayer(0)).sendARP(send_arp_data);

	}

	boolean ARP_reply_send(byte[] data) {

		byte[] receive_sender_Ethernet = new byte[6];
		byte[] receive_sender_IP = new byte[4];
		byte[] receive_target_IP = new byte[4];
		byte[] receive_target_Ethernet = new byte[6];

		System.arraycopy(data, 8, receive_sender_Ethernet, 0, 6);
		System.arraycopy(data, 14, receive_sender_IP, 0, 4);
		System.arraycopy(data, 18, receive_target_Ethernet, 0, 6);
		System.arraycopy(data, 24, receive_target_IP, 0, 4);

		setARPCacheTable(receive_sender_IP, receive_sender_Ethernet, (byte) 1); 

		if (java.util.Arrays.equals(ARP_senderIPAddr, receive_sender_IP)) {
			return false;
		}

		if (data[6] == 0 && data[7] == 1) {
			byte[] conform = new byte[4];
			conform[0] = data[24];
			conform[1] = data[25];
			conform[2] = data[26];
			conform[3] = data[27];

			if (java.util.Arrays.equals(receive_sender_Ethernet, receive_target_Ethernet)) {
				if (findARPCacheTable(receive_sender_IP) != -1) {
					setARPCacheTable(receive_sender_IP, receive_sender_Ethernet, (byte) 1);
					return true;
				}
			}

			System.arraycopy(receive_sender_Ethernet, 0, data, 18, 6);
			System.arraycopy(receive_sender_IP, 0, data, 24, 4);
			System.arraycopy(receive_target_IP, 0, data, 14, 4);
			System.arraycopy(ARP_senderMacAddr, 0, data, 8, 6);

			data[6] = 0;
			data[7] = 2;
			byte[] frame_type = new byte[2];
			frame_type[0] = 0x08;
			frame_type[1] = 0x06;
			((EthernetLayer) this.GetUnderLayer(0)).sendARP(data);
			return true;

		} else if (data[6] == 0 && data[7] == 2) {
			System.arraycopy(data, 8, receive_sender_Ethernet, 0, 6);
			System.arraycopy(data, 14, receive_sender_IP, 0, 4);
			if (findARPCacheTable(receive_sender_IP) != -1) {
				setARPCacheTable(receive_sender_IP, receive_sender_Ethernet, (byte) 1);
				return true;
			}
		}
		return true;
	}

	public void setSrcEthAddress(byte[] src_EthAddress) {
		ARP_senderMacAddr = Arrays.copyOf(src_EthAddress, src_EthAddress.length);
	}

	public void setDstIPAddress(String dst_IPAddress) {
		ARP_targetIPAddr[0] = ((byte) Integer.parseInt(dst_IPAddress.substring(0, 3)));
		ARP_targetIPAddr[1] = ((byte) Integer.parseInt(dst_IPAddress.substring(3, 6)));
		ARP_targetIPAddr[2] = ((byte) Integer.parseInt(dst_IPAddress.substring(6, 9)));
		ARP_targetIPAddr[3] = ((byte) Integer.parseInt(dst_IPAddress.substring(9, 12)));
	}

	public void setSrcIPAddress(String src_IPAddress) {
		ARP_senderIPAddr[0] = ((byte) Integer.parseInt(src_IPAddress.substring(0, 3)));
		ARP_senderIPAddr[1] = ((byte) Integer.parseInt(src_IPAddress.substring(3, 6)));
		ARP_senderIPAddr[2] = ((byte) Integer.parseInt(src_IPAddress.substring(6, 9)));
		ARP_senderIPAddr[3] = ((byte) Integer.parseInt(src_IPAddress.substring(9, 12)));
	}

	public void ARPTable_reset() {
		for (int i = 0; i < ARPCacheTableCount; i++) {
			for (int j = 0; j < ARP_TABLE_SIZE; j++) {
				ARPCacheTable[i][j] = 0;
			}
		}
		ARPCacheTableCount = 0;
	}

	public void ARPTable_delete() {
		if (ARPCacheTableCount > 0) {
			ARPCacheTableCount--;
			for (int j = 0; j < ARP_TABLE_SIZE; j++) {
				ARPCacheTable[ARPCacheTableCount][j] = 0;
			}
		}
	}

	public void ProxyTable_delete() {
		if (ARPProxyTable_count > 0) {
			ARPProxyTable_count--;
			for (int j = 0; j < ARPProxyTable_count; j++) {
				ARPProxyTable[ARPProxyTable_count][j] = 0;
			}
		}
	}

	public void ARPTable_IP_delete(byte[] ip) {
		if (findARPCacheTable(ip) != -1) {
			for (int i = findARPCacheTable(ip); i < ARPCacheTableCount - 1; i++) {
				ARPCacheTable[i] = ARPCacheTable[i + 1];
			}
			ARPCacheTableCount--;
		}
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