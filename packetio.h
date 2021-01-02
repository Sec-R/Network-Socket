#ifndef PACKETIO_H_
#define PACKETIO_H_
#include "device.h"


int send_frame(const void *buf, int len, int ethtype, const void *destmac,
               int id)
{
	if(len>1500){
	std::cerr<<"Frame size " << len <<" Invalid"<<std::endl;
	return -1;
	}
	
	Device *dev = get_device(id);
	
	if(dev==NULL){
	std::cerr<<"Device id "<<id<<" invalid"<<std::endl;
	return -1;
	}
	
	u_char* send_buf;
	if(len <46)
	{
	send_buf = new u_char[60];
	memset(send_buf+len+14,0,60-len-14);
	}
	else
	send_buf = new u_char[len+14];
	
	memcpy(send_buf,destmac,6);
	memcpy(send_buf+6,dev->mac_addr,6);
	send_buf[12] = (ethtype>>8) & 0xff;
	send_buf[13] = ethtype & 0xff;
	memcpy(send_buf+14,buf,len);
	pthread_mutex_lock(&mutex_send_packet_lock);
	int res = pcap_sendpacket(dev->pcap,send_buf,(len+14>60)?len+14:60);
	pthread_mutex_unlock(&mutex_send_packet_lock);
	
	delete [] send_buf;
	if(res){
	std::cerr<<"send failed"<<" "<<pcap_geterr(dev->pcap)<<std::endl;
	return -1;
	}
	else return 0;
	
}               
        

int set_frame_receive_callback(frame_receive_callback callback)
{
	eth_call_back_function = callback;
	return 0;
}

#endif
