#ifndef RIP_H_
#define RIP_H_

#include "device.h"
#include "packetio.h"
#include "ip.h"

struct __attribute__((packed)) udp_header{
  uint16_t src_port ;
  uint16_t dst_port ;
  uint16_t len ;
  uint16_t checksum ;
  
};

int send_udp(const struct in_addr src, const struct in_addr dst,void* buf, uint16_t src_port, uint16_t dst_port, uint16_t len){
	
	u_char* send_buf = new u_char[len+8];
	udp_header* udp_head = (udp_header*) send_buf;
	udp_head->src_port = src_port;
	udp_head->dst_port = dst_port;
	udp_head->len = endian_reverse_16(len+8);
	udp_head->checksum = 0;
	memcpy(send_buf+8,buf,len);
	udp_head->checksum = 0;
	int res = sendIPPacket(src,dst,17,send_buf,len+8);
	delete [] send_buf;
	return res;
}

int send_rip_request(const struct in_addr src, const struct in_addr dst){
	
	u_char* buf = new u_char[4];
	*(uint8_t*) buf = 1;
	*(uint8_t*) (buf+1) = 1;
	*(uint16_t*) (buf+2) = 0;
	
	int res = send_udp(src,dst,buf,0,0,4);
	delete [] buf;
	return res;
}

int send_rip_response(const struct in_addr src, const struct in_addr dst){
	
	struct in_addr real_dst;
	real_dst.s_addr = ~0;
	struct in_addr real_src;
	
	pthread_mutex_lock(&mutex_self_ips_lock);
    	real_src.s_addr = *(self_ips.begin());
	pthread_mutex_unlock(&mutex_self_ips_lock);
    		
	pthread_mutex_lock(&mutex_ip_route_lock);
	int size = global_route_cost_table.size();
	
	if(size == 0){
	pthread_mutex_unlock(&mutex_ip_route_lock);
	return 0;
	}
	
	u_char** buf_pointer = new u_char* [(size-1)/25+1];
	int rest_size = size - (size/25)*25;
	std::map<route,int>::iterator iter = global_route_cost_table.begin();
	for(int i=0;i<size/25;++i){
		buf_pointer[i] = new u_char [4+20*25];
		*(uint8_t*) buf_pointer[i] = 2;
		*(uint8_t*) (buf_pointer[i]+1) = 1;
		*(uint16_t*) (buf_pointer[i]+2) = 0;
		for(int j=0;j<25;++j){
			*(uint16_t*)(buf_pointer[i]+4+20*j) = 2;
			*(uint16_t*)(buf_pointer[i]+4+20*j+2) = 0;
			*(uint32_t*)(buf_pointer[i]+4+20*j+4) = (iter->first).dst;
			*(uint32_t*)(buf_pointer[i]+4+20*j+8) = 0;
			*(uint32_t*)(buf_pointer[i]+4+20*j+12) = 0;
			*(uint32_t*)(buf_pointer[i]+4+20*j+16) = (iter->second == 16) ? 16 : iter->second+ 1;
			++iter;
		}
	}
	if(rest_size!=0)
	{
		buf_pointer[size/25] = new u_char [32+160*rest_size];
		*(uint8_t*) buf_pointer[size/25] = 2;
		*(uint8_t*) (buf_pointer[size/25]+1) = 1;
		*(uint16_t*) (buf_pointer[size/25]+2) = 0;
		for(int j=0;j<rest_size;++j){
			*(uint16_t*)(buf_pointer[size/25]+4+20*j) = 2;
			*(uint16_t*)(buf_pointer[size/25]+4+20*j+2) = 0;
			*(uint32_t*)(buf_pointer[size/25]+4+20*j+4) = (iter->first).dst;
			*(uint32_t*)(buf_pointer[size/25]+4+20*j+8) = 0;
			*(uint32_t*)(buf_pointer[size/25]+4+20*j+12) = 0;
			*(uint32_t*)(buf_pointer[size/25]+4+20*j+16) = (iter->second == 16) ? 16 : iter->second+ 1;
			++iter;
		}
	
	}
	pthread_mutex_unlock(&mutex_ip_route_lock);
	
	int res = 0;
	for(int i=0;i<size/25;++i)
	{
	res |= send_udp(real_src,real_dst,buf_pointer[i],0,0,4+20*25);
	delete [] buf_pointer[i];	
	}
	
	if(rest_size!=0)
	{
	res |= send_udp(real_src,real_dst,buf_pointer[size/25],0,0,4+20*rest_size);
	delete [] buf_pointer[size/25];
	}
	
	delete [] buf_pointer;
	return res;
}

int reset_route_table(){
	pthread_mutex_lock(&mutex_ip_route_lock);
	pthread_mutex_lock(&mutex_self_ips_lock);
	std::map<route,int>::iterator iter = global_route_cost_table.begin();
	while(iter!=global_route_cost_table.end())
	{
		if(self_ips.find((iter->first).dst)!=self_ips.end())
		{
		iter->second = 16;
		}
		++iter;
	}
	pthread_mutex_unlock(&mutex_self_ips_lock);
	pthread_mutex_unlock(&mutex_ip_route_lock);	
	return 0;
}


int default_ripcallbacker(const void *buf, int len,const struct in_addr src, const struct in_addr dst,int dev_id,uint64_t mac_address){
	if(*(uint8_t*) buf == 1)
	{
		add_or_upgrade_route(dev_id,src.s_addr,mac_address,1);
		if(dst.s_addr == ~0)
		{
		struct in_addr real_src;
    		real_src.s_addr = *((get_device(dev_id)->ip_addrs).begin());
    		return send_rip_response(real_src,src);
		}else return send_rip_response(dst,src);
	}
	else if(*(uint8_t*) buf == 2)
	{
		int res_size = (len-4)/20;
		int res = 0;
		for(int i=0;i<res_size;++i)
		{
		res |= add_or_upgrade_route(dev_id,*(uint32_t*)((char*)buf+4+20*i+4),mac_address, *(uint32_t*)((char*)buf+4+20*i+16));
		}
		
		if(res)
		return send_rip_response(dst,src);
		else 
		return 0;
	}
	else
	{
	std::cerr<<"Unknown rip type"<<std::endl;
	return -1;
	}
}













#endif
