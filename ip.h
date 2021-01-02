#ifndef IP_H_
#define IP_H_

#include "packetio.h"
#include "device.h"
#include <map>
#include <algorithm>
#include <netinet/ip.h>
#include <stdlib.h>
#include <ctime>




struct __attribute__((packed)) ip_header{
  uint8_t version_and_ihl ;
  uint8_t tos ;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;
};

bool route::operator<(const struct route &r) const {
  if (dst < r.dst) {
    return true;
  } else if (dst == r.dst) {
    if(dev_id < r.dev_id)
    return true;
    else if(dev_id == r.dev_id)
    return mac_address < r.mac_address;
    else return false;
  } else return false;
}

int add_or_update_route(int dev_id, uint32_t dst, uint64_t mac_address, int cost){
    int res = 1;
    pthread_mutex_lock(&mutex_ip_route_lock);
    route r;
    r.dev_id = dev_id;
    r.dst = dst;
    r.mac_address = mac_address;
    if(global_route_cost_table.find(r) != global_route_cost_table.end())
    res = (global_route_cost_table[r]!=cost);
    global_route_cost_table[r]=cost;
    pthread_mutex_unlock(&mutex_ip_route_lock);
    return res;
}

int add_or_upgrade_route(int dev_id, uint32_t dst, uint64_t mac_address, int cost){
    int res = 1;
    pthread_mutex_lock(&mutex_ip_route_lock);
    route r;
    r.dev_id = dev_id;
    r.dst = dst;
    r.mac_address = mac_address;
    if(global_route_cost_table.find(r) != global_route_cost_table.end())
    {
    if(global_route_cost_table[r]>cost)
    {
    global_route_cost_table[r]=cost;
    }
    else res = 0;
    }
    else global_route_cost_table[r]=cost;
    pthread_mutex_unlock(&mutex_ip_route_lock);
    return res;
}

int lookup_subnet(uint32_t ip_address, route* res){
	pthread_mutex_lock(&mutex_subnets_lock);
	int size = subnets.size();
	int longest_matched = -1;
	int subnet_id;
	for(int i=0;i<size;++i)
	{
	if((ip_address & subnets[i].mask) == (subnets[i].dst & subnets[i].mask))
		{
		if(subnets[i].mask_length > 	longest_matched)
		{
		longest_matched = subnets[i].mask_length;
		subnet_id  = i;
		}
		}
	
	}
	
	if(longest_matched == -1)
	{
	pthread_mutex_unlock(&mutex_subnets_lock);
	return -1;
	}
	
	res->mac_address = subnets[subnet_id].mac_address;
	res->dev_id = subnets[subnet_id].dev_id;
	pthread_mutex_unlock(&mutex_subnets_lock);
	return 0;
}

int remove_route(int dev_id, uint32_t dst, uint64_t mac_address){
    pthread_mutex_lock(&mutex_ip_route_lock);
    route r;
    r.dev_id = dev_id;
    r.dst = dst;
    r.mac_address = mac_address;
    if(global_route_cost_table.find(r)==global_route_cost_table.end())
    {
    pthread_mutex_unlock(&mutex_ip_route_lock);
    return -1;
    }
    global_route_cost_table.erase(global_route_cost_table.find(r));
    pthread_mutex_unlock(&mutex_ip_route_lock);
    return 0;
}

int lookup_route(uint32_t ip_address, route* res){
	pthread_mutex_lock(&mutex_ip_route_lock);
	route rtmp;
	rtmp.dst = ip_address;
	std::map<route,int>::iterator iter = global_route_cost_table.lower_bound(rtmp);
	if(iter == global_route_cost_table.end()||(iter->first).dst != ip_address)
	{
	return lookup_subnet(ip_address,res);
	}
	int lowest_cost = iter->second;
	rtmp = iter->first;
	++iter;
	while(iter!=global_route_cost_table.end()&&(iter->first).dst == ip_address)
	{
		if(iter-> second < lowest_cost)
		{	
		lowest_cost = iter->second;
		rtmp = iter->first;
		}
	++iter;
	}
	if(lowest_cost == 16)
	{
	pthread_mutex_unlock(&mutex_ip_route_lock);
	return lookup_subnet(ip_address,res);
	}
	else
	*res = rtmp;
	pthread_mutex_unlock(&mutex_ip_route_lock);
	return 0;
}



int setIPPacketReceiveCallback(IPPacketReceiveCallback callback){
	
	global_ip_callback = callback;
	return 0;
}


uint16_t cal_16_bit_check_sum(uint16_t* buf,int len)
{
    uint32_t sum = 0;
    for(int i=0;i<len/2;++i)
    {	
    	sum+=buf[i];    
    }
    
    if(len%2)
    {
    uint16_t tmp = 0;
    tmp = *(uint8_t*)(buf+len/2);
    sum+=tmp;
    }
    while(sum > 0xffff)
    	sum = (sum & 0xffff) + ((sum >> 16));
    return ~sum;
}

int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len){
    route rtmp;
    if(dest.s_addr != 0xffffffff && lookup_route(dest.s_addr,&rtmp)!=0)
    {
    	std::cerr<<"send ip packet failed!"<<std::endl;
    	return -1;
    }
    
    u_char* send_buf = new u_char[sizeof(ip_header)+len];
    ip_header* ip_packet = (ip_header*) send_buf;
    ip_packet->version_and_ihl = 0x45;
    ip_packet->tos = 0;
    ip_packet->total_length = endian_reverse_16(sizeof(ip_header)+len);
    srand((int)time(0));
    ip_packet->identification = rand() & 0xffff;
    ip_packet->flags = 0x0040;
    ip_packet->ttl = 32;
    ip_packet->protocol = proto;
    ip_packet->checksum = 0;
    ip_packet->src_addr = src.s_addr;
    ip_packet->dst_addr = dest.s_addr;
    memcpy(send_buf+sizeof(ip_header),buf,len);
    ip_packet->checksum = cal_16_bit_check_sum((uint16_t*) send_buf,20);
    
    int res = 0;
    uint8_t mac_addr[6];
    
    if(dest.s_addr == 0xffffffff)
    {
    for(int i=0;i<6;++i)
    {
    	mac_addr[i] = 0xff;	
    }
    pthread_mutex_lock(&mutex_Devices_lock);
    int size = Devices.size();
    pthread_mutex_unlock(&mutex_Devices_lock);
    for(int i=0;i<size;++i)
    res |= send_frame(send_buf, sizeof(ip_header)+len, 0x0800, mac_addr, i);	
    
    
    delete [] send_buf;
    return res;
    }
    
    for(int i=0;i<6;++i)
	mac_addr[i] = rtmp.mac_address >> (8*(5-i));
    res = send_frame(send_buf, sizeof(ip_header)+len, 0x0800, mac_addr, rtmp.dev_id);
    
    delete [] send_buf;
    return res;
}


int is_ip_frame_mine(uint32_t dst){
	int res;
	pthread_mutex_lock(&mutex_self_ips_lock);
       
       if(self_ips.find(dst)!=self_ips.end())
       res = 1;
       else res = 0;
       pthread_mutex_unlock(&mutex_self_ips_lock);
       
       if(dst == 0xffffffff)
       res = 1;
       return res;     
}

int default_ripcallbacker(const void *buf, int len, const struct in_addr src, const struct in_addr dst,int dev_id,uint64_t mac_address);

int default_ipcallbacker2(const void *buf, int len, int dev_id,uint64_t mac_address){
	ip_header* ip_head = (ip_header*) buf;
	
	if(is_ip_frame_mine(ip_head->dst_addr))
	{
		if(ip_head->protocol == 0x11)
		{	
			struct in_addr src,dst;
			src.s_addr = ip_head->src_addr;
			dst.s_addr = ip_head->dst_addr;
			return default_ripcallbacker((char*)buf+28,len-28,src,dst,dev_id,mac_address);
		}	
	}
	return global_ip_callback(buf,len);
}

int tcp_dispatcher(const void* buf,int len); 

int default_ipcallbacker(const void *buf, int len){
	ip_header* ip_head = (ip_header*) buf;
	
	if(is_ip_frame_mine(ip_head->dst_addr))
	{
		if(ip_head->protocol == 6)
		{
		     return tcp_dispatcher(buf,len);
		}
		else return 0;
	}
	else
	{
	in_addr src, dest;
	src.s_addr = ip_head->src_addr;
	dest.s_addr = ip_head->dst_addr;
	return sendIPPacket(src,dest,ip_head->protocol,(char*)buf+20,len-20);
	}
}

int setRoutingTable(const struct in_addr dest, const struct in_addr mask, const void* nextHopMAC, const char *device)
	{
	pthread_mutex_lock(&mutex_Devices_lock);
    	int size = Devices.size();
   	pthread_mutex_unlock(&mutex_Devices_lock);
	int dev_id = -1;    
    	for(int i=0;i<size;++i)
    	{
    		if(get_device(i)->device_name == device)
    		{
    		dev_id = i;
    		break;
    		}
    	}
    	
    	if(dev_id == -1)
    	{
    	std::cerr<<"Device not found :"<<device<<std::endl;
	pthread_mutex_unlock(&mutex_subnets_lock);    	
    	return -1;
    	}
    	subnet s;
    	s.dev_id = dev_id;
    	s.mask = mask.s_addr;
    	s.mask_length = 0;
    	uint32_t masks = s.mask;
    	for(int i=0;i<32;++i) 
	{
	s.mask_length += (masks>>i) & 1;   	
	}
	s.dst = dest.s_addr;
	
	for(int i=0;i<6;++i)
      	s.mac_address += ((uint64_t)*(uint8_t*)((char*)nextHopMAC+i+6) )<<(8*(5-i));
      	pthread_mutex_lock(&mutex_subnets_lock);
	subnets.push_back(s);
	pthread_mutex_unlock(&mutex_subnets_lock);
	return  0;
	} 
    
























#endif
