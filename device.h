#ifndef DEVICE_H_
#define DEVICE_H_

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstdint>
#include <pcap.h>
#include <string>
#include <utility>
#include <vector>
#include <functional>
#include <map>
#include <iostream>
#include <sys/epoll.h>
#include <pthread.h>
#include <set>

struct Device;

pthread_mutex_t mutex_send_packet_lock;

struct route {
  int dev_id = -1;
  uint32_t dst;
  uint64_t mac_address;
  bool operator<(const struct route &r) const;
};

struct subnet {
  int dev_id;
  uint32_t mask;
  int mask_length;
  uint32_t dst;
  uint64_t mac_address;
};

pthread_mutex_t mutex_subnets_lock;
std::vector<subnet> subnets;


pthread_mutex_t mutex_ip_route_lock;
std::map<route,int> global_route_cost_table;


pthread_mutex_t mutex_mdi_lock;
std::map<std::string,int> mdi;

pthread_mutex_t mutex_Devices_lock;
std::vector<Device> Devices;

pthread_mutex_t mutex_mfd_lock;
std::map<int,int> mfd;

pthread_mutex_t mutex_self_ips_lock;
std::set<uint32_t> self_ips;


pthread_mutex_t global_session_table_lock;
pthread_mutex_t global_fd_to_session_map_lock;
pthread_mutex_t partial_tcp_connection_lock;
pthread_mutex_t socket_state_lock;

int null_fd;

struct epoll_event global_events[256];
int global_epfd;

int initialed = 0;  

using frame_receive_callback = int (*)(const void *, int, int);


int default_ethcallbacker(const void *buf, int len, int id);

frame_receive_callback eth_call_back_function = default_ethcallbacker;


typedef int (*IPPacketReceiveCallback)(const void* buf, int len);


int default_ipcallbacker(const void *buf, int len);

IPPacketReceiveCallback global_ip_callback = default_ipcallbacker;

int default_ipcallbacker2(const void *buf, int len, int dev_id, uint64_t mac_address);

struct Device {
  std::string device_name;
  uint8_t mac_addr[6];
  int id;
  pcap_t * pcap;
  std::set<uint32_t> ip_addrs;
  int read();
  Device();
  ~Device();
};
Device::Device(){
	pcap =NULL;
	for(int i=0;i<6;++i)
	mac_addr[i]=0;
}

Device::~Device() {
  if (pcap) {
    pcap_close(pcap);
  }
}

uint32_t endian_reverse_32(uint32_t number){
	uint32_t res = 0;
	for(int i=0;i<4;++i)
	res += ((number >> ((3-i)*8)) & 0xff) << (i*8);
	return res; 
}


uint16_t endian_reverse_16(uint16_t number){
	uint16_t res = 0;
	for(int i=0;i<2;++i)
	res += ((number >> ((1-i)*8)) & 0xff) << (i*8);
	return res; 
}

int find_device(const char *device)
{
	pthread_mutex_lock(&mutex_mdi_lock);
	int res;
	std::map<std::string,int>::iterator iter;
	iter = mdi.find(device);
	if(iter==mdi.end()) res = -1;
	else res = iter->second;
	pthread_mutex_unlock(&mutex_mdi_lock);
	return res;
}



Device* get_device(int id){
	
	pthread_mutex_lock(&mutex_Devices_lock);
	Device* res;
	if( id < 0 || id >= Devices.size()) res = NULL;
	else res = &Devices[id];
	pthread_mutex_unlock(&mutex_Devices_lock);
	return res;
}

int get_device_id_from_fd(int fd){
	
	pthread_mutex_lock(&mutex_mfd_lock);
	int res = mfd[fd];
	pthread_mutex_unlock(&mutex_mfd_lock);
	return res;
}

int init_all(){
	
	if(initialed)
	return 0;
	
	pthread_mutex_init(&mutex_mdi_lock, NULL);
	pthread_mutex_init(&mutex_mfd_lock, NULL);
	pthread_mutex_init(&mutex_Devices_lock, NULL);
	pthread_mutex_init(&mutex_send_packet_lock, NULL);
	pthread_mutex_init(&mutex_ip_route_lock, NULL);
	pthread_mutex_init(&mutex_self_ips_lock, NULL);
	pthread_mutex_init(&mutex_subnets_lock, NULL);
	pthread_mutex_init(&global_session_table_lock,NULL);
	pthread_mutex_init(&global_fd_to_session_map_lock,NULL);
	pthread_mutex_init(&partial_tcp_connection_lock,NULL);
	pthread_mutex_init(&socket_state_lock,NULL);
	
	
	global_epfd  = epoll_create(256);
	null_fd = dup(STDOUT_FILENO);
	if (global_epfd == -1) {
    	std::cerr << "epoll_create: " << strerror(errno)<< std::endl;
    	return -1;
  	}
	else {
	initialed = 1;
	return 0;
	}
}


int add_device(const char *device)
{
	pthread_mutex_lock(&mutex_mdi_lock);
	pthread_mutex_lock(&mutex_Devices_lock);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap_new = pcap_open_live(device,65536,1,10,errbuf);
	
	if(!pcap_new){
	std::cerr<<"Unable to open"<<device<<std::endl<<"error info: "<<errbuf;
	pthread_mutex_unlock(&mutex_Devices_lock);
	pthread_mutex_unlock(&mutex_mdi_lock);
	return -1;	
	}
	
	int pcap_fd = pcap_get_selectable_fd(pcap_new);
	if (pcap_fd == PCAP_ERROR) {
    	std::cerr<< "pcap_get_selectable_fd failed"<<std::endl;
    	pthread_mutex_unlock(&mutex_Devices_lock);
	pthread_mutex_unlock(&mutex_mdi_lock);
    	return -1;
  	}
  	
	
	Devices.emplace_back();
	Devices[Devices.size()-1].id = Devices.size()-1;
	Devices[Devices.size()-1].pcap = pcap_new;
	Devices[Devices.size()-1].device_name = device;
	
	
	if (pcap_setnonblock(pcap_new,1, errbuf) < 0) 
    	{
    	std::cerr<<"set nonblock error"<<std::endl;
    	pthread_mutex_unlock(&mutex_Devices_lock);
	pthread_mutex_unlock(&mutex_mdi_lock);
    	return -1;
    	}
       
        pthread_mutex_lock(&mutex_mfd_lock);
	mfd[pcap_fd] = Devices.size()-1;
	pthread_mutex_unlock(&mutex_mfd_lock);
  	
	struct epoll_event event;
 	event.events = EPOLLIN ;
 	event.data.fd = pcap_fd;
	int rv;
	rv = epoll_ctl(global_epfd, EPOLL_CTL_ADD, pcap_fd, &event);
 	
 	if (rv < 0) {
  	std::cerr << "epoll add failed"<<std::endl; 
  	pthread_mutex_unlock(&mutex_Devices_lock);
	pthread_mutex_unlock(&mutex_mdi_lock);
    	return -1;
  	}
	
	
	struct ifreq if_req;
	int fd = socket(AF_PACKET, SOCK_DGRAM,0);
	if_req.ifr_addr.sa_family = AF_INET;
	strncpy(if_req.ifr_name,device,IFNAMSIZ-1);
	ioctl(fd,SIOCGIFHWADDR,&if_req);
	close(fd);
	memcpy(Devices[Devices.size()-1].mac_addr,if_req.ifr_hwaddr.sa_data,6);
	
	struct ifaddrs * ifAddrStruct=NULL;
	getifaddrs(&ifAddrStruct);
    	while (ifAddrStruct!=NULL) {
        if (ifAddrStruct->ifa_addr->sa_family==AF_INET && !strcmp(ifAddrStruct->ifa_name,device)) { 
        
            Devices[Devices.size()-1].ip_addrs.insert((((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr).s_addr);
            pthread_mutex_lock(&mutex_self_ips_lock);
            self_ips.insert((((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr).s_addr);
            pthread_mutex_unlock(&mutex_self_ips_lock);
            pthread_mutex_lock(&mutex_ip_route_lock);
            route r;
            r.dev_id = Devices.size()-1;
            r.dst = (((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr).s_addr;
            r.mac_address = 0;
            for(int i=0;i<6;++i)
            {
            	r.mac_address +=((uint64_t)Devices[Devices.size()-1].mac_addr[i])<<(8*(5-i));
            }
            global_route_cost_table[r] = 0;
            
            pthread_mutex_unlock(&mutex_ip_route_lock);
            
        } 
        ifAddrStruct=ifAddrStruct->ifa_next;
        }
    
	mdi[device]=Devices.size()-1;
	int res = Devices.size()-1;
	pthread_mutex_unlock(&mutex_Devices_lock);
	pthread_mutex_unlock(&mutex_mdi_lock);
	return res;
}

int is_ether_frame_mine(uint8_t* dst, uint8_t* mac){
	
	int broadcast = 1;
	for(int i=0;i<6;++i)
	if (dst[i]!=0xff)
	broadcast = 0;
	
	int mac_matched = 1;
	for(int i=0;i<6;++i)
	if (dst[i]!=mac[i])
	mac_matched = 0;
	
	
	
	return mac_matched | broadcast;
	
}

int Device::read(){
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	while((res = pcap_next_ex(this->pcap, &header, &pkt_data)) >= 0){
        
        if(res == 0)
        return 0;
        
        
        if(eth_call_back_function){
        	return eth_call_back_function(pkt_data,header->len,this->id);        
        }
        else{
        std::cerr<<"NO callback function"<<std::endl;
        return -1;
        }
    	}
	return 0;
}

int default_ethcallbacker(const void *buf, int len, int id)
{
	if(!is_ether_frame_mine((uint8_t*)buf, get_device(id)->mac_addr))
        return 0;
        if(*(uint16_t*)((char*)buf+12) == 0x0008)
        {
        uint64_t mac_address = 0;
      	for(int i=0;i<6;++i)
      	mac_address += ((uint64_t)*(uint8_t*)((char*)buf+i+6) )<<(8*(5-i));
      	return default_ipcallbacker2((char*)buf+14,len-14,id,mac_address);
        }
        else
        { 
        //do whatever you want
        
        return 0;
        }
        
}

int read_epoll(int timeout){
  int res;
  res = epoll_wait(global_epfd, global_events, 256, timeout);
  if (res < 0) {
    std::cerr << "epoll_wait failed"<<std::endl;
    return -1;
  }
   
  if (res == 0) {
  
    return -1;
  }
  for (int i = 0; i < res; i++) {
    int fd = global_events[i].data.fd;
    if (global_events[i].events & EPOLLERR) {
      std::cerr<<  "fd: " << fd << "read fail";
    }
  get_device(get_device_id_from_fd(fd))->read();
  }
  return true;
}

 
#endif
