#ifndef POSIX_H_
#define POSIX_H_

#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "rip.h"
#include "tcp.h"
#include <unistd.h>

extern "C" {

int __wrap_socket(int domain, int type, int protocol);

int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);
                
int __wrap_listen(int socket, int backlog);

int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);

int __wrap_close(int fildes);

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);


int __real_socket(int domain, int type, int protocol);

int __real_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);

int __real_listen(int socket, int backlog);

int __real_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

int __real_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

ssize_t __real_read(int fildes, void *buf, size_t nbyte);

ssize_t __real_write(int fildes, const void *buf, size_t nbyte);

int __real_close(int fildes);

int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);
                       
}

struct partial_tcp_connection{
	uint32_t ip_addr;
	uint16_t port_num;
	int fd;
	int listening;
	int to_be_accept;
	pthread_mutex_t* mut;
	pthread_cond_t* cond;
	struct sockaddr *address;
};

std::list<session*> global_session_table;
std::map<int,session*> global_fd_to_session_map;
std::list<partial_tcp_connection> session_to_be_setup;

session* find_session(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port){
	pthread_mutex_lock(&global_session_table_lock);
	for(std::list<session*>::iterator iter=global_session_table.begin();iter!=global_session_table.end();++iter)
	{
		if((*iter)->src == src && (*iter)->dst == dst && (*iter)->src_port == src_port && (*iter)->dst_port == dst_port)
		{
		session* res = *iter;
		pthread_mutex_unlock(&global_session_table_lock);
		return res;
		}
	
	}
	pthread_mutex_unlock(&global_session_table_lock);
	return NULL;
}

session* add_session(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port){
	
	session* res = find_session(src, dst, src_port,dst_port);
	if(res!=NULL)
	return res;
	
	session* new_session = new session;
	new_session->src = src;
	new_session->dst = dst;
	new_session->src_port = src_port;
	new_session->dst_port = dst_port;
	pthread_mutex_lock(&global_session_table_lock);
	global_session_table.push_back(new_session);	
	pthread_mutex_unlock(&global_session_table_lock);
	return new_session;
}



session* find_session_by_fd(int fd){
	session* res;
	pthread_mutex_lock(&global_fd_to_session_map_lock);
	std::map<int,session*>::iterator iter;
	iter = global_fd_to_session_map.find(fd);
	if(iter == global_fd_to_session_map.end())
	res = NULL;
	else res = iter->second;
	pthread_mutex_unlock(&global_fd_to_session_map_lock);
	return res;
}


int remove_session(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port){
	pthread_mutex_lock(&global_session_table_lock);
	for(std::list<session*>::iterator iter=global_session_table.begin();iter!=global_session_table.end();++iter)
	{
		if((*iter)->src == src && (*iter)->dst == dst && (*iter)->src_port == src_port && (*iter)->dst_port == dst_port)
		{
		delete (*iter);
		global_session_table.erase(iter);
		pthread_mutex_unlock(&global_session_table_lock);
		return 0;
		}
	
	}
	pthread_mutex_unlock(&global_session_table_lock);
	return 0;
}


int find_fd(int fd){
	pthread_mutex_lock(&global_fd_to_session_map_lock);
  	int res = (global_fd_to_session_map.find(fd)!=global_fd_to_session_map.end());
  	pthread_mutex_unlock(&global_fd_to_session_map_lock);
  	return res;
}



partial_tcp_connection* find_unset_connection_by_ip_and_port(uint32_t ip_addr,uint16_t port_num){
	pthread_mutex_lock(&partial_tcp_connection_lock);
 	for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
		if((*iter).ip_addr == ip_addr && (*iter).port_num == port_num &&(*iter).listening == 1 && (*iter).to_be_accept == 0)
		{
			partial_tcp_connection* res =&(*iter);
 			pthread_mutex_unlock(&partial_tcp_connection_lock);
			return res;
		}
	
	}
 	pthread_mutex_unlock(&partial_tcp_connection_lock);
	return NULL;  
}


int remove_unset_connection_by_fd(int fd){
	pthread_mutex_lock(&partial_tcp_connection_lock);
 	for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
		if((*iter).fd == fd)
		{
			session_to_be_setup.erase(iter);
 			pthread_mutex_unlock(&partial_tcp_connection_lock);
			return 0;
		}
	
	}
 	pthread_mutex_unlock(&partial_tcp_connection_lock);
	return 0;  
}


int tcp_dispatcher(const void* buf,int len){
	ip_header* ip_head = (ip_header*) buf;
	tcp_header* tcp_head = (tcp_header*)((char*)buf + sizeof(ip_header));
	partial_tcp_connection* connection = find_unset_connection_by_ip_and_port(ip_head->dst_addr, tcp_head->dst_port);
		
	if(connection == NULL)
		{
		session* session_determined = find_session(ip_head->dst_addr,ip_head->src_addr,tcp_head->dst_port,tcp_head->src_port);
		if(session_determined == NULL)
		{
			return 0;		
  		
		}
		else
		{
			return session_determined->process_packet((char*)buf + sizeof(ip_header),len-sizeof(ip_header));
		}
		}
		
	if(!(tcp_head->flags & 2)||(tcp_head->flags &16))
		return 0;
		
	session* new_session = add_session(ip_head->dst_addr,ip_head->src_addr,tcp_head->dst_port,tcp_head->src_port);
  	
  	new_session->add_notify_for_syn_ack(connection->mut,connection->cond);
  	new_session->ready_for_connection();
  	
  	pthread_mutex_lock(&global_fd_to_session_map_lock);
	global_fd_to_session_map[connection->fd] = new_session;
  	pthread_mutex_unlock(&global_fd_to_session_map_lock);
  	
  	pthread_mutex_lock(&partial_tcp_connection_lock);
        new_session->process_packet((char*)buf + sizeof(ip_header),len-sizeof(ip_header));
  	connection->to_be_accept = 1;
  	pthread_mutex_unlock(&partial_tcp_connection_lock);
        
  	connection->address = new sockaddr;	
  	((struct sockaddr_in*)(connection->address))->sin_family = AF_INET;
  	((struct sockaddr_in*)(connection->address))->sin_port = tcp_head->src_port;
  	(((struct sockaddr_in*)(connection->address))->sin_addr).s_addr = ip_head->src_addr;
  		
  	return 0;
	
}

int __wrap_socket(int domain, int type, int protocol) {
  if ((domain != AF_INET) || (type != SOCK_STREAM) ||(protocol != 0 && protocol != IPPROTO_TCP))
    return __real_socket(domain, type, protocol);

  int fd = dup(null_fd);
  pthread_mutex_lock(&global_fd_to_session_map_lock);
  global_fd_to_session_map[fd] = NULL;
  pthread_mutex_unlock(&global_fd_to_session_map_lock);
  return fd;
}


int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
  if (!find_fd(socket)) 
    return __real_bind(socket, address, address_len);
  
  if(address->sa_family != AF_INET || address_len < static_cast<socklen_t>(sizeof(sockaddr_in)))
  {
  	std::cerr<<"parameter not suitable for binding!"<<std::endl;
  	return EINVAL;
  }
  
  if(find_session_by_fd(socket))
  {
  	return EALREADY;
  }
  
  pthread_mutex_lock(&partial_tcp_connection_lock);
  for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
		if((*iter).fd == socket)
		{
 			pthread_mutex_unlock(&partial_tcp_connection_lock);
			return EALREADY;
		}
	
	}
 
  partial_tcp_connection connection;
  connection.ip_addr = (((sockaddr_in*)address)->sin_addr).s_addr;
  connection.port_num = ((sockaddr_in*)address)->sin_port;
  connection.fd = socket;
  connection.mut = NULL;
  connection.cond = NULL;
  connection.address = NULL;
  connection.to_be_accept = 0;
  connection.listening = 0;
  session_to_be_setup.push_back(connection);
  pthread_mutex_unlock(&partial_tcp_connection_lock);
  
  return 0;
}

int __wrap_listen(int socket, int backlog) {
  if (!find_fd(socket)) {
    return __real_listen(socket, backlog);
  }
  
  if(find_session_by_fd(socket))
  return EINVAL;
 
  pthread_mutex_lock(&partial_tcp_connection_lock);
  for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
		if((*iter).fd == socket)
		{
			  if((*iter).listening)
			  {
			  pthread_mutex_unlock(&partial_tcp_connection_lock);
			  return 0;
			  }
			  (*iter).mut = new pthread_mutex_t;
			  (*iter).cond = new pthread_cond_t;
			  (*iter).listening = 1;
			  pthread_mutex_t* mut = (*iter).mut;
			  pthread_cond_t* cond = (*iter).cond;
			  
			  pthread_mutex_init(mut,NULL);
			  pthread_cond_init(cond,NULL);
			  
  		          pthread_mutex_unlock(&partial_tcp_connection_lock);
			  return 0;			
		}
	}
  pthread_mutex_unlock(&partial_tcp_connection_lock);
  return EINVAL;	
}


int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
  if (!find_fd(socket)) {
    return __real_accept(socket, address, address_len);
  }
  
  if(find_session_by_fd(socket))
  return EINVAL;
    
  
  pthread_mutex_lock(&partial_tcp_connection_lock);
 	for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
		if((*iter).fd == socket)
		{
			if((*iter).to_be_accept == 0)
			{
				pthread_mutex_lock((*iter).mut);
				pthread_mutex_unlock(&partial_tcp_connection_lock);	
				pthread_cond_wait((*iter).cond,(*iter).mut);
				pthread_mutex_unlock((*iter).mut);
			}
			else
			{
				pthread_mutex_unlock(&partial_tcp_connection_lock);	
			}

			pthread_cond_destroy((*iter).cond);
			delete (*iter).mut;
			delete (*iter).cond;
			
			if(address)
			*address = *((*iter).address);
			delete (*iter).address;
			
			if(address_len)
			*address_len = sizeof(sockaddr_in);

			pthread_mutex_lock(&partial_tcp_connection_lock);	
			session_to_be_setup.erase(iter);	
			pthread_mutex_unlock(&partial_tcp_connection_lock);	
				
			return 0;
		}
	
	}
  
  		
  	
  pthread_mutex_unlock(&partial_tcp_connection_lock);
  return EINVAL;					
}

int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    if (!find_fd(socket)) {
      return __real_connect(socket, address, address_len);
    }
  
    if(address->sa_family != AF_INET || address_len < static_cast<socklen_t>(sizeof(sockaddr_in)))
    {
  	std::cerr<<"parameter not suitable for binding!\n"<<std::endl;
  	return EINVAL;
    }
  
    if(find_session_by_fd(socket))
    {
  	return EISCONN;
    }
    
     
    srand((int)(time(0)));
    uint16_t port_num = rand();
    uint32_t ip = ~0;
    pthread_mutex_lock(&mutex_self_ips_lock);
    if(!self_ips.empty()) ip = *(self_ips.begin());
    pthread_mutex_unlock(&mutex_self_ips_lock);
    
    session* new_session;         
    new_session = add_session(ip,(((sockaddr_in*)address)->sin_addr).s_addr,port_num,((sockaddr_in*)address)->sin_port);
     	
    pthread_mutex_t mutex;	
    pthread_cond_t cond;
  			
    pthread_mutex_init(&mutex,NULL);
    pthread_cond_init(&cond,NULL);
    pthread_mutex_lock(&mutex); 			
  			
    new_session->add_notify_for_syn_ack(&mutex,&cond);
    
    if(new_session->set_up_connection())
    {
    return EADDRINUSE;   
    }
    pthread_mutex_lock(&global_fd_to_session_map_lock);
    global_fd_to_session_map[socket] = new_session;
    pthread_mutex_unlock(&global_fd_to_session_map_lock);  	
    
    struct timeval now;
    struct timespec outtime;
    gettimeofday(&now, NULL);
    outtime.tv_sec = now.tv_sec + 15;
    outtime.tv_nsec = now.tv_usec * 1000;
    int res = pthread_cond_timedwait(&cond,&mutex,&outtime);
    pthread_mutex_unlock(&mutex);
    pthread_cond_destroy(&cond);
    if(res == ETIMEDOUT)
    {
	    pthread_mutex_lock(&global_fd_to_session_map_lock);
  	    global_fd_to_session_map[socket] = NULL;
  	    pthread_mutex_unlock(&global_fd_to_session_map_lock);
	    return res;
    }
    else return 0;

}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte){
	if (!find_fd(fildes)) {
	      return __real_read(fildes, buf, nbyte);	
	}
	
	session* new_session = find_session_by_fd(fildes);
	if(new_session == NULL)
	return 0;
	else return new_session->read_data(buf, nbyte);
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte){
	if (!find_fd(fildes)) {
	      return __real_write(fildes, buf, nbyte);	
	}
	
	
	session* new_session = find_session_by_fd(fildes);
	
	if(new_session == NULL)
	return 0;
	
	else 
	{
	int res= new_session->send_data(buf,nbyte);
	if(res)
	return 0;
	else return nbyte;
	}
}

int __wrap_close(int fildes){
	
	int res = __real_close(fildes);
	session* new_session = find_session_by_fd(fildes);
	
	if(new_session == NULL)
	return res;
	
	
	else
	{
	new_session->close_connection();
	pthread_mutex_lock(&global_fd_to_session_map_lock);
	global_fd_to_session_map.erase(global_fd_to_session_map.find(fildes));
	pthread_mutex_unlock(&global_fd_to_session_map_lock);
	
	return res;		
	}

}

int get_ip_from_node(const char* node,uint32_t* res){
	uint32_t i1,i2,i3,i4;
	if(sscanf(node,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4)
	{
	return -1;
	}
	else
	{
	*res = i1 + (i2<<8) + (i3<<16) + (i4<<24);
	return 0;
	}

}

int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
	
	uint32_t ip_addr = 0;
	uint32_t port = 0;
	
	if((hints && (hints->ai_family != AF_INET || hints->ai_socktype != SOCK_STREAM|| hints->ai_protocol != IPPROTO_TCP || hints->ai_flags != 0) )|| (node && get_ip_from_node(node, &ip_addr)) || (service && sscanf(service,"%d",&port)!=1) )
	{
		return __real_getaddrinfo(node,service,hints,res);
	}
	
	if(!node && !service)
	{
		return EAI_NONAME;
	}
	
	addrinfo* curpointer = NULL;
	
	pthread_mutex_lock(&global_session_table_lock);
	for(std::list<session*>::iterator iter=global_session_table.begin();iter!=global_session_table.end();++iter)
		{
			if((!service && ip_addr == (*iter)->dst)||(service && port && ip_addr == (*iter)->dst &&(*iter)->dst_port))
			{
				if(curpointer)
				{
					curpointer->ai_next = new addrinfo;
					curpointer = curpointer->ai_next;
				}
				else
				{
					curpointer = new addrinfo;
					*res = curpointer;
				}
				curpointer->ai_family = AF_INET;
				curpointer->ai_socktype = SOCK_STREAM;
				curpointer->ai_protocol = IPPROTO_TCP;
				curpointer->ai_flags = 0;
				curpointer->ai_addrlen = sizeof(sockaddr_in);
				curpointer->ai_canonname = NULL;
				curpointer->ai_addr = new sockaddr;
				((sockaddr_in*)(curpointer->ai_addr))->sin_family = AF_INET;
				((sockaddr_in*)(curpointer->ai_addr))->sin_port = (*iter)->dst_port;
				(((sockaddr_in*)(curpointer->ai_addr))->sin_addr).s_addr = (*iter)->dst;
				curpointer->ai_next = NULL;
			}
		}
	pthread_mutex_unlock(&global_session_table_lock);
	
	pthread_mutex_lock(&partial_tcp_connection_lock);
 	for(std::list<partial_tcp_connection>::iterator iter=session_to_be_setup.begin();iter!=session_to_be_setup.end();++iter)
	{
			if(!node && port == (*iter).port_num)
			{
				if(curpointer)
				{
					curpointer->ai_next = new addrinfo;
					curpointer = curpointer->ai_next;
				}
				else
				{
					curpointer = new addrinfo;
					*res = curpointer;
				}
				curpointer->ai_family = AF_INET;
				curpointer->ai_socktype = SOCK_STREAM;
				curpointer->ai_protocol = IPPROTO_TCP;
				curpointer->ai_flags = AI_PASSIVE;
				curpointer->ai_addrlen = sizeof(sockaddr_in);
				curpointer->ai_canonname = NULL;
				curpointer->ai_addr = new sockaddr;
				((sockaddr_in*)(curpointer->ai_addr))->sin_family = AF_INET;
				((sockaddr_in*)(curpointer->ai_addr))->sin_port = (*iter).port_num;
				(((sockaddr_in*)(curpointer->ai_addr))->sin_addr).s_addr = (*iter).ip_addr;
				curpointer->ai_next = NULL;
			}
		}
	pthread_mutex_unlock(&partial_tcp_connection_lock);
 	return 0;	
}



#endif
