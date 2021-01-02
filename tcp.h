#ifndef TCP_H_
#define TCP_H_

#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "rip.h"
#include <list>
#include <unistd.h>
#include <signal.h>

enum session_state {
  CLOSED,
  LISTEN,
  SYN_RECEIVED,
  SYN_SENT,
  ESTAB,
  FIN_WAIT_1,
  CLOSE_WAIT,
  FIN_WAIT_2,
  CLOSING,
  LAST_ACK,
  TIME_WAIT,
  
};


struct __attribute__((packed)) tcp_header{
  uint16_t src_port ;
  uint16_t dst_port ;
  uint32_t seq_number;
  uint32_t ack_number;
  uint8_t data_offset_and_reserved;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
};


struct __attribute__((packed)) pseudo_tcp_header{
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t zeros;
  uint8_t protocol;
  uint16_t length;
};


struct lock_helper{
	pthread_cond_t* cond;
	pthread_mutex_t* mut;
};


struct sending_info{
	uint32_t src_addr;
	uint32_t dst_addr;
	void* buf;
	int len;
	struct lock_helper lock;
	uint32_t unacked_number;
	std::list<uint32_t>* unacked_number_pointer;
	std::list<lock_helper>* unacked_lock_helper_pointer;
	pthread_mutex_t* unacked_lock;
	pthread_mutex_t* syn_ack_mut;
	pthread_cond_t* syn_ack_cond;
	int is_syn_ack;
	int* syn_ack_notify;
};

struct close_time_wait_info{
	session_state* state;
	pthread_mutex_t* state_lock;
};

struct session{
	session();
	~session();
	uint32_t src;	
	uint32_t dst;
	uint16_t src_port;
	uint16_t dst_port;
	pthread_mutex_t unacked_lock;
	std::list<uint32_t> unacked_number;
	std::list<lock_helper> unacked_lock_helper;
	pthread_mutex_t state_lock;
	enum session_state state = session_state::CLOSED;
	pthread_mutex_t sequence_number_lock;
	pthread_mutex_t last_ack_lock;
	uint32_t sequence_number_now;
	uint32_t last_ack;
	pthread_mutex_t length_lock;
	pthread_mutex_t buffer_lock;
	int length;
	int ack_head;
	char* buffer;
	pthread_mutex_t* syn_ack_mut;
	pthread_cond_t* syn_ack_cond;
	int syn_ack_notify;
	pthread_t closing_thread_id;
	 
	int sendTCPPacket(uint32_t ack_number,uint8_t option, const void *buf, int len, int FIN_ACK);
	int process_packet(const void *buf, int len);
	int shutdown();
	int set_up_connection();
	int ready_for_connection();
	int close_connection();
	int send_data(const void* buf, int len);
	int read_data(void* buf, int len);
	int add_notify_for_syn_ack(pthread_mutex_t* mut,pthread_cond_t* cond);
};



session::session(){
	pthread_mutex_init(&unacked_lock,NULL);
	pthread_mutex_init(&state_lock,NULL);
	pthread_mutex_init(&sequence_number_lock,NULL);
	pthread_mutex_init(&last_ack_lock,NULL);
	pthread_mutex_init(&length_lock,NULL);
	pthread_mutex_init(&buffer_lock,NULL);
	srand((int)time(0));
	sequence_number_now = rand();
	last_ack = 0;
	length = 0;
	ack_head = 0;
	buffer = new char[65536];
	syn_ack_mut = NULL;
	syn_ack_cond = NULL;
	syn_ack_notify = 0;
}

session::~session(){
	this->shutdown();
	delete [] buffer;
}

void* sending_thread(void* arg)
{
	pthread_detach(pthread_self());
	sending_info* info = (sending_info*) arg;
	struct in_addr src,dst;
	src.s_addr = info->src_addr;
    	dst.s_addr = info->dst_addr;
    	
    	
    	
    	std::list<uint32_t>::iterator num_iter;
    	std::list<lock_helper>::iterator lock_iter;
    	
	pthread_mutex_lock(info->unacked_lock);
	sendIPPacket(src, dst, 6, info->buf, info->len);
    	(info->unacked_number_pointer)->push_back(info->unacked_number);
    	(info->unacked_lock_helper_pointer)->push_back(info->lock);
    	pthread_mutex_unlock(info->unacked_lock);	
 	
 	lock_helper lock = info->lock;
    	
    	struct timeval now;
    	struct timespec outtime;
    	gettimeofday(&now, NULL);
	outtime.tv_sec = now.tv_sec + 1;
	outtime.tv_nsec = now.tv_usec * 1000;
    	
    	pthread_mutex_lock(lock.mut);
    	while(pthread_cond_timedwait(lock.cond,lock.mut,&outtime)==ETIMEDOUT)
    	{
    		sendIPPacket(src, dst, 6, info->buf, info->len);
    		outtime.tv_sec = outtime.tv_sec+1;
    	}
 	pthread_mutex_unlock(lock.mut);
 	
 	if(info->is_syn_ack && info->syn_ack_mut && info->syn_ack_cond && *(info->syn_ack_notify))
 	{
 		*(info->syn_ack_notify) = 0;	
 		pthread_mutex_lock(info->syn_ack_mut);
  		pthread_cond_signal(info->syn_ack_cond);
  		pthread_mutex_unlock(info->syn_ack_mut);
  		
 	}
 	pthread_cond_destroy(lock.cond);
	delete lock.mut;
	delete lock.cond;		
 		
 	delete [] ((char*)(info->buf)-12);
 	delete (sending_info*) arg;
 	
 	pthread_exit(0);
}

void* close_time_wait(void* arg){
	
	pthread_detach(pthread_self());
	sleep(2);
	close_time_wait_info* info = (close_time_wait_info*) arg;
	pthread_mutex_lock(info->state_lock);
	*(info->state)= session_state::CLOSED;
	pthread_mutex_unlock(info->state_lock);
	delete info;
	pthread_exit(0);
}

int session::sendTCPPacket(uint32_t ack_number,uint8_t option, const void *buf, int len, int FIN_ACK)
{
		
	//send_buf is recycled by the thread
	
	pthread_mutex_lock(&state_lock);
    	if(this->state == session_state::CLOSED)
    	{
    		if(option & 2)
    		{
    			this->state = session_state::SYN_SENT;
    		}
    		else
    		{
    			pthread_mutex_unlock(&state_lock);
    			std::cerr<<"Undefined sending behaviour in the state CLOSED"<<std::endl;
    			return -1;
    		}
    	
    	}	
	else if(this->state == session_state::LISTEN)
	{
		if((option & 2) && (option & 16))
		{
			this->state = session_state::SYN_RECEIVED;
		}
		else if(option & 2)
		{
			this->state = session_state::SYN_SENT;
		}				
		else
		{
			pthread_mutex_unlock(&state_lock);
			std::cerr<<"Undefined sending behaviour in the state LISTEN"<<std::endl;
    			return -1;
		}			
					
	}
	else if(this->state == session_state::SYN_SENT)
	{
		if((option & 16)&&(option & 2))
		{
			this->state = session_state::SYN_RECEIVED;
		}
		else if((option & 16) )
		{
			this->state = session_state::ESTAB;
		}				
		else
		{
			pthread_mutex_unlock(&state_lock);
    			std::cerr<<"Undefined sending behaviour in the state SYN_SENT"<<std::endl;
    			return -1;
		}
	}
	else if(this->state == session_state::ESTAB)
	{
		if(option & 1)
		{
			this->state = session_state::FIN_WAIT_1;
		}
		else if((option & 16) && FIN_ACK)
		{
			this->state = session_state::CLOSE_WAIT;
		}	
	}
	else if(this->state == session_state::FIN_WAIT_1)
	{
		if((option & 16))
		{
			this->state = session_state::CLOSING;
		}				
		else
		{
			pthread_mutex_unlock(&state_lock);
    			std::cerr<<"Undefined sending behaviour in the state FIN_WAIT_1"<<std::endl;
    			return -1;
		}	
	}
	else if(this->state == session_state::CLOSE_WAIT)
	{
		if((option & 1))
		{
			this->state = session_state::LAST_ACK;
		}				
		else
		{
			pthread_mutex_unlock(&state_lock);
    			std::cerr<<"Undefined sending behaviour in the state CLOSE_WAIT"<<std::endl;
    			return -1;
		}		
	}
	else if(this->state == session_state::FIN_WAIT_2)
	{
		if((option & 16))
		{
			this->state = session_state::TIME_WAIT;
			pthread_t closing_thread;
			close_time_wait_info* close_info = new close_time_wait_info;
			close_info->state = &(this->state);
			close_info->state_lock = &(this->state_lock);
			pthread_create(&closing_thread,0,close_time_wait,close_info);
			this->closing_thread_id = closing_thread;
		}				
		else
		{
			pthread_mutex_unlock(&state_lock);
    			std::cerr<<"Undefined sending behaviour in the state FIN_WAIT_2"<<std::endl;
    			return -1;
		}			
	}
	else
	{
		pthread_mutex_unlock(&state_lock);
    		std::cerr<<"Session state not suitable for sending "<< this->state <<std::endl;
		return -1;
	}
	pthread_mutex_unlock(&state_lock);
    	
	char* send_buf = new char[len+32];
	
	pseudo_tcp_header* pseudo_tcp_head = (pseudo_tcp_header*) send_buf;
	pseudo_tcp_head->src_addr = this->src;
	pseudo_tcp_head->dst_addr = this->dst;
	pseudo_tcp_head->zeros = 0;
	pseudo_tcp_head->protocol = 6;
	pseudo_tcp_head->length = endian_reverse_16(len+20);
	
	tcp_header* tcp_head = (tcp_header*) (send_buf+12);
	tcp_head->src_port = this->src_port;
	tcp_head->dst_port = this->dst_port;
	tcp_head->ack_number = endian_reverse_32(ack_number);
	tcp_head->data_offset_and_reserved = 0x50;
	tcp_head->flags = option;
	tcp_head->window = 65535;
	tcp_head->checksum = 0;
	tcp_head->urgent_pointer = 0;
	
	
	
    	
	if(len!=0)
	memcpy(send_buf+32,buf,len);
	
	
    	if((option & 16) && !(option & 2))
    	{
    		pthread_mutex_lock(&sequence_number_lock);
    		tcp_head->seq_number = endian_reverse_32(this->sequence_number_now);
		pthread_mutex_unlock(&sequence_number_lock);
    		
		tcp_head->checksum = cal_16_bit_check_sum((uint16_t*) send_buf,len+32);
    	
    		struct in_addr src,dst;
		src.s_addr = this->src;
    		dst.s_addr = this->dst;
    		sendIPPacket(src, dst, 6, send_buf+12, len+20);
    		delete [] send_buf;
    		
    	}
    	else
    	{
    	struct lock_helper lock;
    	lock.mut = NULL;
    	lock.cond = NULL;
    	
    	pthread_mutex_lock(&(this->sequence_number_lock));
    	uint32_t unacked_number = this->sequence_number_now;
    	if(option & 3)
    	{
    		unacked_number++;
    	}
    	else
    	{
    		unacked_number += len;	
    	}
    	tcp_head->seq_number = endian_reverse_32(this->sequence_number_now);
    	this->sequence_number_now = unacked_number;
    	pthread_mutex_unlock(&(this->sequence_number_lock));
    	
    	tcp_head->checksum = cal_16_bit_check_sum((uint16_t*) send_buf,len+32);
    	
    	pthread_t  send_thread;
    	lock.mut = new pthread_mutex_t;
    	lock.cond = new pthread_cond_t;
    	
    	
    	
    	pthread_mutex_init(lock.mut,NULL);	
    	pthread_cond_init(lock.cond,NULL);	
    	
    	struct sending_info*  info = new sending_info;
	info->src_addr = this->src;
    	info->dst_addr = this->dst;
    	info->buf = send_buf+12;
    	info->len = len+20;
    	info->lock = lock;
    	info->unacked_number = unacked_number;
    	info->unacked_number_pointer = &(this->unacked_number);
	info->unacked_lock_helper_pointer = &(this->unacked_lock_helper);
	info->unacked_lock = &(this->unacked_lock);
	info->is_syn_ack = (option & 2);
	info->syn_ack_mut = this->syn_ack_mut;
    	info->syn_ack_cond = this->syn_ack_cond;
    	info->syn_ack_notify = &(this->syn_ack_notify);
    	
    	pthread_create(&send_thread,NULL,sending_thread,info);
    	
    	
    	}
    	
    	return 0;		
}




int session::process_packet(const void* buf,int len){
	tcp_header* tcp_head = (tcp_header*) buf;
	
	if(tcp_head->flags & 4)
	{
		return this->shutdown();
	}
	
	int ack_number = 0;
	pthread_mutex_lock(&last_ack_lock);
	if(!(tcp_head->flags & 16)||(tcp_head->flags & 2))
	{
		
		if(tcp_head->flags & 3)
	    	{
	   		this->last_ack = endian_reverse_32(tcp_head->seq_number) + 1;
	   	}
    		else
  	 	{
  	 		this->last_ack = endian_reverse_32(tcp_head->seq_number) + len-20;
  	 	}
  	 	
        }
        ack_number = this->last_ack;
        pthread_mutex_unlock(&last_ack_lock);
    	
    		
    		
	if(tcp_head->flags & 16)
	{
		uint32_t ack_num = endian_reverse_32(tcp_head->ack_number);
		pthread_mutex_lock(&(this->unacked_lock));
		std::list<uint32_t>::iterator num_iter = unacked_number.begin();
		std::list<lock_helper>::iterator lock_iter = unacked_lock_helper.begin();
		int finded = 0;
		for(;num_iter!=unacked_number.end();)
		{
			if(ack_num!=*num_iter)
			{
				++num_iter;
				++lock_iter;
			}
			else
			{
				finded = 1;
				pthread_mutex_t* mut = (*lock_iter).mut;
				pthread_cond_t* cond = (*lock_iter).cond;
				pthread_mutex_unlock(&unacked_lock);
				pthread_mutex_lock(mut);
				pthread_cond_signal(cond);
				unacked_number.erase(num_iter);
				unacked_lock_helper.erase(lock_iter);
				pthread_mutex_unlock(mut);
				break;
			}
		
		}
		
		if(!finded)
		pthread_mutex_unlock(&unacked_lock);
			
		
    		pthread_mutex_lock(&state_lock);
		
		if(state == session_state::SYN_SENT)
		{	
			if((tcp_head->flags & 2) && (endian_reverse_32(tcp_head->ack_number)==this->sequence_number_now))
			{
				pthread_mutex_unlock(&state_lock);
				pthread_mutex_lock(&length_lock);
  	 			ack_head = ack_number;
  	 			pthread_mutex_unlock(&length_lock);
  	 	
				return this->sendTCPPacket(ack_number,16,NULL,0,0);
			}				
			
		}
		else if(state == session_state::SYN_RECEIVED)
		{	
			if(endian_reverse_32(tcp_head->ack_number)==this->sequence_number_now)
			{
				this->state = session_state::ESTAB;
			}				
			
		}
		else if(this->state == session_state::ESTAB)
		{
			//do nothing	
		}
		else if(this->state == session_state::FIN_WAIT_1)
		{
			if(endian_reverse_32(tcp_head->ack_number)==this->sequence_number_now)
			{
				this->state = session_state::FIN_WAIT_2;
			}				
				
		}
		else if(this->state == session_state::CLOSING)
		{
			if(endian_reverse_32(tcp_head->ack_number)==this->sequence_number_now)
			{
				this->state = session_state::TIME_WAIT;
				pthread_t closing_thread;
				close_time_wait_info* close_info = new close_time_wait_info;
				close_info->state = &(this->state);
				close_info->state_lock = &(this->state_lock);
				pthread_create(&closing_thread,0,close_time_wait,close_info);
				this->closing_thread_id = closing_thread;
			}		
		}
		else if(this->state == session_state::LAST_ACK)	
		{
			if(endian_reverse_32(tcp_head->ack_number)==this->sequence_number_now)	
			{
				this->state = session_state::CLOSED;	
			}				
						
		}
		
		pthread_mutex_unlock(&state_lock);	
		return 0;	
	}
	else
	{
		pthread_mutex_lock(&state_lock);
		if(state == session_state::LISTEN)
		{	
			if(tcp_head->flags & 2) 
			{
				pthread_mutex_unlock(&state_lock);
				pthread_mutex_lock(&length_lock);
  	 			ack_head = ack_number;
  	 			pthread_mutex_unlock(&length_lock);
  	 	
				return this->sendTCPPacket(ack_number,16|2,NULL,0,0);
			}				
			
		}
		else if(state == session_state::SYN_SENT)
		{	
			if(tcp_head->flags & 2)
			{
				pthread_mutex_unlock(&state_lock);
				pthread_mutex_lock(&length_lock);
  	 			ack_head = ack_number;
  	 			pthread_mutex_unlock(&length_lock);
  	 	
				return this->sendTCPPacket(ack_number,16|2,NULL,0,0);
			}				
			
		}
		else if(this->state == session_state::ESTAB)
		{
			if(tcp_head->flags & 1)
			{
				pthread_mutex_unlock(&state_lock);
				this->sendTCPPacket(ack_number,16,NULL,0,1);
				return this->sendTCPPacket(ack_number,1,NULL,0,0);
			}
			else
			{
				pthread_mutex_unlock(&state_lock);
				
				pthread_mutex_lock(&length_lock);
				if(len-sizeof(tcp_header)+this->length > 65536 || endian_reverse_32(tcp_head->seq_number)!=ack_head)
				{
					pthread_mutex_unlock(&length_lock);
					return 0;
				}
				else
				{
					ack_head = endian_reverse_32(tcp_head->seq_number) + len-sizeof(tcp_header);
					pthread_mutex_lock(&buffer_lock);
					memcpy((this->buffer)+(this->length),(char*)buf+sizeof(tcp_header),len-sizeof(tcp_header));
					length += len-sizeof(tcp_header);
					pthread_mutex_unlock(&buffer_lock);
					pthread_mutex_unlock(&length_lock);
				}
				return this->sendTCPPacket(ack_number,16,NULL,0,0);			
			}	
		}
		else if(this->state == session_state::FIN_WAIT_1)
		{
			if(tcp_head->flags & 1)
			{
				pthread_mutex_unlock(&state_lock);
				return this->sendTCPPacket(ack_number,16,NULL,0,0);
			}				
				
		}
		else if(this->state == session_state::FIN_WAIT_2)
		{
			if(tcp_head->flags & 1)
			{
				pthread_mutex_unlock(&state_lock);
				return this->sendTCPPacket(ack_number,16,NULL,0,0);
			}				
			
		}
		pthread_mutex_unlock(&state_lock);	
		return 0;
	}
}

int session::shutdown(){
	pthread_mutex_lock(&unacked_lock);
	while(!unacked_number.empty())
		{
			
			pthread_mutex_t* mut = (*unacked_lock_helper.begin()).mut;
			pthread_cond_t* cond = (*unacked_lock_helper.begin()).cond;
			pthread_mutex_unlock(&unacked_lock);
			
			pthread_mutex_lock(mut);
			pthread_cond_signal(cond);
			unacked_number.erase(unacked_number.begin());
			unacked_lock_helper.erase(unacked_lock_helper.begin());
			pthread_mutex_unlock(mut);
			
			pthread_mutex_lock(&unacked_lock);
		}
	pthread_mutex_unlock(&unacked_lock);
	
	pthread_mutex_lock(&state_lock);
	if(this->state == session_state::TIME_WAIT)
	{
		pthread_kill(this->closing_thread_id,SIGKILL);
	}
	this->state = session_state::CLOSED;
	pthread_mutex_unlock(&state_lock);
	
	pthread_mutex_lock(&last_ack_lock);
	this->last_ack = 0;
	pthread_mutex_unlock(&last_ack_lock);
	
	pthread_mutex_lock(&length_lock);
	this->length = 0;
	pthread_mutex_unlock(&length_lock);
	
	this->syn_ack_mut = NULL;
	this->syn_ack_cond = NULL;
	
	return 0;		
}


int session::set_up_connection(){
	pthread_mutex_lock(&state_lock);
	if(state!=session_state::CLOSED)
	{
	pthread_mutex_unlock(&state_lock);
	return -1;
	}
	else
	{
	pthread_mutex_unlock(&state_lock);
	return sendTCPPacket(this->last_ack,2,NULL,0,0);
	}
}


int session::ready_for_connection(){
	int res;
	pthread_mutex_lock(&state_lock);
	if(state == session_state::CLOSED)
	{
	res = 0;
	this->state = session_state::LISTEN;
	}
	else
	res = -1;
	pthread_mutex_unlock(&state_lock);
	return res;
}

int session::close_connection(){
       pthread_mutex_lock(&state_lock);
	if(state!=session_state::ESTAB)
	{
	pthread_mutex_unlock(&state_lock);
	return -1;
	}
	else
	{
	pthread_mutex_unlock(&state_lock);
	return sendTCPPacket(this->last_ack,1,NULL,0,0);
	}
}

int session::send_data(const void* buf,int len){
	return sendTCPPacket(this->last_ack,0,buf,len,0);
}

int session::read_data(void* buf, int len){
	if(len >= length)
	{
		int res = length;
		pthread_mutex_lock(&length_lock);
		pthread_mutex_lock(&buffer_lock);
		memcpy(buf,this->buffer,length);
		length = 0;
		pthread_mutex_unlock(&buffer_lock);
		pthread_mutex_unlock(&length_lock);
		return res;
	}
	else
	{
		pthread_mutex_lock(&length_lock);
		pthread_mutex_lock(&buffer_lock);
		memcpy(buf,this->buffer,len);
		memmove(this->buffer,this->buffer+len,length-len);
		length -= len;
		pthread_mutex_unlock(&buffer_lock);
		pthread_mutex_unlock(&length_lock);
		return len;
	}
}


int session::add_notify_for_syn_ack(pthread_mutex_t* mut,pthread_cond_t* cond){
	syn_ack_mut = mut;
	syn_ack_cond = cond;	
	syn_ack_notify = 1; 
	return 0;
}	

#endif
























