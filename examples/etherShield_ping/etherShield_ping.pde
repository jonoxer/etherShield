#include "etherShield.h"

// please modify the following two lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {
  0x54,0x55,0x58,0x10,0x00,0x24}; 
static uint8_t myip[4] = {
  192,168,1,15};
// how did I get the mac addr? Translate the first 3 numbers into ascii is: TUX

#define BUFFER_SIZE 250
unsigned char buf[BUFFER_SIZE+1];

uint16_t plen;

EtherShield es=EtherShield();


void setup(){

 
 
  /*initialize enc28j60*/
  es.ES_enc28j60Init(mymac);
  es.ES_enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
 
  delay(10);

  /* Magjack leds configuration, see enc28j60 datasheet, page 11 */
  // LEDA=green LEDB=yellow
  //
  // 0x880 is PHLCON LEDB=on, LEDA=on
  // enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x880);
  delay(500);
 
  //
  // 0x990 is PHLCON LEDB=off, LEDA=off
  // enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x990);
  delay(500);
 
  //
  // 0x880 is PHLCON LEDB=on, LEDA=on
  // enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x880);
  delay(500);
 
  //
  // 0x990 is PHLCON LEDB=off, LEDA=off
  // enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
  es.ES_enc28j60PhyWrite(PHLCON,0x990);
  delay(500);
 
  //
  // 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
  // enc28j60PhyWrite(PHLCON,0b0000 0100 0111 01 10);
  es.ES_enc28j60PhyWrite(PHLCON,0x476);
  delay(100);
 
  //init the ethernet/ip layer:
  es.ES_init_ip_arp_udp_tcp(mymac,myip,80);
 

}

void loop(){

  plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

  /*plen will be unequal to zero if there is a valid packet (without crc error) */
  if(plen!=0){
       if(es.ES_eth_type_is_arp_and_my_ip(buf,plen)){
      	es.ES_make_arp_answer_from_request(buf);
      }
      // check if ip packets (icmp or udp) are for us:
      if(es.ES_eth_type_is_ip_and_my_ip(buf,plen)!=0){
         if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V){
         		// a ping packet, let's send pong
          
            es.ES_make_echo_reply_from_request(buf,plen);
   		    }
      }
 
  }  
}
