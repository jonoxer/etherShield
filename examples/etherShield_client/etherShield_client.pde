#include "etherShield.h"

// please modify the following lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x24}; 
static uint8_t myip[4] = {192,168,1,88};
static uint16_t my_port = 1200;     // client port

// client_ip - modify it when you have multiple client on the network
// for server to distinguish each ethershield client
static char client_ip[] = "192.168.1.88";

// server settings - modify the service ip to your own server
static uint8_t dest_ip[4]={192,168,1,4};
static uint8_t dest_mac[6];

enum CLIENT_STATE
{  
   IDLE, ARP_SENT, ARP_REPLY, SYNC_SENT
 };
 
static CLIENT_STATE client_state;

static uint8_t client_data_ready;

static uint8_t syn_ack_timeout = 0;


#define BUFFER_SIZE 500
static uint8_t buf[BUFFER_SIZE+1];

char sensorData[10];

EtherShield es=EtherShield();

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf);
int8_t analyse_cmd(char *str);
// get current temperature
#define TEMP_PIN  3
void getCurrentTemp( char *temperature);
void client_process(void);

void setup(){
  
   /*initialize enc28j60*/
	 es.ES_enc28j60Init(mymac);
   es.ES_enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
   delay(10);
        
	/* Magjack leds configuration, see enc28j60 datasheet, page 11 */
	// LEDA=greed LEDB=yellow
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
  
  // intialize varible;
  syn_ack_timeout =0;
  client_data_ready = 0;
  client_state = IDLE;
  // initialize DS18B20 datapin
    digitalWrite(TEMP_PIN, LOW);
    pinMode(TEMP_PIN, INPUT);      // sets the digital pin as input (logic 1)


}

void loop(){

        if(client_data_ready==0){
          delay(60000UL);             // delay 60s
          getCurrentTemp(sensorData);
          client_data_ready = 1;
         }
	client_process();
       
}

uint16_t gen_client_request(uint8_t *buf )
{
	uint16_t plen;
	byte i;
        
	plen= es.ES_fill_tcp_data_p(buf,0, PSTR ( "GET /ethershield_log/save.php?pwd=secret&client=" ) );
        for(i=0; client_ip[i]!='\0'; i++){
            buf[TCP_DATA_P+plen]=client_ip[i];
            plen++;
        }
        plen= es.ES_fill_tcp_data_p(buf,plen, PSTR ( "&status=temperature-" ) );
        for(i=0; sensorData[i]!='\0'; i++){
        
                buf[TCP_DATA_P+plen]=sensorData[i];
                plen++;
        }	
     
        
	plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( " HTTP/1.0\r\n" ));
	plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( "Host: 192.168.1.4\r\n" ));
	plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( "User-Agent: AVR ethernet\r\n" ));
        plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( "Accept: text/html\r\n" ));
	plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( "Keep-Alive: 300\r\n" ));
	plen= es.ES_fill_tcp_data_p(buf, plen, PSTR ( "Connection: keep-alive\r\n\r\n" ));

	return plen;
}

//*****************************************************************************************
//
// Function : client_process
// Description : send temparature to web server, this option is disabled by default.
// YOU MUST install webserver and server script before enable this option,
// I recommented Apache webserver and PHP script.
// More detail about Apache and PHP installation please visit http://www.avrportal.com/
//
//*****************************************************************************************
void client_process ( void )
{
    uint16_t plen;
	uint8_t i;

    if (client_data_ready == 0)  return;     // nothing to send

	if(client_state == IDLE){   // initialize ARP
       es.ES_make_arp_request(buf, dest_ip);
	   
	   client_state = ARP_SENT;
	   return;
	}
     
		
	if(client_state == ARP_SENT){
        
        plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

		// destination ip address was found on network
        if ( plen!=0 )
        {
            if ( es.ES_arp_packet_is_myreply_arp ( buf ) ){
                client_state = ARP_REPLY;
				syn_ack_timeout=0;
				return;
            }
		
		}
	        delay(10);
		syn_ack_timeout++;
		
		
		if(syn_ack_timeout== 100) {  //timeout, server ip not found
			client_state = IDLE;
			client_data_ready =0;
			syn_ack_timeout=0;
			return;
		}	
    }

   

 // send SYN packet to initial connection
	if(client_state == ARP_REPLY){
		// save dest mac
		for(i=0; i<6; i++){
			dest_mac[i] = buf[ETH_SRC_MAC+i];
		}
	
        es.ES_tcp_client_send_packet (
                       buf,
                       80,
                       1200,
                       TCP_FLAG_SYN_V,                 // flag
                       1,                                              // (bool)maximum segment size
                       1,                                              // (bool)clear sequence ack number
                       0,                                              // 0=use old seq, seqack : 1=new seq,seqack no data : new seq,seqack with data
                       0,                                              // tcp data length
		      dest_mac,
		      dest_ip
                       );
		
		client_state = SYNC_SENT;
	}
  // get new packet
  if(client_state == SYNC_SENT){
    plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

       // no new packet incoming
    if ( plen == 0 )
    {
        return;
    }

       // check ip packet send to avr or not?
       // accept ip packet only
    if ( es.ES_eth_type_is_ip_and_my_ip(buf,plen)==0){
		return;
    }

       // check SYNACK flag, after AVR send SYN server response by send SYNACK to AVR
    if ( buf [ TCP_FLAGS_P ] == ( TCP_FLAG_SYN_V | TCP_FLAG_ACK_V ) )
    {

               // send ACK to answer SYNACK

               es.ES_tcp_client_send_packet (
                       buf,
                       80,
                       1200,
                       TCP_FLAG_ACK_V,                 // flag
                       0,                                              // (bool)maximum segment size
                       0,                                              // (bool)clear sequence ack number
                       1,                                              // 0=use old seq, seqack : 1=new seq,seqack no data : new seq,seqack with data
                       0,                                              // tcp data length
						dest_mac,
						dest_ip
                       );
               // setup http request to server
               plen = gen_client_request( buf );
               // send http request packet
               // send packet with PSHACK
               es.ES_tcp_client_send_packet (
                                       buf,
                                       80,                                             // destination port
                                       1200,                                   // source port
                                       TCP_FLAG_ACK_V | TCP_FLAG_PUSH_V,                        // flag
                                       0,                                              // (bool)maximum segment size
                                       0,                                              // (bool)clear sequence ack number
                                       0,                                              // 0=use old seq, seqack : 1=new seq,seqack no data : >1 new seq,seqack with data
                                       plen,                           // tcp data length
                                       dest_mac,
									   dest_ip
									   );
               return;
       }
       // after AVR send http request to server, server response by send data with PSHACK to AVR
       // AVR answer by send ACK and FINACK to server
       if ( buf [ TCP_FLAGS_P ] == (TCP_FLAG_ACK_V|TCP_FLAG_PUSH_V) )
       {
               plen = es.ES_tcp_get_dlength( (uint8_t*)&buf );

               // send ACK to answer PSHACK from server
               es.ES_tcp_client_send_packet (
                                       buf,
                                       80,                                             // destination port
                                       1200,                                   // source port
                                       TCP_FLAG_ACK_V,                  // flag
                                       0,                                              // (bool)maximum segment size
                                       0,                                              // (bool)clear sequence ack number
                                       plen,                                           // 0=use old seq, seqack : 1=new seq,seqack no data : >1 new seq,seqack with data
                                       0,                              // tcp data length
				      dest_mac,
				      dest_ip
               );;
               // send finack to disconnect from web server

               es.ES_tcp_client_send_packet (
                                       buf,
                                       80,                                             // destination port
                                       1200,                                   // source port
                                       TCP_FLAG_FIN_V|TCP_FLAG_ACK_V,                  // flag
                                       0,                                              // (bool)maximum segment size
                                       0,                                              // (bool)clear sequence ack number
                                       0,                                           // 0=use old seq, seqack : 1=new seq,seqack no data : >1 new seq,seqack with data
                                       0,
										dest_mac,
										dest_ip
				);

               return;
               
       }
       // answer FINACK from web server by send ACK to web server
       if ( buf [ TCP_FLAGS_P ] == (TCP_FLAG_ACK_V|TCP_FLAG_FIN_V) )
       {
               // send ACK with seqack = 1
               es.ES_tcp_client_send_packet(

                                       buf,
                                       80,                                             // destination port
                                       1200,                                   // source port
                                       TCP_FLAG_ACK_V,                 // flag
                                       0,                                              // (bool)maximum segment size
                                       0,                                              // (bool)clear sequence ack number
                                       1,                                              // 0=use old seq, seqack : 1=new seq,seqack no data : >1 new seq,seqack with data
                                       0,
									   dest_mac,
									   dest_ip
				);
			client_state = IDLE;		// return to IDLE state
			client_data_ready =0;		// client data sent
		}
  }       
}

void OneWireReset(int Pin) // reset.  Should improve to act as a presence pulse
{
     digitalWrite(Pin, LOW);
     pinMode(Pin, OUTPUT); // bring low for 500 us
     delayMicroseconds(500);
     pinMode(Pin, INPUT);
     delayMicroseconds(500);
}

void OneWireOutByte(int Pin, byte d) // output byte d (least sig bit first).
{
   byte n;

   for(n=8; n!=0; n--)
   {
      if ((d & 0x01) == 1)  // test least sig bit
      {
         digitalWrite(Pin, LOW);
         pinMode(Pin, OUTPUT);
         delayMicroseconds(5);
         pinMode(Pin, INPUT);
         delayMicroseconds(60);
      }
      else
      {
         digitalWrite(Pin, LOW);
         pinMode(Pin, OUTPUT);
         delayMicroseconds(60);
         pinMode(Pin, INPUT);
      }

      d=d>>1; // now the next bit is in the least sig bit position.
   }
   
}

byte OneWireInByte(int Pin) // read byte, least sig byte first
{
    byte d, n, b;

    for (n=0; n<8; n++)
    {
        digitalWrite(Pin, LOW);
        pinMode(Pin, OUTPUT);
        delayMicroseconds(5);
        pinMode(Pin, INPUT);
        delayMicroseconds(5);
        b = digitalRead(Pin);
        delayMicroseconds(50);
        d = (d >> 1) | (b<<7); // shift d to right and insert b in most sig bit position
    }
    return(d);
}


void getCurrentTemp(char *temp)
{  
  int HighByte, LowByte, TReading, Tc_100, sign, whole, fract;

  OneWireReset(TEMP_PIN);
  OneWireOutByte(TEMP_PIN, 0xcc);
  OneWireOutByte(TEMP_PIN, 0x44); // perform temperature conversion, strong pullup for one sec

  OneWireReset(TEMP_PIN);
  OneWireOutByte(TEMP_PIN, 0xcc);
  OneWireOutByte(TEMP_PIN, 0xbe);

  LowByte = OneWireInByte(TEMP_PIN);
  HighByte = OneWireInByte(TEMP_PIN);
  TReading = (HighByte << 8) + LowByte;
  sign = TReading & 0x8000;  // test most sig bit
  if (sign) // negative
  {
    TReading = (TReading ^ 0xffff) + 1; // 2's comp
  }
  Tc_100 = (6 * TReading) + TReading / 4;    // multiply by (100 * 0.0625) or 6.25

  whole = Tc_100 / 100;  // separate off the whole and fractional portions
  fract = Tc_100 % 100;

	if(sign) temp[0]='-';
	else 		 temp[0]='+';
	
	
	temp[1]= (whole-(whole/100)*100)/10 +'0' ;
	temp[2]= whole-(whole/10)*10 +'0';
	
	temp[3]='.';
	temp[4]=fract/10 +'0';
	temp[5]=fract-(fract/10)*10 +'0';
	
	temp[6] = '\0';
}	
