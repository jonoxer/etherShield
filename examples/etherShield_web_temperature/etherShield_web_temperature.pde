#include "etherShield.h"

// please modify the following two lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x24}; 
static uint8_t myip[4] = {192,168,1,15};
static char baseurl[]="http://192.168.1.15/";
static uint16_t mywwwport =80; // listen port for tcp/www (max range 1-254)
// or on a different port:
//static char baseurl[]="http://10.0.0.24:88/";
//static uint16_t mywwwport =88; // listen port for tcp/www (max range 1-254)
//


#define BUFFER_SIZE 500
static uint8_t buf[BUFFER_SIZE+1];
#define STR_BUFFER_SIZE 22
static char strbuf[STR_BUFFER_SIZE+1];

EtherShield es=EtherShield();

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf);
int8_t analyse_cmd(char *str);
// get current temperature
#define TEMP_PIN  3
void getCurrentTemp( int *sign, int *whole, int *fract);

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
  
  // initialize DS18B20 datapin
    digitalWrite(TEMP_PIN, LOW);
    pinMode(TEMP_PIN, INPUT);      // sets the digital pin as input (logic 1)


}

void loop(){
  uint16_t plen, dat_p;
  int8_t cmd;

  plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

	/*plen will ne unequal to zero if there is a valid packet (without crc error) */
  if(plen!=0){
	           
    // arp is broadcast if unknown but a host may also verify the mac address by sending it to a unicast address.
    if(es.ES_eth_type_is_arp_and_my_ip(buf,plen)){
      es.ES_make_arp_answer_from_request(buf);
      return;
    }

    // check if ip packets are for us:
    if(es.ES_eth_type_is_ip_and_my_ip(buf,plen)==0){
      return;
    }
    
    if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V){
      es.ES_make_echo_reply_from_request(buf,plen);
      return;
    }
    
    // tcp port www start, compare only the lower byte
    if (buf[IP_PROTO_P]==IP_PROTO_TCP_V&&buf[TCP_DST_PORT_H_P]==0&&buf[TCP_DST_PORT_L_P]==mywwwport){
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V){
         es.ES_make_tcp_synack_from_syn(buf); // make_tcp_synack_from_syn does already send the syn,ack
         return;     
      }
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V){
        es.ES_init_len_info(buf); // init some data structures
        dat_p=es.ES_get_tcp_data_pointer();
        if (dat_p==0){ // we can possibly have no data, just ack:
          if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V){
            es.ES_make_tcp_ack_from_any(buf);
          }
          return;
        }
        if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
          	// head, post and other methods for possible status codes see:
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>"));
            goto SENDTCP;
        }
 	if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
                plen=print_webpage(buf);
            goto SENDTCP;
         }
        cmd=analyse_cmd((char *)&(buf[dat_p+5]));
        if (cmd==1){
             plen=print_webpage(buf);
        }
SENDTCP:  es.ES_make_tcp_ack_from_any(buf); // send ack for http get
           es.ES_make_tcp_ack_with_data(buf,plen); // send data       
      }
    }
  }
        
}
// The returned value is stored in the global var strbuf
uint8_t find_key_val(char *str,char *key)
{
        uint8_t found=0;
        uint8_t i=0;
        char *kp;
        kp=key;
        while(*str &&  *str!=' ' && found==0){
                if (*str == *kp){
                        kp++;
                        if (*kp == '\0'){
                                str++;
                                kp=key;
                                if (*str == '='){
                                        found=1;
                                }
                        }
                }else{
                        kp=key;
                }
                str++;
        }
        if (found==1){
                // copy the value to a buffer and terminate it with '\0'
                while(*str &&  *str!=' ' && *str!='&' && i<STR_BUFFER_SIZE){
                        strbuf[i]=*str;
                        i++;
                        str++;
                }
                strbuf[i]='\0';
        }
        return(found);
}

int8_t analyse_cmd(char *str)
{
        int8_t r=-1;
     
        if (find_key_val(str,"cmd")){
                if (*strbuf < 0x3a && *strbuf > 0x2f){
                        // is a ASCII number, return it
                        r=(*strbuf-0x30);
                }
        }
        return r;
}


uint16_t print_webpage(uint8_t *buf)
{
        char temp_string[10];
        int i=0;
        //char *temp_string="100";
        
        uint16_t plen;
        
        getCurrentTemp(temp_string);
        
        plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<center><p><h1>Welcome to Arduino Ethernet Shield V1.0  </h1></p> "));
         
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<hr><br><form METHOD=get action=\""));
        plen=es.ES_fill_tcp_data(buf,plen,baseurl);
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("\">"));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<h2> Current Temperature is </h2> "));
 	plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<h1><font color=\"#00FF00\"> "));
         
       
        while (temp_string[i]) {
                buf[TCP_CHECKSUM_L_P+3+plen]=temp_string[i++];
                plen++;
        }

 	plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("  &#176C</font></h1><br> ") );
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<input type=hidden name=cmd value=1>"));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<input type=submit value=\"Get Temperature\"></form>"));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</center><hr> <p> V1.0 <a href=\"http://www.nuelectronics.com\">www.nuelectronics.com<a>"));
  
        return(plen);
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
	
        if(whole/100==0)
           temp[1] =' ';
        else
	  temp[1]= whole/100+'0';
	temp[2]= (whole-(whole/100)*100)/10 +'0' ;
	temp[3]= whole-(whole/10)*10 +'0';
	
	temp[4]='.';
	temp[5]=fract/10 +'0';
	temp[6]=fract-(fract/10)*10 +'0';
	
	temp[7] = '\0';


	
}	
