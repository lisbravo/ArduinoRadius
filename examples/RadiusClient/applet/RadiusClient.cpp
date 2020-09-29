// RadiusClient.pde
//
// Sample Radius Client using the Radius library for ArduinoMega and Ethernet Shield
// Author: Mike McCauley (mikem@open.com.au)
// $Id: $
#undef abs
#include <stdlib.h>
#include <wiring.h>

#include "Ethernet.h"
#include "RadiusMsg.h"
#include "UDPSocket.h"

#include "WProgram.h"
void setup();
void loop();
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IP4Address ip = { 203, 63, 154, 2 };
IP4Address server = { 203, 63, 154, 29 };
IP4Address gateway = { 203, 63, 154, 248 };

UDPSocket client;

void setup()
{
  Serial.begin(9600);

  Ethernet.begin(mac, ip, gateway);
  client.begin();
  delay(1000); // Lets the Ethernet card get set up.
}

void loop()
{
  // Build a new Access Request
  RadiusMsg  msg(RadiusCodeAccessRequest);
  msg.addAttr(RadiusAttrUserName, 0, "mikem");
  msg.addAttr(RadiusAttrUserPassword, 0, "fred");
  msg.addAttr(RadiusAttrNASPort, 0, 0x01020304);
  msg.sign((uint8_t*)"mysecret", 8);
  // Send it and blocking wait for a reply. Retransmissions will occur if necessary
  // Check the reply
  RadiusMsg reply;
  if (msg.sendWaitReply(&client, server, 1645, &reply)
      && reply.checkAuthenticatorsWithOriginal((uint8_t*)"mysecret", 8, &msg)
      && reply.code() == RadiusCodeAccessAccept)
  {
    Serial.println("Got Access-Accept");
    uint8_t buf[255];
    uint8_t bufLength = 255;
    uint32_t protocol;
    // Get an attribute from the reply
    if (reply.getAttr(RadiusAttrFramedProtocol, 0, &protocol))
    {
//       Serial.println("Got framed protocol: ");
//       Serial.println(protocol, DEC);
    }
  }
  delay(1000);
}

int main(void)
{
	init();

	setup();
    
	for (;;)
		loop();
        
	return 0;
}

