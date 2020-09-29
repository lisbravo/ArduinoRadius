// RadiusClient.pde
//
// Sample Radius Client using the Radius library for ArduinoMega and Ethernet Shield
//
// Note that in order to use the Ethernet Shield with ArduinoMega, you need to make some hardware adjustments. 
// See http://mcukits.com/2009/04/06/arduino-ethernet-shield-mega-hack/ 
// and http://www.arduino.cc/cgi-bin/yabb2/YaBB.pl?num=1252386632
// Note that 3 pins on the Ethernet shield must be bent out of the way to make this work.

//
// Author: Mike McCauley (mikem@airspayce.com)
// $Id: $

// Prevent compile complaints with some versi0ns of arduino:
#undef abs
#include <stdlib.h>

#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include "RadiusMsg.h"
#include <EthernetUdp.h>

// This is the MAC address that your Ethernet shield will use
// Configure to suit your needs
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
// Configure IP to be a suitable address for your network
IPAddress ip = { 192, 168, 20, 25};
// Configure server to be the IP address of your RADIUS server
IPAddress server = { 192, 168, 20, 254 };
// Configure gateway to be the IP address of your gateway router
IPAddress gateway = { 192, 168, 20, 254 };
unsigned int localPort = 8888;      // local port to listen on
unsigned int serverPort = 1812;      // local port to listen on


//credentials
String user       = "test";
String password   = "password";
String secret     = "testing123";
int secret_lenght = secret.length();
uint64_t nas_port = 0x01020304;
// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void setup()
{
  Serial.begin(9600);

  Ethernet.begin(mac, ip, gateway);
  Udp.begin(localPort);
  delay(1000); // Lets the Ethernet card get set up.
}

void loop()
{
  // Build a new Access Request
  RadiusMsg  msg(RadiusCodeAccessRequest);
  msg.addAttr(RadiusAttrUserName, 0, user.c_str());
  msg.addAttr(RadiusAttrUserPassword, 0, password.c_str());
  msg.addAttr(RadiusAttrNASPort, 0, nas_port);
  msg.sign(secret.c_str(), secret_lenght);
  // Send it and blocking wait for a reply. Retransmissions will occur if necessary
  // Check the reply
  RadiusMsg reply;
  if (msg.sendWaitReply(&Udp, server, 1812, &reply)
      && reply.checkAuthenticatorsWithOriginal(secret.c_str(), secret_lenght, &msg)
      && reply.code() == RadiusCodeAccessAccept)
  {
    Serial.println("Got Access-Accept");
    uint8_t buf[255];
    uint8_t bufLength = 255;
    uint32_t protocol;
    // Get an attribute from the reply
    if (reply.getAttr(RadiusAttrFramedProtocol, 0, &protocol))
    {
       Serial.println("Got framed protocol: ");
       Serial.println(protocol, DEC);
    }
  }
  delay(1000);
}
