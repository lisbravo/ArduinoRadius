// RadiusMsg.h
//
// Class for managing a RADIUS requests
//
// Author: Mike McCauley (mikem@airspayce.com)
// $Id: RadiusMsg.cpp,v 1.1 2009/10/13 05:07:28 mikem Exp mikem $

#include "Ethernet.h"
#include "RadiusMsg.h"
//#include <string.h>

extern "C" 
{
#include "md5.h"
#include "utility/socket.h"
#include "utility/w5100.h"
}

uint16_t htons(uint16_t v)
{
#if SYSTEM_ENDIAN == _ENDIAN_LITTLE_
  return ((v & 0xff) << 8) | ((v & 0xff00) >> 8);
#else
  return v;
#endif
}

uint32_t htonl(uint32_t v)
{
#if SYSTEM_ENDIAN == _ENDIAN_LITTLE_
  return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8) | ((v & 0xff000000) >> 24);
#else
  return v;
#endif
}

#define ntohs htons
#define ntohl htonl

static uint8_t nextIdentifier = 0;

RadiusMsg::RadiusMsg()
{
  packetLength = RADIUS_HEADER_LENGTH;
  retries = 3;
  timeout = 5;
}

RadiusMsg::RadiusMsg(RadiusCode code)
{
  packet.code = code;
  packet.identifier = nextIdentifier++;
  packetLength = RADIUS_HEADER_LENGTH;
  retries = 3;
  timeout = 5;
}

uint8_t 
RadiusMsg::code()
{
  return packet.code;
}

// REVISIT: handle VSAs
void
RadiusMsg::addAttr(unsigned type, unsigned vendor, uint8_t* value, uint8_t length)
{
  RadiusAttrHeader* h = (RadiusAttrHeader*)((uint8_t*)&packet + packetLength);

  memcpy(h->value, value, length);
  
  // Pad some types to multiple of RADIUS_PASSWORD_BLOCK_SIZE(16) octets
  if (type == RadiusAttrUserPassword && vendor == 0)
  {
    uint8_t padding = length % RADIUS_PASSWORD_BLOCK_SIZE;
    if (padding)
    {
      padding = RADIUS_PASSWORD_BLOCK_SIZE - padding;
      memset(h->value + length, 0, padding);
      length += padding;
    }
  }
  h->type = type;
  h->length = length + 2;
  packetLength += h->length;
}

void
RadiusMsg::addAttr(unsigned type, unsigned vendor, const char* value)
{
  return addAttr(type, vendor, (uint8_t*)value, strlen(value));
}

void
RadiusMsg::addAttr(unsigned type, unsigned vendor, uint32_t value)
{
  uint32_t v = htonl(value);
  return addAttr(type, vendor, (uint8_t*)&v, sizeof(v));
}

uint8_t
RadiusMsg::getAttr(unsigned type, unsigned vendor, uint8_t* value, uint8_t* length, uint8_t skip)
{
  uint8_t i;
  for (i = RADIUS_HEADER_LENGTH; i < packetLength;)
  {
    RadiusAttrHeader* h = (RadiusAttrHeader*)((uint8_t*)&packet + i);

    if (h->type == type and skip-- == 0)
    {
      uint8_t l = h->length - 2;
      if (l > *length) 
        l = *length;
      memcpy(value, h->value, l);
      *length = l;
      return true; // Found
    }
    i += h->length;
  }
  return false; // not found
}

uint8_t
RadiusMsg::getAttr(unsigned type, unsigned vendor, uint32_t* value, uint8_t skip)
{
  uint32_t v;
  uint8_t  vLength = sizeof(v);
  uint8_t ret = getAttr(type, vendor, (uint8_t*)&v, &vLength, skip);
  if (ret && vLength == 4)
  {
   *value = ntohl(v);
   return true;
  }
  else
    return false;
}

void  
RadiusMsg::encryptPassword(uint8_t* data, uint8_t length, uint8_t* secret, uint8_t secretLength, uint8_t* iv)
{
  uint8_t  i;
  uint8_t lastround[RADIUS_PASSWORD_BLOCK_SIZE];
  memcpy(lastround, iv, RADIUS_PASSWORD_BLOCK_SIZE);
  
  for (i = 0; i < length; i+= RADIUS_PASSWORD_BLOCK_SIZE)
  {
    md5_ctx  context;
    md5_init(&context);
    md5_update(&context, secret, secretLength);
    md5_update(&context, lastround, RADIUS_PASSWORD_BLOCK_SIZE);
    uint8_t digest[RADIUS_PASSWORD_BLOCK_SIZE];
    md5_final(digest, &context);
    uint8_t j;
    for (j = 0; j < RADIUS_PASSWORD_BLOCK_SIZE; j++)
    {
      data[i+j] ^= digest[j];
      lastround[j] = data[i+j];
    }
  }
}

void 
RadiusMsg::sign(uint8_t* secret, uint8_t secretLength, RadiusMsg* original)
{
  // Set the authenticator
  uint8_t i;
  uint8_t setRandomAuthenticator = 0;
  if (   packet.code == RadiusCodeAccountingRequest
      || packet.code == RadiusCodeDisconnectRequest
      || packet.code == RadiusCodeChangeFilterRequest)
  {
    memset(packet.authenticator, 0, RADIUS_AUTHENTICATOR_LENGTH);
  }
  else if (original 
          && (  packet.code == RadiusCodeAccessAccept
	     || packet.code == RadiusCodeAccessReject
	     || packet.code == RadiusCodeAccessChallenge
	     || packet.code == RadiusCodeDisconnectRequestACKed
	     || packet.code == RadiusCodeDisconnectRequestNAKed
	     || packet.code == RadiusCodeChangeFilterRequestACKed
	     || packet.code == RadiusCodeChangeFilterRequestNAKed))
  {
    memcpy(packet.authenticator, original->packet.authenticator, RADIUS_AUTHENTICATOR_LENGTH);
  }
  else
  {
    for (i = 0; i < RADIUS_AUTHENTICATOR_LENGTH; i++)
      packet.authenticator[i] = rand();
    setRandomAuthenticator = 1;
  }
  
  // Encrypt any attrs that need it
  for (i = RADIUS_HEADER_LENGTH; i < packetLength;)
  {
    RadiusAttrHeader* h = (RadiusAttrHeader*)((uint8_t*)&packet + i);

    if (h->type == RadiusAttrUserPassword)
    {
      encryptPassword(h->value, h->length-2, secret, secretLength, packet.authenticator);
    }
    i += h->length;
  }
  if (!setRandomAuthenticator)
  {
    // Compute authenticator
    md5_ctx context;
    md5_init(&context);
    md5_update(&context, (uint8_t*)&packet, packetLength);
    md5_update(&context, secret, secretLength);
    RadiusAuthenticator digest;
    md5_final(digest, &context);
    memcpy(packet.authenticator, digest, RADIUS_AUTHENTICATOR_LENGTH);
  }
}


uint16_t
RadiusMsg::sendto(UDPSocket* socket, IP4Address peer, uint16_t port)
{
  uint8_t i;
  for (i = 0; i < 4; i++)
    peerAddress[i] = peer[i];
  peerPort = port;
  packet.length = htons(packetLength);
  return socket->sendto((const uint8_t*)&packet, packetLength, peer, 1645);
}

uint16_t
RadiusMsg::recv(UDPSocket* socket)
{
  packetLength = 0;
  uint16_t ret = socket->recvfrom((uint8*)&packet, 255, peerAddress, &peerPort);
  if (ret < RADIUS_HEADER_LENGTH || ret > RADIUS_MAX_SIZE)
    return 0; // Discard
  uint16_t l = ntohs(packet.length);
  if (l > ret)
    return 0; // Discard
  packetLength = ret; 
  return ret;
}

uint8_t
RadiusMsg::sendWaitReply(UDPSocket* socket, IP4Address server, uint16_t port, RadiusMsg* reply)
{
  while (retries-- > 0)
  {
    uint16_t ret = sendto(socket, server, port);
    unsigned long sendTime = millis();
    if (ret <= 0)
      return false;  // Send failed
    // wait for the timeout
    while (millis() < sendTime + 1000 * timeout)
    {
      if (socket->available())
      {
        ret = reply->recv(socket);

        if (ret > 0 && reply->packet.identifier == packet.identifier 
            && reply->peerAddress[0] == peerAddress[0]
            && reply->peerAddress[1] == peerAddress[1]
            && reply->peerAddress[2] == peerAddress[2]
            && reply->peerAddress[3] == peerAddress[3]
            && reply->peerPort == peerPort)  
         {
            // This is the reply we are waiting for
            return true; 
         }
      }
    }
  }
  return false;  // No reply
}

uint8_t
RadiusMsg::checkAuthenticatorsWithOriginal(uint8_t* secret, uint8_t secretLength, RadiusMsg* original)
{
  RadiusAuthenticator  savedAuthenticator;
  memcpy(savedAuthenticator, packet.authenticator, RADIUS_AUTHENTICATOR_LENGTH);
   
  if (   packet.code == RadiusCodeAccountingRequest
        || packet.code == RadiusCodeDisconnectRequest
	|| packet.code == RadiusCodeChangeFilterRequest)
  {
    memset(packet.authenticator, 0, RADIUS_AUTHENTICATOR_LENGTH);
  }
  else if (   packet.code == RadiusCodeAccessAccept
	   || packet.code == RadiusCodeAccessReject
	   || packet.code == RadiusCodeAccessChallenge
	   || packet.code == RadiusCodeDisconnectRequestACKed
	   || packet.code == RadiusCodeDisconnectRequestNAKed
	   || packet.code == RadiusCodeChangeFilterRequestACKed
	   || packet.code == RadiusCodeChangeFilterRequestNAKed)
  {
    memcpy(packet.authenticator, original->packet.authenticator, RADIUS_AUTHENTICATOR_LENGTH);
  }
  else
  {
    return 1; // Random authenticator, cant check it
  }
  
  md5_ctx context;
  md5_init(&context);
  md5_update(&context, (uint8_t*)&packet, packetLength);
  md5_update(&context, secret, secretLength);
  RadiusAuthenticator  digest;
  md5_final(digest, &context);
  // Restore the saved authenticator
  memcpy(packet.authenticator, savedAuthenticator, RADIUS_AUTHENTICATOR_LENGTH);
  return memcmp(digest, savedAuthenticator, RADIUS_AUTHENTICATOR_LENGTH) == 0;
}
