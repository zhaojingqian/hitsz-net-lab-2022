#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    // 判断数据长度
    if(buf->len < sizeof(ether_hdr_t)) return;

    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));

    uint8_t *src = hdr->src;
    net_protocol_t protocol = swap16(hdr->protocol16);
    net_in(buf, protocol, src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    // 若不足46则填充0
    if(buf->len < 46) {
        int padding_len = 46 - buf->len;
        buf_add_padding(buf, padding_len);
    }

    // 调用buf_add_header 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *) buf->data;

    // 填写hdr信息
    for(int i=0; i<NET_MAC_LEN; i++) {
        hdr->dst[i] = mac[i];
        hdr->src[i] = net_if_mac[i];
    }
    net_protocol_t swap_protocol = swap16(protocol);
    hdr->protocol16 = swap_protocol;

    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
