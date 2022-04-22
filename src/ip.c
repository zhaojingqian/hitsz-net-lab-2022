#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if(buf->len < sizeof(ip_hdr_t)) return;
    ip_hdr_t *iht = (ip_hdr_t *)buf->data;
    //if(!is_valid(iht)) return;
    uint16_t pre_checksum16 = iht->hdr_checksum16;
    iht->hdr_checksum16 = 0;
    uint16_t cur_checksum16 = checksum16((uint16_t *)buf, sizeof(ip_hdr_t));
    if(cur_checksum16 != pre_checksum16) return;
    iht->hdr_checksum16 = pre_checksum16;

    // if(!is_hostip(iht)) return;
    // uint16_t total_len = iht->total_len16;
    if(buf->len > iht->total_len16) {
        buf_remove_padding(buf, iht->total_len16);
    }
    buf_remove_header(buf, sizeof(ip_hdr_t));
    net_in(buf, iht->protocol, src_mac);
    return;
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *iht = (ip_hdr_t *)buf->data;
    iht->hdr_len = 5;
    iht->version = 4;
    iht->tos = 0;
    iht->total_len16 = swap16((uint16_t)buf->len);
    iht->id16 = swap16((uint16_t)id);
    iht->flags_fragment16 = swap16(((uint16_t)mf<<13) | offset);
    iht->ttl = 64;
    iht->protocol = protocol;
    iht->hdr_checksum16 = 0;
    memcpy(iht->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(iht->dst_ip, ip, NET_IP_LEN);
    iht->hdr_checksum16 = checksum16((uint16_t *)iht, sizeof(ip_hdr_t));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
static int id = -1;
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    id++;
    int data_len = (1500 - sizeof(ip_hdr_t))/8 * 8;
    int offset_unit = data_len/8;
    if(buf->len > data_len) {
        size_t n = buf->len / data_len;
        size_t final_len = data_len;
        if(buf->len % data_len) {
            final_len = buf->len - n*data_len;
            n++;
        }
        buf_t ip_buf;
        
        for(size_t i=0; i<n-1; i++) {
            // memcpy(tmp_buf, buf, data_len);
            buf_init(&ip_buf, data_len);
            memcpy(ip_buf.data, buf->data + i*data_len, data_len);
            ip_fragment_out(&ip_buf, ip, protocol, id, i*offset_unit, 1);
        }
        buf_init(&ip_buf, final_len);
        memcpy(ip_buf.data, buf->data + (n-1)*data_len, final_len);
        ip_fragment_out(&ip_buf, ip, protocol, id, (n-1)*offset_unit, 0);
    } else {
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }
    return;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}