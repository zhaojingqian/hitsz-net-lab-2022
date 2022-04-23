#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, req_buf->len);
    icmp_hdr_t *icht = (icmp_hdr_t *)buf->data;
    icmp_hdr_t *req_icht = (icmp_hdr_t *)req_buf->data;
    icht->type = ICMP_TYPE_ECHO_REPLY;
    icht->code = 0;
    icht->checksum16 = 0;
    icht->id16 = req_icht->id16;
    icht->seq16 = req_icht->seq16;
    if(req_buf->len > sizeof(icmp_hdr_t)) {
        memcpy(buf->data+sizeof(icmp_hdr_t), req_buf->data+sizeof(icmp_hdr_t), req_buf->len-sizeof(icmp_hdr_t));
    }
    icht->checksum16 = checksum16((uint16_t *)buf->data, buf->len);
    ip_out(buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    if(buf->len < sizeof(icmp_hdr_t)) return;
    icmp_hdr_t *icht = (icmp_hdr_t *)buf->data;
    if(icht->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
    return;
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(ip_hdr_t)+8);

    memcpy(buf->data, recv_buf->data, sizeof(ip_hdr_t)+8);

    buf_add_header(buf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icht = (icmp_hdr_t *)buf->data;
    icht->type = ICMP_TYPE_UNREACH;
    icht->code = code;
    icht->id16 = 0;
    icht->seq16 = 0;
    icht->checksum16 = 0;
    icht->checksum16 = checksum16((uint16_t *)buf->data, buf->len);
    ip_out(buf, src_ip, NET_PROTOCOL_ICMP);
    return;
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}