/*
 * connection.cpp
 *
 *  Created on: Sep 23, 2017
 *      Author: root
 */

#include "connection.h"
static inline int seq_lt(u32_t a, u32_t b);
static inline int seq_le(u32_t a, u32_t b);
static inline int seq_gt(u32_t a, u32_t b);
int tcpemul_send_ack(conn_info_t &conn_info);
int tcpemul_on_recv_frame(conn_info_t &conn_info);
int tcpemul_record_sent(conn_info_t &conn_info, const char *pkt, int len, u32_t seq_start);
int tcpemul_retire_acked(conn_info_t &conn_info);
int tcpemul_retx_scan(conn_info_t &conn_info);
int tcpemul_fast_retx(conn_info_t &conn_info);

#include "encrypt.h"
#include "fd_manager.h"

int disable_anti_replay = 0;  // if anti_replay windows is diabled

const int disable_conn_clear = 0;  // a raw connection is called conn.

conn_manager_t conn_manager;

anti_replay_seq_t anti_replay_t::get_new_seq_for_send() {
    return anti_replay_seq++;
}
anti_replay_t::anti_replay_t() {
    max_packet_received = 0;
    anti_replay_seq = get_true_random_number_64() / 10;  // random first seq
    // memset(window,0,sizeof(window)); //not necessary
}
void anti_replay_t::re_init() {
    max_packet_received = 0;
    // memset(window,0,sizeof(window));
}

int anti_replay_t::is_vaild(u64_t seq) {
    if (disable_anti_replay) return 1;
    // if(disabled) return 0;

    if (seq == max_packet_received)
        return 0;
    else if (seq > max_packet_received) {
        if (seq - max_packet_received >= anti_replay_window_size) {
            memset(window, 0, sizeof(window));
            window[seq % anti_replay_window_size] = 1;
        } else {
            for (u64_t i = max_packet_received + 1; i < seq; i++)
                window[i % anti_replay_window_size] = 0;
            window[seq % anti_replay_window_size] = 1;
        }
        max_packet_received = seq;
        return 1;
    } else if (seq < max_packet_received) {
        if (max_packet_received - seq >= anti_replay_window_size)
            return 0;
        else {
            if (window[seq % anti_replay_window_size] == 1)
                return 0;
            else {
                window[seq % anti_replay_window_size] = 1;
                return 1;
            }
        }
    }

    return 0;  // for complier check
}

void conn_info_t::recover(const conn_info_t &conn_info) {
    raw_info = conn_info.raw_info;

    raw_info.rst_received = 0;
    raw_info.disabled = 0;

    last_state_time = conn_info.last_state_time;
    last_hb_recv_time = conn_info.last_hb_recv_time;
    last_hb_sent_time = conn_info.last_hb_sent_time;
    my_id = conn_info.my_id;
    oppsite_id = conn_info.oppsite_id;
    blob->anti_replay.re_init();

    my_roller = 0;       // no need to set,but for easier debug,set it to zero
    oppsite_roller = 0;  // same as above
    last_oppsite_roller_time = 0;
}

void conn_info_t::re_init() {
    // send_packet_info.protocol=g_packet_info_send.protocol;
    if (program_mode == server_mode)
        state.server_current_state = server_idle;
    else
        state.client_current_state = client_idle;
    last_state_time = 0;
    oppsite_const_id = 0;

    timer_fd64 = 0;

    my_roller = 0;
    oppsite_roller = 0;
    last_oppsite_roller_time = 0;
}
conn_info_t::conn_info_t() {
    blob = 0;
    re_init();
}
void conn_info_t::prepare() {
    assert(blob == 0);
    blob = new blob_t;
    if (program_mode == server_mode) {
        blob->conv_manager.s.additional_clear_function = server_clear_function;
    } else {
        assert(program_mode == client_mode);
    }
}

conn_info_t::conn_info_t(const conn_info_t &b) {
    assert(0 == 1);
    // mylog(log_error,"called!!!!!!!!!!!!!\n");
}

conn_info_t &conn_info_t::operator=(const conn_info_t &b) {
    mylog(log_fatal, "not allowed\n");
    myexit(-1);
    return *this;
}
conn_info_t::~conn_info_t() {
    if (program_mode == server_mode) {
        if (state.server_current_state == server_ready) {
            assert(blob != 0);
            assert(oppsite_const_id != 0);
            // assert(conn_manager.const_id_mp.find(oppsite_const_id)!=conn_manager.const_id_mp.end()); // conn_manager 's deconstuction function  erases it
        } else {
            assert(blob == 0);
            assert(oppsite_const_id == 0);
        }
    }
    assert(timer_fd64 == 0);
    // if(oppsite_const_id!=0)     //do this at conn_manager 's deconstuction function
    // conn_manager.const_id_mp.erase(oppsite_const_id);
    if (blob != 0)
        delete blob;

    // send_packet_info.protocol=g_packet_info_send.protocol;
}

conn_manager_t::conn_manager_t() {
    ready_num = 0;
    mp.reserve(10007);
    // clear_it=mp.begin();
    // timer_fd_mp.reserve(10007);
    const_id_mp.reserve(10007);
    // udp_fd_mp.reserve(100007);
    last_clear_time = 0;
    // current_ready_ip=0;
    // current_ready_port=0;
}
int conn_manager_t::exist(address_t addr) {
    // u64_t u64=0;
    // u64=ip;
    // u64<<=32u;
    // u64|=port;
    if (mp.find(addr) != mp.end()) {
        return 1;
    }
    return 0;
}
/*
int insert(uint32_t ip,uint16_t port)
{
        uint64_t u64=0;
        u64=ip;
        u64<<=32u;
        u64|=port;
        mp[u64];
        return 0;
}*/
conn_info_t *&conn_manager_t::find_insert_p(address_t addr)  // be aware,the adress may change after rehash
{
    // u64_t u64=0;
    // u64=ip;
    // u64<<=32u;
    // u64|=port;
    unordered_map<address_t, conn_info_t *>::iterator it = mp.find(addr);
    if (it == mp.end()) {
        mp[addr] = new conn_info_t;
        // lru.new_key(addr);
    } else {
        // lru.update(addr);
    }
    return mp[addr];
}
conn_info_t &conn_manager_t::find_insert(address_t addr)  // be aware,the adress may change after rehash
{
    // u64_t u64=0;
    // u64=ip;
    // u64<<=32u;
    // u64|=port;
    unordered_map<address_t, conn_info_t *>::iterator it = mp.find(addr);
    if (it == mp.end()) {
        mp[addr] = new conn_info_t;
        // lru.new_key(addr);
    } else {
        // lru.update(addr);
    }
    return *mp[addr];
}
int conn_manager_t::erase(unordered_map<address_t, conn_info_t *>::iterator erase_it) {
    if (erase_it->second->state.server_current_state == server_ready) {
        ready_num--;
        assert(i32_t(ready_num) != -1);
        assert(erase_it->second != 0);

        assert(erase_it->second->timer_fd64 != 0);

        assert(fd_manager.exist(erase_it->second->timer_fd64));

        assert(erase_it->second->oppsite_const_id != 0);
        assert(const_id_mp.find(erase_it->second->oppsite_const_id) != const_id_mp.end());

        // assert(timer_fd_mp.find(erase_it->second->timer_fd)!=timer_fd_mp.end());

        const_id_mp.erase(erase_it->second->oppsite_const_id);

        fd_manager.fd64_close(erase_it->second->timer_fd64);

        erase_it->second->timer_fd64 = 0;
        // timer_fd_mp.erase(erase_it->second->timer_fd);
        // close(erase_it->second->timer_fd);// close will auto delte it from epoll
        delete (erase_it->second);
        mp.erase(erase_it->first);
    } else {
        assert(erase_it->second->blob == 0);
        assert(erase_it->second->timer_fd64 == 0);

        assert(erase_it->second->oppsite_const_id == 0);
        delete (erase_it->second);
        mp.erase(erase_it->first);
    }
    return 0;
}
int conn_manager_t::clear_inactive() {
    if (get_current_time() - last_clear_time > conn_clear_interval) {
        last_clear_time = get_current_time();
        return clear_inactive0();
    }
    return 0;
}
int conn_manager_t::clear_inactive0() {
    unordered_map<address_t, conn_info_t *>::iterator it;
    unordered_map<address_t, conn_info_t *>::iterator old_it;

    if (disable_conn_clear) return 0;

    // map<uint32_t,uint64_t>::iterator it;
    int cnt = 0;
    it = clear_it;
    int size = mp.size();
    int num_to_clean = size / conn_clear_ratio + conn_clear_min;  // clear 1/10 each time,to avoid latency glitch

    mylog(log_trace, "mp.size() %d\n", size);

    num_to_clean = min(num_to_clean, (int)mp.size());
    u64_t current_time = get_current_time();

    for (;;) {
        if (cnt >= num_to_clean) break;
        if (mp.begin() == mp.end()) break;

        if (it == mp.end()) {
            it = mp.begin();
        }

        if (it->second->state.server_current_state == server_ready && current_time - it->second->last_hb_recv_time <= server_conn_timeout) {
            it++;
        } else if (it->second->state.server_current_state != server_ready && current_time - it->second->last_state_time <= server_handshake_timeout) {
            it++;
        } else if (it->second->blob != 0 && it->second->blob->conv_manager.s.get_size() > 0) {
            assert(it->second->state.server_current_state == server_ready);
            it++;
        } else {
            mylog(log_info, "[%s:%d]inactive conn cleared \n", it->second->raw_info.recv_info.new_src_ip.get_str1(), it->second->raw_info.recv_info.src_port);
            old_it = it;
            it++;
            erase(old_it);
        }
        cnt++;
    }
    clear_it = it;

    return 0;
}

int send_bare(raw_info_t &raw_info, const char *data, int len)  // send function with encryption but no anti replay,this is used when client and server verifys each other
// you have to design the protocol carefully, so that you wont be affect by relay attack
{
    if (len < 0) {
        mylog(log_debug, "input_len <0\n");
        return -1;
    }
    packet_info_t &send_info = raw_info.send_info;
    packet_info_t &recv_info = raw_info.recv_info;

    char send_data_buf[buf_len];  // buf for send data and send hb
    char send_data_buf2[buf_len];

    // static send_bare[buf_len];
    iv_t iv = get_true_random_number_64();
    padding_t padding = get_true_random_number_64();

    memcpy(send_data_buf, &iv, sizeof(iv));
    memcpy(send_data_buf + sizeof(iv), &padding, sizeof(padding));

    send_data_buf[sizeof(iv) + sizeof(padding)] = 'b';
    memcpy(send_data_buf + sizeof(iv) + sizeof(padding) + 1, data, len);
    int new_len = len + sizeof(iv) + sizeof(padding) + 1;

    if (my_encrypt(send_data_buf, send_data_buf2, new_len) != 0) {
        return -1;
    }
    send_raw0(raw_info, send_data_buf2, new_len);
    return 0;
}
int reserved_parse_bare(const char *input, int input_len, char *&data, int &len)  // a sub function used in recv_bare
{
    static char recv_data_buf[buf_len];

    if (input_len < 0) {
        mylog(log_debug, "input_len <0\n");
        return -1;
    }
    if (my_decrypt(input, recv_data_buf, input_len) != 0) {
        mylog(log_debug, "decrypt_fail in recv bare\n");
        return -1;
    }
    if (recv_data_buf[sizeof(iv_t) + sizeof(padding_t)] != 'b') {
        mylog(log_debug, "not a bare packet\n");
        return -1;
    }
    len = input_len;
    data = recv_data_buf + sizeof(iv_t) + sizeof(padding_t) + 1;
    len -= sizeof(iv_t) + sizeof(padding_t) + 1;
    if (len < 0) {
        mylog(log_debug, "len <0\n");
        return -1;
    }
    return 0;
}
int recv_bare(raw_info_t &raw_info, char *&data, int &len)  // recv function with encryption but no anti replay,this is used when client and server verifys each other
// you have to design the protocol carefully, so that you wont be affect by relay attack
{
    packet_info_t &send_info = raw_info.send_info;
    packet_info_t &recv_info = raw_info.recv_info;

    if (recv_raw0(raw_info, data, len) < 0) {
        // printf("recv_raw_fail in recv bare\n");
        return -1;
    }

    if (len >= max_data_len + 1) {
        mylog(log_debug, "data_len=%d >= max_data_len+1,ignored", len);
        return -1;
    }

    mylog(log_trace, "data len=%d\n", len);
    if ((raw_mode == mode_faketcp && (recv_info.syn == 1 || recv_info.ack != 1))) {
        mylog(log_debug, "unexpect packet type recv_info.syn=%d recv_info.ack=%d \n", recv_info.syn, recv_info.ack);
        return -1;
    }
    return reserved_parse_bare(data, len, data, len);
}

int send_handshake(raw_info_t &raw_info, my_id_t id1, my_id_t id2, my_id_t id3)  // a warp for send_bare for sending handshake(this is not tcp handshake) easily
{
    packet_info_t &send_info = raw_info.send_info;
    packet_info_t &recv_info = raw_info.recv_info;

    char *data;
    int len;
    // len=sizeof(id_t)*3;
    if (numbers_to_char(id1, id2, id3, data, len) != 0) return -1;
    if (send_bare(raw_info, data, len) != 0) {
        mylog(log_warn, "send bare fail\n");
        return -1;
    }
    return 0;
}
/*
int recv_handshake(packet_info_t &info,id_t &id1,id_t &id2,id_t &id3)
{
        char * data;int len;
        if(recv_bare(info,data,len)!=0) return -1;

        if(char_to_numbers(data,len,id1,id2,id3)!=0) return -1;

        return 0;
}*/

int send_safer(conn_info_t &conn_info, char type, const char *data, int len)  // safer transfer function with anti-replay,when mutually verification is done.
{
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    if (type != 'h' && type != 'd') {
        mylog(log_warn, "first byte is not h or d  ,%x\n", type);
        return -1;
    }

    char send_data_buf[buf_len];  // buf for send data and send hb
    char send_data_buf2[buf_len];

    my_id_t n_tmp_id = htonl(conn_info.my_id);

    memcpy(send_data_buf, &n_tmp_id, sizeof(n_tmp_id));

    n_tmp_id = htonl(conn_info.oppsite_id);

    memcpy(send_data_buf + sizeof(n_tmp_id), &n_tmp_id, sizeof(n_tmp_id));

    anti_replay_seq_t n_seq = hton64(conn_info.blob->anti_replay.get_new_seq_for_send());

    memcpy(send_data_buf + sizeof(n_tmp_id) * 2, &n_seq, sizeof(n_seq));

    send_data_buf[sizeof(n_tmp_id) * 2 + sizeof(n_seq)] = type;
    send_data_buf[sizeof(n_tmp_id) * 2 + sizeof(n_seq) + 1] = conn_info.my_roller;

    memcpy(send_data_buf + 2 + sizeof(n_tmp_id) * 2 + sizeof(n_seq), data, len);  // data;

    int new_len = len + sizeof(n_seq) + sizeof(n_tmp_id) * 2 + 2;

    if (g_fix_gro == 0) {
        if (my_encrypt(send_data_buf, send_data_buf2, new_len) != 0) {
            return -1;
        }
    } else {
        if (my_encrypt(send_data_buf, send_data_buf2 + 2, new_len) != 0) {
            return -1;
        }
        write_u16(send_data_buf2, new_len);
        new_len += 2;
        if (cipher_mode == cipher_xor) {
            send_data_buf2[0] ^= gro_xor[0];
            send_data_buf2[1] ^= gro_xor[1];
        } else if (cipher_mode == cipher_aes128cbc || cipher_mode == cipher_aes128cfb) {
            aes_ecb_encrypt1(send_data_buf2);
        }
    }

    u32_t tcpemul_seq_start = conn_info.raw_info.send_info.seq;
    if (send_raw0(conn_info.raw_info, send_data_buf2, new_len) != 0) return -1;

    if (after_send_raw0(conn_info.raw_info) != 0) return -1;

    if (type == 'd' && new_len > 0) {
        tcpemul_record_sent(conn_info, send_data_buf2, new_len, tcpemul_seq_start);
    }

    return 0;
}
int send_data_safer(conn_info_t &conn_info, const char *data, int len, u32_t conv_num)  // a wrap for  send_safer for transfer data.
{
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    char send_data_buf[buf_len];
    // send_data_buf[0]='d';
    u32_t n_conv_num = htonl(conv_num);
    memcpy(send_data_buf, &n_conv_num, sizeof(n_conv_num));

    memcpy(send_data_buf + sizeof(n_conv_num), data, len);
    int new_len = len + sizeof(n_conv_num);
    send_safer(conn_info, 'd', send_data_buf, new_len);
    return 0;
}
int reserved_parse_safer(conn_info_t &conn_info, const char *input, int input_len, char &type, char *&data, int &len)  // subfunction for recv_safer,allow overlap
{
    static char recv_data_buf[buf_len];

    // char *recv_data_buf=recv_data_buf0; //fix strict alias warning
    if (my_decrypt(input, recv_data_buf, input_len) != 0) {
        // printf("decrypt fail\n");
        return -1;
    }

    // char *a=recv_data_buf;
    // id_t h_oppiste_id= ntohl (  *((id_t * )(recv_data_buf)) );
    my_id_t h_oppsite_id;
    memcpy(&h_oppsite_id, recv_data_buf, sizeof(h_oppsite_id));
    h_oppsite_id = ntohl(h_oppsite_id);

    // id_t h_my_id= ntohl (  *((id_t * )(recv_data_buf+sizeof(id_t)))    );
    my_id_t h_my_id;
    memcpy(&h_my_id, recv_data_buf + sizeof(my_id_t), sizeof(h_my_id));
    h_my_id = ntohl(h_my_id);

    // anti_replay_seq_t h_seq= ntoh64 (  *((anti_replay_seq_t * )(recv_data_buf  +sizeof(id_t) *2 ))   );
    anti_replay_seq_t h_seq;
    memcpy(&h_seq, recv_data_buf + sizeof(my_id_t) * 2, sizeof(h_seq));
    h_seq = ntoh64(h_seq);

    if (h_oppsite_id != conn_info.oppsite_id || h_my_id != conn_info.my_id) {
        mylog(log_debug, "id and oppsite_id verification failed %x %x %x %x \n", h_oppsite_id, conn_info.oppsite_id, h_my_id, conn_info.my_id);
        return -1;
    }

    if (conn_info.blob->anti_replay.is_vaild(h_seq) != 1) {
        mylog(log_debug, "dropped replay packet\n");
        // hardened fork: a duplicate the replay window rejects is a
        // retransmission of bytes we already delivered, i.e. our earlier ACK
        // was lost. re-ack immediately so the peer retires the segment
        // instead of backing off to the RTO cap.
        packet_info_t &r_info = conn_info.raw_info.recv_info;
        packet_info_t &s_info = conn_info.raw_info.send_info;
        if (raw_mode == mode_faketcp && r_info.data_len != 0
            && seq_le(r_info.seq + r_info.data_len, s_info.ack_seq)) {
            if (tcpemul_send_ack(conn_info) == 0) conn_info.blob->tcp_emul.stat_reacks++;
        }
        return -1;
    }

    // printf("recv _len %d\n ",recv_len);
    data = recv_data_buf + sizeof(anti_replay_seq_t) + sizeof(my_id_t) * 2;
    len = input_len - (sizeof(anti_replay_seq_t) + sizeof(my_id_t) * 2);

    if (data[0] != 'h' && data[0] != 'd') {
        mylog(log_debug, "first byte is not h or d  ,%x\n", data[0]);
        return -1;
    }

    uint8_t roller = data[1];

    type = data[0];
    data += 2;
    len -= 2;

    if (len < 0) {
        mylog(log_debug, "len <0 ,%d\n", len);
        return -1;
    }

    if (roller != conn_info.oppsite_roller) {
        conn_info.oppsite_roller = roller;
        conn_info.last_oppsite_roller_time = get_current_time();
    }
    if (hb_mode == 0)
        conn_info.my_roller++;  // increase on a successful recv
    else if (hb_mode == 1) {
        if (type == 'h')
            conn_info.my_roller++;
    } else {
        mylog(log_fatal, "unknow hb_mode\n");
        myexit(-1);
    }

    if (conn_info.raw_info.recv_info.ack_seq_counter >= 3) {
        tcpemul_fast_retx(conn_info);  // fast retransmit on 3 dup-acks
    }
    if (after_recv_raw0(conn_info.raw_info) != 0) return -1;  // TODO might need to move this function to somewhere else after --fix-gro is introduced

    return 0;
}
int recv_safer_notused(conn_info_t &conn_info, char &type, char *&data, int &len)  /// safer transfer function with anti-replay,when mutually verification is done.
{
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    char *recv_data;
    int recv_len;
    // static char recv_data_buf[buf_len];

    if (recv_raw0(conn_info.raw_info, recv_data, recv_len) != 0) return -1;
    if (tcpemul_on_recv_frame(conn_info) == -2) return -2;  // fully-old frame: re-acked, skip parse

    return reserved_parse_safer(conn_info, recv_data, recv_len, type, data, len);
}

// ================= fake-TCP behaviour emulation (hardened fork) =================
// Emulates the TCP behaviours a mid-path observer expects: cumulative ACKs,
// duplicate ACKs on gaps, real byte retransmission with RTO backoff and fast
// retransmit on 3 dup-ACKs, and re-ACK when a retransmission hits a replay-
// window duplicate (meaning our ack was lost).
//
// Data-plane safety: retransmitted packets carry the SAME inner anti-replay
// seq, so a peer that already processed them drops the copy in its replay
// window. Nothing is ever duplicated into user data.
//
// Wire-compatible with unpatched peers: our retransmissions are ordinary data
// packets to them; our dup-ACKs are ordinary frames; fast retransmit degrades
// to RTO-only against unpatched peers.

static inline int seq_lt(u32_t a, u32_t b) { return (int)(a - b) < 0; }
static inline int seq_le(u32_t a, u32_t b) { return (int)(a - b) <= 0; }
static inline int seq_gt(u32_t a, u32_t b) { return (int)(a - b) > 0; }

// ACKs only ride the heartbeat (600 ms, +/-150 ms jitter), so a clean path can
// leave a burst unacked for most of a second. An 800 ms RTO fired spuriously on
// every burst; 2 s is >2 heartbeat periods + jitter + RTT, so an RTO now means
// the peer's cumulative ack really stopped moving.
static const int tcpemul_rto_base = 2000;     // ms
static const int tcpemul_max_retries = 4;
static const size_t tcpemul_max_buf = 192;    // unacked segment cap (< anti-replay window 4000)

int tcpemul_send_ack(conn_info_t &conn_info) {
    if (conn_info.state.server_current_state != server_ready
        && conn_info.state.client_current_state != client_ready) return -1;
    return send_safer(conn_info, 'h', 0, 0);
}

int tcpemul_on_recv_frame(conn_info_t &conn_info) {
    // runs BEFORE after_recv_raw0, so send_info.ack_seq is still the contiguous
    // receive position as of the previous frame (mode 3 advances it in-order only).
    if (raw_mode != mode_faketcp) return 0;
    if (seq_mode != 3 && seq_mode != 4) return 0;
    int ready = (program_mode == client_mode)
                    ? conn_info.state.client_current_state == client_ready
                    : conn_info.state.server_current_state == server_ready;
    if (!ready) return 0;  // handshake frames have their own seq rules
    packet_info_t &recv_info = conn_info.raw_info.recv_info;
    packet_info_t &send_info = conn_info.raw_info.send_info;
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    u32_t seq = recv_info.seq;
    u32_t len = (u32_t)recv_info.data_len;
    if (len == 0) return 0;  // pure ack carrier
    u32_t ackpos = send_info.ack_seq;
    if (seq == ackpos) {  // in order: contiguous receive position moves up
        te.rcv_nxt = seq + len;
        te.rcv_valid = 1;
        return 0;
    }
    if (seq_gt(seq, ackpos)) {    // gap ahead of us
        if (te.gap_base != ackpos) {
            te.gap_base = ackpos;
            te.gap_dups = 0;
            te.stat_gaps++;
        }
        if (te.gap_dups < 5) {
            if (tcpemul_send_ack(conn_info) == 0) {  // dup-ack: ack stays at the gap
                te.stat_dupacks++;
                te.gap_dups++;
            }
        }
        return 0;  // out-of-order frame is still processed (UDP semantics)
    }
    if (seq_gt(seq + len, ackpos)) return 0;  // partial overlap: process, ack unchanged
    // fully old: retransmission of data we already have -> re-ack
    if (tcpemul_send_ack(conn_info) == 0) te.stat_reacks++;
    return -2;
}

int tcpemul_fast_retx(conn_info_t &conn_info) {
    // immediate retransmit of the segment at the dup-acked position (3 dup-acks)
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    if (te.retx_q.empty()) return 0;
    retx_entry_t &e = te.retx_q.front();
    u32_t ack = conn_info.raw_info.recv_info.ack_seq;
    if (e.seq_start != ack) return 0;
    u64_t now = get_current_time();
    if (now - e.last_ms < 100) return 0;  // pacing
    u32_t saved_seq = conn_info.raw_info.send_info.seq;
    conn_info.raw_info.send_info.seq = e.seq_start;
    conn_info.raw_info.send_info.psh = 1;
    int r = send_raw0(conn_info.raw_info, e.pkt.data(), (int)e.pkt.size());
    if (r == 0) {
        after_send_raw0(conn_info.raw_info);
        te.stat_fast_retx++;
    }
    conn_info.raw_info.send_info.seq = saved_seq;
    e.retries++;
    e.last_ms = now;
    conn_info.raw_info.recv_info.ack_seq_counter = 0;
    return 0;
}
int tcpemul_record_sent(conn_info_t &conn_info, const char *pkt, int len, u32_t seq_start) {
    if (raw_mode != mode_faketcp) return 0;
    if (len <= 0) return 0;
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    retx_entry_t e;
    e.pkt.assign(pkt, pkt + len);
    e.seq_start = seq_start;
    e.seq_end = seq_start + (u32_t)len;
    e.first_ms = e.last_ms = get_current_time();
    e.retries = 0;
    e.gave_up = 0;
    if (te.retx_q.size() >= tcpemul_max_buf) te.retx_q.pop_front();
    if (te.retx_q.empty()) {
        // first segment after an idle period: measure ack staleness from here,
        // not from the last ack we saw before the connection went quiet
        te.last_ack_progress_ms = e.first_ms;
        te.last_ack_val = conn_info.raw_info.recv_info.ack_seq;
    }
    te.retx_q.push_back(e);
    return 0;
}

int tcpemul_retire_acked(conn_info_t &conn_info) {
    if (raw_mode != mode_faketcp) return 0;
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    u32_t ack = conn_info.raw_info.recv_info.ack_seq;
    u64_t now = get_current_time();
    if (te.last_ack_progress_ms == 0 || ack != te.last_ack_val) {
        te.last_ack_val = ack;
        te.last_ack_progress_ms = now;
    }
    // scan-based: entries may be out of order in the queue (new data is sent
    // while old segments await retransmission), so pop any acked entry,
    // not just the front one.
    for (auto it = te.retx_q.begin(); it != te.retx_q.end();) {
        if (seq_le(it->seq_end, ack)) it = te.retx_q.erase(it);
        else ++it;
    }
    return 0;
}

// Report emulation activity at log_info no more than every 10 s, and only if
// something happened. This is the only visibility into the emulation: it emits
// no per-packet logs (that would be a packet-rate log flood).
static void tcpemul_maybe_log_stats(conn_info_t &conn_info) {
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    u64_t now = get_current_time();
    if (te.stat_last_log_ms != 0 && now - te.stat_last_log_ms < 10000) return;
    te.stat_last_log_ms = now;
    if (te.stat_retx == te.log_retx && te.stat_fast_retx == te.log_fast_retx
        && te.stat_dupacks == te.log_dupacks && te.stat_reacks == te.log_reacks
        && te.stat_gaps == te.log_gaps && te.stat_giveup == te.log_giveup) return;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;
    u64_t ack_idle = te.last_ack_progress_ms ? now - te.last_ack_progress_ms : 0;
    mylog(log_info, "[%s:%d]tcp-emul retx=%llu fast_retx=%llu dupack=%llu reack=%llu gaps=%llu giveup=%llu ackidle=%llums inflight=%d\n",
          recv_info.new_src_ip.get_str1(), recv_info.src_port,
          (unsigned long long)te.stat_retx, (unsigned long long)te.stat_fast_retx,
          (unsigned long long)te.stat_dupacks, (unsigned long long)te.stat_reacks,
          (unsigned long long)te.stat_gaps, (unsigned long long)te.stat_giveup,
          (unsigned long long)ack_idle, (int)te.retx_q.size());
    te.log_retx = te.stat_retx;
    te.log_fast_retx = te.stat_fast_retx;
    te.log_dupacks = te.stat_dupacks;
    te.log_reacks = te.stat_reacks;
    te.log_gaps = te.stat_gaps;
    te.log_giveup = te.stat_giveup;
}

int tcpemul_retx_scan(conn_info_t &conn_info) {
    if (raw_mode != mode_faketcp) return 0;
    if (conn_info.state.server_current_state != server_ready
        && conn_info.state.client_current_state != client_ready) return 0;
    tcp_emul_t &te = conn_info.blob->tcp_emul;
    u64_t now = get_current_time();
    if (te.retx_q.empty()) {
        tcpemul_maybe_log_stats(conn_info);
        return 0;
    }
    // Cumulative acks retire in order, so only the oldest unacked segment can
    // be blocking the peer. Retransmitting anything behind it is pure waste:
    // the peer cannot ack past the hole anyway.
    retx_entry_t &e = te.retx_q.front();
    if (e.retries >= tcpemul_max_retries) {
        if (!e.gave_up) {  // abandoned: peer never acked this segment
            e.gave_up = 1;
            te.stat_giveup++;
        }
        tcpemul_maybe_log_stats(conn_info);
        return 0;
    }
    int rto = tcpemul_rto_base << e.retries;
    u64_t ack_idle = now - (te.last_ack_progress_ms ? te.last_ack_progress_ms : e.first_ms);
    // Loss evidence gate: an RTO only counts when the peer's cumulative ack
    // has not moved for a full RTO, and this segment was not resent recently
    // (fast retransmit may have just fired). On a clean path the ack advances
    // every heartbeat, so the timer never expires and nothing is duplicated.
    if (ack_idle < (u64_t)rto || now - e.last_ms < (u64_t)rto) {
        tcpemul_maybe_log_stats(conn_info);
        return 0;
    }
    u32_t saved_seq = conn_info.raw_info.send_info.seq;
    conn_info.raw_info.send_info.seq = e.seq_start;
    conn_info.raw_info.send_info.psh = 1;
    if (send_raw0(conn_info.raw_info, e.pkt.data(), (int)e.pkt.size()) == 0) {
        after_send_raw0(conn_info.raw_info);
        e.retries++;
        e.last_ms = now;
        te.stat_retx++;
    }
    conn_info.raw_info.send_info.seq = saved_seq;
    tcpemul_maybe_log_stats(conn_info);
    return 0;
}
// ===============================================================================
int recv_safer_multi(conn_info_t &conn_info, vector<char> &type_arr, vector<string> &data_arr)  /// safer transfer function with anti-replay,when mutually verification is done.
{
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    char *recv_data;
    int recv_len;
    assert(type_arr.empty());
    assert(data_arr.empty());

    if (recv_raw0(conn_info.raw_info, recv_data, recv_len) != 0) return -1;
    // receiver-side emulation must run before reserved_parse_safer, whose
    // after_recv_raw0() advances the cumulative ack position for in-order data
    if (tcpemul_on_recv_frame(conn_info) == -2) return 0;  // fully-old frame: re-acked, skip parse

    char type;
    char *data;
    int len;

    if (g_fix_gro == 0) {
        int ret = reserved_parse_safer(conn_info, recv_data, recv_len, type, data, len);
        if (ret == 0) {
            type_arr.push_back(type);
            data_arr.emplace_back(data, data + len);
            // std::copy(data,data+len,data_arr[0]);
        }
        return 0;
    } else {
        char *ori_recv_data = recv_data;
        int ori_recv_len = recv_len;
        // mylog(log_debug,"recv_len:%d\n",recv_len);
        int cnt = 0;
        while (recv_len >= 16) {
            cnt++;
            int single_len_no_xor;
            single_len_no_xor = read_u16(recv_data);
            int single_len;
            if (cipher_mode == cipher_xor) {
                recv_data[0] ^= gro_xor[0];
                recv_data[1] ^= gro_xor[1];
            } else if (cipher_mode == cipher_aes128cbc || cipher_mode == cipher_aes128cfb) {
                aes_ecb_decrypt1(recv_data);
            }
            single_len = read_u16(recv_data);
            recv_len -= 2;
            recv_data += 2;
            if (single_len > recv_len) {
                mylog(log_debug, "illegal single_len %d(%d), recv_len %d left,dropped\n", single_len, single_len_no_xor, recv_len);
                break;
            }
            if (single_len > max_data_len) {
                mylog(log_warn, "single_len %d(%d) > %d, maybe you need to turn down mtu at upper level\n", single_len, single_len_no_xor, max_data_len);
                break;
            }

            int ret = reserved_parse_safer(conn_info, recv_data, single_len, type, data, len);

            if (ret != 0) {
                mylog(log_debug, "parse failed, offset= %d,single_len=%d(%d)\n", (int)(recv_data - ori_recv_data), single_len, single_len_no_xor);
            } else {
                type_arr.push_back(type);
                data_arr.emplace_back(data, data + len);
                // std::copy(data,data+len,data_arr[data_arr.size()-1]);
            }
            recv_data += single_len;
            recv_len -= single_len;
        }
        if (cnt > 1) {
            mylog(log_debug, "got a suspected gro packet, %d packets recovered, recv_len=%d, loop_cnt=%d\n", (int)data_arr.size(), ori_recv_len, cnt);
        }
        return 0;
    }
}

void server_clear_function(u64_t u64)  // used in conv_manager in server mode.for server we have to use one udp fd for one conv(udp connection),
// so we have to close the fd when conv expires
{
    // int fd=int(u64);
    //	int ret;
    // assert(fd!=0);
    /*
    epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.u64 = u64;

    ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
    if (ret!=0)
    {
            mylog(log_fatal,"fd:%d epoll delete failed!!!!\n",fd);
            myexit(-1);   //this shouldnt happen
    }*/
    // no need

    /*ret= close(fd);  //closed fd should be auto removed from epoll

    if (ret!=0)
    {
            mylog(log_fatal,"close fd %d failed !!!!\n",fd);
            myexit(-1);  //this shouldnt happen
    }*/
    // mylog(log_fatal,"size:%d !!!!\n",conn_manager.udp_fd_mp.size());
    fd64_t fd64 = u64;
    assert(fd_manager.exist(fd64));
    fd_manager.fd64_close(fd64);

    // assert(conn_manager.udp_fd_mp.find(fd)!=conn_manager.udp_fd_mp.end());
    // conn_manager.udp_fd_mp.erase(fd);
}
