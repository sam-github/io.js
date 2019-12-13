#ifndef SRC_NODE_QUIC_SOCKET_H_
#define SRC_NODE_QUIC_SOCKET_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "node_crypto.h"
#include "node_internals.h"
#include "ngtcp2/ngtcp2.h"
#include "node_quic_session.h"
#include "node_quic_util.h"
#include "node_sockaddr.h"
#include "env.h"
#include "udp_wrap.h"
#include "v8.h"
#include "uv.h"

#include <deque>
#include <map>
#include <string>
#include <vector>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

static constexpr size_t MAX_VALIDATE_ADDRESS_LRU = 10;

enum QuicSocketOptions : uint32_t {
  // When enabled the QuicSocket will validate the address
  // using a RETRY packet to the peer.
  QUICSOCKET_OPTIONS_VALIDATE_ADDRESS = 0x1,

  // When enabled, and the VALIDATE_ADDRESS option is also
  // set, the QuicSocket will use an LRU cache to track
  // validated addresses. Address validation will be skipped
  // if the address is currently in the cache.
  QUICSOCKET_OPTIONS_VALIDATE_ADDRESS_LRU = 0x2,
};

enum QuicSocketStatsIdx : int {
    IDX_QUIC_SOCKET_STATS_CREATED_AT,
    IDX_QUIC_SOCKET_STATS_BOUND_AT,
    IDX_QUIC_SOCKET_STATS_LISTEN_AT,
    IDX_QUIC_SOCKET_STATS_BYTES_RECEIVED,
    IDX_QUIC_SOCKET_STATS_BYTES_SENT,
    IDX_QUIC_SOCKET_STATS_PACKETS_RECEIVED,
    IDX_QUIC_SOCKET_STATS_PACKETS_IGNORED,
    IDX_QUIC_SOCKET_STATS_PACKETS_SENT,
    IDX_QUIC_SOCKET_STATS_SERVER_SESSIONS,
    IDX_QUIC_SOCKET_STATS_CLIENT_SESSIONS,
    IDX_QUIC_SOCKET_STATS_STATELESS_RESET_COUNT
};

class QuicSocket;

// This is the generic interface for objects that control QuicSocket
// instances. The default `JSQuicSocketListener` emits events to
// JavaScript
class QuicSocketListener {
 public:
  virtual ~QuicSocketListener();

  virtual void OnError(ssize_t code);
  virtual void OnError(int code);
  virtual void OnSessionReady(BaseObjectPtr<QuicSession> session);
  virtual void OnServerBusy(bool busy);
  virtual void OnDone();
  virtual void OnDestroy();

  QuicSocket* Socket() { return socket_; }

 private:
  QuicSocket* socket_ = nullptr;
  QuicSocketListener* previous_listener_ = nullptr;
  friend class QuicSocket;
};

class JSQuicSocketListener : public QuicSocketListener {
 public:
  void OnError(ssize_t code) override;
  void OnError(int code) override;
  void OnSessionReady(BaseObjectPtr<QuicSession> session) override;
  void OnServerBusy(bool busy) override;
  void OnDone() override;
  void OnDestroy() override;
};

class QuicSocket : public AsyncWrap,
                   public UDPListener,
                   public mem::NgLibMemoryManager<QuicSocket, ngtcp2_mem> {
 public:
  static void Initialize(
      Environment* env,
      Local<Object> target,
      Local<Context> context);

  QuicSocket(
      Environment* env,
      Local<Object> wrap,
      Local<Object> udp_base_wrap,
      uint64_t retry_token_expiration,
      size_t max_connections_per_host,
      uint32_t options = 0,
      QlogMode qlog = QlogMode::kDisabled,
      const uint8_t* session_reset_secret = nullptr);
  ~QuicSocket() override;

  SocketAddress* GetLocalAddress() { return &local_address_; }

  void MaybeClose();

  void AddSession(
      const QuicCID& cid,
      BaseObjectPtr<QuicSession> session);
  void AssociateCID(
      const QuicCID& cid,
      const QuicCID& scid);
  void DisassociateCID(
      const QuicCID& cid);
  void Listen(
      crypto::SecureContext* context,
      const sockaddr* preferred_address = nullptr,
      const std::string& alpn = NGTCP2_ALPN_H3,
      uint32_t options = 0);
  int ReceiveStart();
  int ReceiveStop();
  void RemoveSession(
      const QuicCID& cid,
      const SocketAddress& addr);
  void ReportSendError(
      int error);
  int SendPacket(
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      QuicBuffer* buf,
      BaseObjectPtr<QuicSession> session,
      const char* diagnostic_label = nullptr);
  void SetServerBusy(bool on);
  void SetDiagnosticPacketLoss(double rx = 0.0, double tx = 0.0);
  void StopListening();
  void WaitForPendingCallbacks();

  crypto::SecureContext* GetServerSecureContext() {
    return server_secure_context_;
  }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(QuicSocket)
  SET_SELF_SIZE(QuicSocket)

  // Implementation for mem::NgLibMemoryManager
  void CheckAllocatedSize(size_t previous_size) const;
  void IncreaseAllocatedSize(size_t size);
  void DecreaseAllocatedSize(size_t size);

  ResetTokenSecret* GetSessionResetSecret() { return &reset_token_secret_; }

  // Implementation for UDPWrapListener
  uv_buf_t OnAlloc(size_t suggested_size) override;
  void OnRecv(ssize_t nread,
              const uv_buf_t& buf,
              const sockaddr* addr,
              unsigned int flags) override;
  ReqWrap<uv_udp_send_t>* CreateSendWrap(size_t msg_size) override;
  void OnSendDone(ReqWrap<uv_udp_send_t>* wrap, int status) override;
  void OnAfterBind() override;

  bool SendRetry(
      uint32_t version,
      const QuicCID& dcid,
      const QuicCID& scid,
      const sockaddr* addr);

  bool SendStatelessReset(
      const QuicCID& cid,
      const sockaddr* addr);

  void PushListener(QuicSocketListener* listener);
  void RemoveListener(QuicSocketListener* listener);

 private:
  static void OnAlloc(
      uv_handle_t* handle,
      size_t suggested_size,
      uv_buf_t* buf);

  void Receive(
      ssize_t nread,
      AllocatedBuffer buf,
      const SocketAddress& local_addr,
      const struct sockaddr* remote_addr,
      unsigned int flags);

  void SendInitialConnectionClose(
      uint32_t version,
      uint64_t error_code,
      const QuicCID& dcid,
      const sockaddr* addr);

  void SendVersionNegotiation(
      uint32_t version,
      const QuicCID& dcid,
      const QuicCID& scid,
      const sockaddr* addr);

  void OnSend(
      int status,
      size_t length,
      QuicBuffer* buffer,
      const char* diagnostic_label);

  void SetValidatedAddress(const sockaddr* addr);
  bool IsValidatedAddress(const sockaddr* addr) const;

  BaseObjectPtr<QuicSession> AcceptInitialPacket(
      uint32_t version,
      const QuicCID& dcid,
      const QuicCID& scid,
      ssize_t nread,
      const uint8_t* data,
      const SocketAddress& local_addr,
      const struct sockaddr* remote_addr,
      unsigned int flags);

  void IncrementSocketAddressCounter(const SocketAddress& addr);
  void DecrementSocketAddressCounter(const SocketAddress& addr);
  size_t GetCurrentSocketAddressCounter(const sockaddr* addr);

  void IncrementPendingCallbacks() { pending_callbacks_++; }
  void DecrementPendingCallbacks() { pending_callbacks_--; }
  bool HasPendingCallbacks() { return pending_callbacks_ > 0; }

  // Returns true if, and only if, diagnostic packet loss is enabled
  // and the current packet should be artificially considered lost.
  bool IsDiagnosticPacketLoss(double prob);

  enum QuicSocketFlags : uint32_t {
    QUICSOCKET_FLAGS_NONE = 0x0,

    // Indicates that the QuicSocket has entered a graceful
    // closing phase, indicating that no additional
    QUICSOCKET_FLAGS_GRACEFUL_CLOSE = 0x1,
    QUICSOCKET_FLAGS_WAITING_FOR_CALLBACKS = 0x2,
    QUICSOCKET_FLAGS_SERVER_LISTENING = 0x4,
    QUICSOCKET_FLAGS_SERVER_BUSY = 0x8,
  };

  void SetFlag(QuicSocketFlags flag, bool on = true) {
    if (on)
      flags_ |= flag;
    else
      flags_ &= ~flag;
  }

  bool IsFlagSet(QuicSocketFlags flag) const {
    return flags_ & flag;
  }

  void SetOption(QuicSocketOptions option, bool on = true) {
    if (on)
      options_ |= option;
    else
      options_ &= ~option;
  }

  bool IsOptionSet(QuicSocketOptions option) const {
    return options_ & option;
  }

  ngtcp2_mem alloc_info_;
  UDPWrapBase* udp_;
  BaseObjectPtr<AsyncWrap> udp_strong_ptr_;
  uint32_t flags_ = QUICSOCKET_FLAGS_NONE;
  uint32_t options_;
  uint32_t server_options_;

  size_t pending_callbacks_ = 0;
  size_t max_connections_per_host_;
  size_t current_ngtcp2_memory_ = 0;

  uint64_t retry_token_expiration_;

  // Used to specify diagnostic packet loss probabilities
  double rx_loss_ = 0.0;
  double tx_loss_ = 0.0;

  QuicSocketListener* listener_;
  JSQuicSocketListener default_listener_;
  SocketAddress local_address_;
  QuicSessionConfig server_session_config_;
  QlogMode qlog_ = QlogMode::kDisabled;
  crypto::SecureContext* server_secure_context_ = nullptr;
  std::string server_alpn_;
  std::unordered_map<std::string, BaseObjectPtr<QuicSession>> sessions_;
  std::unordered_map<std::string, std::string> dcid_to_scid_;
  RetryTokenSecret token_secret_;
  ResetTokenSecret reset_token_secret_;

  // Counts the number of active connections per remote
  // address. A custom std::hash specialization for
  // sockaddr instances is used. Values are incremented
  // when a QuicSession is added to the socket, and
  // decremented when the QuicSession is removed. If the
  // value reaches the value of max_connections_per_host_,
  // attempts to create new connections will be ignored
  // until the value falls back below the limit.
  std::unordered_map<const sockaddr*, size_t, SocketAddress::Hash,
      SocketAddress::Compare> addr_counts_;

  // The validated_addrs_ vector is used as an LRU cache for
  // validated addresses only when the VALIDATE_ADDRESS_LRU
  // option is set.
  typedef size_t SocketAddressHash;
  std::deque<SocketAddressHash> validated_addrs_;

  struct socket_stats {
    // The timestamp at which the socket was created
    uint64_t created_at;
    // The timestamp at which the socket was bound
    uint64_t bound_at;
    // The timestamp at which the socket began listening
    uint64_t listen_at;
    // The total number of bytes received (and not ignored)
    // by this QuicSocket instance.
    uint64_t bytes_received;

    // The total number of bytes successfully sent by this
    // QuicSocket instance.
    uint64_t bytes_sent;

    // The total number of packets received (and not ignored)
    // by this QuicSocket instance.
    uint64_t packets_received;

    // The total number of packets ignored by this QuicSocket
    // instance. Packets are ignored if they are invalid in
    // some way. A high number of ignored packets could signal
    // a buggy or malicious peer.
    uint64_t packets_ignored;

    // The total number of packets successfully sent by this
    // QuicSocket instance.
    uint64_t packets_sent;

    // The total number of server QuicSessions that have been
    // associated with this QuicSocket instance.
    uint64_t server_sessions;

    // The total number of client QuicSessions that have been
    // associated with this QuicSocket instance.
    uint64_t client_sessions;

    // The total number of stateless resets that have been sent
    uint64_t stateless_reset_count;
  };
  socket_stats socket_stats_{};

  AliasedBigUint64Array stats_buffer_;

  template <typename... Members>
  void IncrementSocketStat(
      uint64_t amount,
      socket_stats* a,
      Members... mems) {
    static uint64_t max = std::numeric_limits<uint64_t>::max();
    uint64_t current = access(a, mems...);
    uint64_t delta = std::min(amount, max - current);
    access(a, mems...) += delta;
  }

  class SendWrap : public ReqWrap<uv_udp_send_t> {
   public:
    SendWrap(Environment* env,
             v8::Local<v8::Object> req_wrap_obj,
             size_t total_length_);

    void set_data(MallocedBuffer<char>&& data) { data_ = std::move(data); }
    void set_quic_buffer(QuicBuffer* buffer) { buffer_ = buffer; }
    void set_session(BaseObjectPtr<QuicSession> session) { session_ = session; }
    void set_diagnostic_label(const char* label) { diagnostic_label_ = label; }
    QuicBuffer* quic_buffer() const { return buffer_; }
    const char* diagnostic_label() const { return diagnostic_label_; }
    size_t total_length() const { return total_length_; }

    SET_SELF_SIZE(SendWrap);
    std::string MemoryInfoName() const override;
    void MemoryInfo(MemoryTracker* tracker) const override;

   private:
    BaseObjectPtr<QuicSession> session_;
    QuicBuffer* buffer_ = nullptr;
    MallocedBuffer<char> data_;
    const char* diagnostic_label_ = nullptr;
    size_t total_length_;
  };

  SendWrap* last_created_send_wrap_ = nullptr;

  int Send(const sockaddr* addr,
           MallocedBuffer<char>&& data,
           const char* diagnostic_label = "unspecified");

  friend class QuicSocketListener;
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_QUIC_SOCKET_H_
