# Discovery服务

## 默认配置

```go
const (
	DefaultAliveTimeInterval            = 5 * time.Second
	DefaultAliveExpirationTimeout       = 5 * DefaultAliveTimeInterval
	DefaultAliveExpirationCheckInterval = DefaultAliveExpirationTimeout / 10
	DefaultReconnectInterval            = DefaultAliveExpirationTimeout
	DefaultMsgExpirationFactor          = 20
	DefaultMaxConnectionAttempts        = 120
)
```

- **DefaultAliveTimeInterval:** 定义了 `Discovery` 服务每隔多长时间向外广播自己的 `alive` 消息，默认是 `5` 秒。

- **DefaultAliveExpirationTimeout**

## Discovery的服务逻辑

### 广播自己的alive消息

区块链系统在启动之初，会建立并启动 `Discovery` 服务，这个服务默认情况下，会每隔 `5` 秒（`DefaultAliveTimeInterval` 定义的时间间隔）对外广播自己的 `alive` 消息。`alive` 消息的结构和内容如下所示：

```go
aliveMsg := GossipMessage{
    Tag: GossipMessage_EMPTY,
    Content: &GossipMessage_AliveMsg{
        Membership: &Member{
            Endpoint:   自己的 ExternalEndpoint,
            Metadata:   自己的 Metadata,
            PkiId:      自己的 PKIid,
        },
        Timestamp: &PeerTime{
            IncNum: Discovery 服务启动时的时间,
            SeqNum: 目前为自己构造 alive 消息的次数, // 实际上就是调用 aliveMsgAndInternalEndpoint（）方法的次数
        }
    }
}
```

在得到自己的 `alive` 消息后，`Discovery` 会利用 `CryptoService` 服务接口，对 `alive` 消息进行签名，得到 `envelope`，紧接着构建 `SignedGossipMessage`：

```go
signedAliveMsg := &SignedGossipMessage{
    GossipMessage:  aliveMsg,
    Envelope:       envelope,
}
```

这个时候，`Discovery` 就会将带有 `alive` 消息的 `SignedGossipMessage` 消息结构广播给其他节点。

### 接收别人的alive消息

在收到别人的 `alive` 消息后，会先后进行下列操作，检查此消息是否值得被处理：

1. 验证携有对方 `alive` 消息的 `SignedGossipMessage` 消息结构中所携带的签名（签名信息存储在 `Envelope` 字段中）是否合法。
2. 验证对方发送来的 `alive` 消息是否太旧，主要是通过 `GossipMessage_AliveMsg` 消息结构中的 `Timestamp` 字段来判断。其实对于同一个 `peer` 节点来说，它的 `Discovery` 服务的启动时间正常来说是恒定不变的，因此判断一个 `alive` 消息是否是陈旧的，主要还是通过判断 `SeqNum` 来确定。
3. 如果接收到的 `alive` 消息是来自于自己的，则直接忽略掉。

经过上述三个步骤的验证后，`Discovery` 服务会将此条消息存储到 `aliveMsgStore` 中，这里需要详细说明，`aliveMsgStore` 是一个会定期清理超时消息的内存数据库，默认情况下，`aliveMsgStore` 中每个 `alive` 消息的存活时间是 `500` 秒（`DefaultAliveExpirationTimeout * DefaultMsgExpirationFactor` 定义的超时时间），根据存储逻辑，在任何时间里，`aliveMsgStore` 只会为每个节点存储唯一一条 `alive` 消息，如果此条 `alive` 消息因为过期被清除掉的话，`Discovery` 处维护的对应节点也会被删除掉。`aliveMsgStore` 里存储的每条 `alive` 消息的生命倒计时是从消息加入到 `aliveMsgStore` 中开始计算的。默认情况下，`alive` 消息的存活时间是 `500` 秒，因此，`aliveMsgStore` 会每隔 `5` 秒检查一下存储的所有 `alive` 消息是否有过期的。

之后，`Discovery` 会判断此条 `alive` 消息是否来自于一个已知的节点，如果不是，那么就表明有一个新节点向我们发送了 `alive` 消息，因此，我们就会根据发送来的 `alive` 消息，构建一个代表此新节点身份的 `NetworkMember` 结构，并将此结构存储到本地，即，将此新节点存储到 `Discovery` 中。不然的话，会判断发送此 `alive` 消息的节点，在 `Discovery` 处的状态，是被认为已经 `dead` 了，还是依然 `alive` 呢？对于前者，如果此条 `alive` 消息是在节点被置为 `dead` 状态后发送来的，那么就将此节点复活，否则就忽视掉此条 `alive` 消息。对于后者，如果此条 `alive` 消息足够新鲜，那么就更新此节点在 `Discovery` 处的信息。最后，我们再将此条 `alive` 消息转发给其他节点。

### 周期性检查有没有之前处于活跃状态的节点现在已经陷入沉寂

默认情况下，`Discovery` 会每隔 `2.5` 秒（`DefaultAliveExpirationCheckInterval` 定义的间隔时间）检查 `aliveLastTS` 字段里存储的每个节点上次发送来 `alive` 消息的时间到现在的时间间隔是否超过了 `25` 秒（`DefaultAliveExpirationTimeout` 定义的超时时间），如果超过了，则说明此节点很可能陷入了沉寂，那么我们就需要将这些陷入沉寂的节点移入到 `deadLastTS` 和 `deadMembership` 中，并断开与其建立的网络连接。