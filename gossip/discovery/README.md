# Discovery服务

## 1. 默认配置

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

- **DefaultAliveExpirationTimeout:** 定义了一段超时时间，如果某个节点在经过了 `DefaultAliveExpirationTimeout` 时间后还没有给 `Discovery` 发送 `alive` 消息，则会认为此节点陷入了沉寂，并且会主动断开与其建立的网络连接。

- **DefaultAliveExpirationCheckInterval:** 定义了一段时间间隔，`Discovery` 的 `alive` 消息存储器会每隔 `DefaultAliveExpirationCheckInterval` 定义的时间间隔检查一遍所有存储的 `alive` 消息是否走到了生命的尽头，`alive` 消息的最大寿命等于 `DefaultAliveExpirationTimeout * DefaultMsgExpirationFactor`。

- **DefaultReconnectInterval:** 定义了一段时间间隔，如果 `Discovery` 第一次与某个节点建立连接时失败了，则会等待 `DefaultReconnectInterval` 定义的时间间隔再次尝试建立连接。

- **DefaultMsgExpirationFactor:** 定义了一个乘法因子，它的用法可回看对 `DefaultAliveExpirationCheckInterval` 的定义。

- **DefaultMaxConnectionAttempts:** 定义了最大连接尝试次数，如果 `Discovery` 第一次与某个节点建立连接时失败了，则会继续最多尝试与其建立连接 `DefaultMaxConnectionAttempts - 1` 次。

## 2. Discovery的服务逻辑

### 2.1 广播自己的alive消息

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

### 2.2 接收别人的alive消息

在收到别人的 `alive` 消息后，会先后进行下列操作，检查此消息是否值得被处理：

1. 验证携有对方 `alive` 消息的 `SignedGossipMessage` 消息结构中所携带的签名（签名信息存储在 `Envelope` 字段中）是否合法。
2. 验证对方发送来的 `alive` 消息是否太旧，主要是通过 `GossipMessage_AliveMsg` 消息结构中的 `Timestamp` 字段来判断。其实对于同一个 `peer` 节点来说，它的 `Discovery` 服务的启动时间正常来说是恒定不变的，因此判断一个 `alive` 消息是否是陈旧的，主要还是通过判断 `SeqNum` 来确定。
3. 如果接收到的 `alive` 消息是来自于自己的，则直接忽略掉。

经过上述三个步骤的验证后，`Discovery` 服务会将此条消息存储到 `aliveMsgStore` 中，这里需要详细说明，`aliveMsgStore` 是一个会定期清理超时消息的内存数据库，默认情况下，`aliveMsgStore` 中每个 `alive` 消息的存活时间是 `500` 秒（`DefaultAliveExpirationTimeout * DefaultMsgExpirationFactor` 定义的超时时间），根据存储逻辑，在任何时间里，`aliveMsgStore` 只会为每个节点存储唯一一条 `alive` 消息，如果此条 `alive` 消息因为过期被清除掉的话，`Discovery` 处维护的对应节点也会被删除掉，但是锚点 `peer` 不会被删除，操作逻辑如下代码所示：

![gossip-1.png](../../assets/gossip-1.png)

`aliveMsgStore` 里存储的每条 `alive` 消息的生命倒计时是从消息加入到 `aliveMsgStore` 中开始计算的。默认情况下，`alive` 消息的存活时间是 `500` 秒，因此，`aliveMsgStore` 会每隔 `5` 秒检查一下存储的所有 `alive` 消息是否有过期的。

之后，`Discovery` 会判断此条 `alive` 消息是否来自于一个已知的节点，如果不是，那么就表明有一个新节点向我们发送了 `alive` 消息，因此，我们就会根据发送来的 `alive` 消息，构建一个代表此新节点身份的 `NetworkMember` 结构，并将此结构存储到本地，即，将此新节点存储到 `Discovery` 中。不然的话，会判断发送此 `alive` 消息的节点，在 `Discovery` 处的状态，是被认为已经 `dead` 了，还是依然 `alive` 呢？对于前者，如果此条 `alive` 消息是在节点被置为 `dead` 状态后发送来的，那么就将此节点复活，否则就忽视掉此条 `alive` 消息。对于后者，如果此条 `alive` 消息足够新鲜，那么就更新此节点在 `Discovery` 处的信息。最后，我们再将此条 `alive` 消息转发给其他节点。

### 2.3 周期性检查有没有之前处于活跃状态的节点现在已经陷入沉寂

默认情况下，`Discovery` 会每隔 `2.5` 秒（`DefaultAliveExpirationCheckInterval` 定义的间隔时间）检查 `aliveLastTS` 字段里存储的每个节点上次发送来 `alive` 消息的时间到现在的时间间隔是否超过了 `25` 秒（`DefaultAliveExpirationTimeout` 定义的超时时间），如果超过了，则说明此节点很可能陷入了沉寂，那么我们就需要将这些陷入沉寂的节点移入到 `deadLastTS` 和 `deadMembership` 中，并断开与其建立的网络连接。

### 2.4 循环监听消息通道中新来的消息

`Discovery` 服务只会接收并处理以下三种消息：

- `AliveMessage`
- `MembershipRequest`
- `MembershipResponse`

1. 如果 `Discovery` 收到的是 `AliveMessage` 消息，则会按照 `2.2` 节所示的过程进行处理。

2. 如果 `Discovery` 收到的是 `MembershipRequest` 消息，则会验证该消息是否新鲜，是否被正确签名，另外，这个节点能给我们发送 `AliveMessage` 消息，则表明此节点是处于 `alive` 状态，所以会将此节点通过 `MembershipRequest` 消息传过来的 `alive` 消息按照 `2.2` 节所示的过程进行处理。最后，`Discovery` 会构建 `MembershipResponse` 消息并回复，构建此消息的代码如下所示：

![gossip-2.png](../../assets/gossip-2.png)

上述代码告诉了我们哪些 `Membership` 的消息能传给请求者，哪些不能。

3. 如果 `Discovery` 收到的是 `MembershipResponse` 消息，则会处理其中的 `alive` 和 `dead` 成员信息。

## 3. 构造MembershipRequest消息的过程

1. > func (impl *gossipDiscoveryImpl) createMembershipRequest(includeInternalEndpoint bool) (*pbgossip.GossipMessage, error)

    `createMembershipRequest` 方法调用 `getMySignedAliveMessage` 方法获取经过签名的 `SignedGossipMessage`，然后通过以下代码，去构造带有 `GossipMessage_MemReq` 消息的 `GossipMessage`：

    ```go
    request := &GossipMessage{
        Tag: GossipMessage_EMPTY,
        Nonce: RandomUint64(),
        Content: &GossipMessage_MemReq{
            MemReq: &MembershipRequest{
                SelfInformation: signedGossipMessage.Envelope,
            },
        }
    }
    ```

2. > func (impl *gossipDiscoveryImpl) getMySignedAliveMessage(includeInternalEndpoint bool) (*protoext.SignedGossipMessage, error)

    `getMySignedAliveMessage` 方法调用 `aliveMsgAndInternalEndpoint` 方法获取经过组装的 `GossipMessage` 和自身的 `InternalEndpoint`。

    `getMySignedAliveMessage` 调用 `CryptoService` 密码服务接口，使用 `SignMessage` 方法对 `GossipMessage` 进行签名，**目前，如何对其进行签名，还不太清楚，可以猜一下：**首先利用 `protobuf` 对 `GossipMessage` 消息进行序列化，得到字节切片 `payload`，然后利用签名算法 `signer` 对 `payload` 进行签名，得到 `signature`，紧接着就是构造 `Envelope`：

    ```go
    envelope := &Envelope{
        Payload: payload,
        Signature: signature,
    }
    ```

    然后再构造 `SignedGossipMessage` 消息结构：

    ```go
    signedGossipMessage := &SignedGossipMessage{
        GossipMessage: gossipMessage,
        Envelope: envelope,
    }
    ```

    **上面的签名过程，我们没有讲解 `Envelope` 消息结构内的 `SecretEnvelope` 字段如何生成，但是盲猜一下，应该是在生成签名的过程中生成的。**

    最后，如果 `includeInternalEndpoint` 的值等于 `false`，则需要将 `signedGossipMessage.Envelope.SecretEnvelope` 设置为 `nil`。

    最后的最后，`getMySignedAliveMessage` 方法将生成的 `signedGossipMessage` 消息返回到上层方法 `createMembershipRequest`，所以此时，我们可以回到第 `1` 步去观察 `createMembershipRequest` 方法如何基于返回的 `SignedGossipMessage` 构造 `GossipMessage_MemReq`。

3. > func (impl *gossipDiscoveryImpl) aliveMsgAndInternalEndpoint() (*pbgossip.GossipMessage, string)

    `aliveMsgAndInternalEndpoint` 方法通过以下过程组装 `GossipMessage`，`GossipMessage` 内存放的实际内容为 `GossipMessage_AliveMsg`。

    ```go
    gossipMessage := &GossipMessage{
        Tag: GossipMessage_EMPTY,
        Content: &GossipMessage_AliveMsg{ //实际消息
            AliveMsg: &AliveMessage{
                Membership: &Member{
                    Endpoint: impl.self.ExternalEndpoint,
                    Metadata: impl.self.Metadata,
                    PkiId: impl.self.PKIid,
                },
                Timestamp: &PeerTime{
                    IncNum: impl.incTime,
                    SeqNum: impl.seqNum,
                },
            }
        }
    }
    ```

    方法返回的 `InternalEndpoint` 则是 `impl.self.InternalEndpoint`。对于方法所构造的 `GossipMessage`，不做任何处理，直接返回到上层方法 `getMySignedAliveMessage`，所以此时，我们可以回到第 `2` 步去观察 `getMySignedAliveMessage` 方法如何基于返回的 `GossipMessage` 构造 `SignedGossipMessage`。