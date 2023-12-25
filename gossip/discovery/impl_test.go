package discovery

import "time"

var (
	aliveTimeInterval = time.Millisecond * 300
	defaultTestConfig = DiscoveryConfig{
		AliveTimeInterval: aliveTimeInterval,
		AliveExpirationTimeout: 10 * aliveTimeInterval,
		AliveExpirationCheckInterval: aliveTimeInterval,
		
	}
)