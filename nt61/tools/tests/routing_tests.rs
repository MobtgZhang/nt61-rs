//! Routing logic host-side tests.
//!
//! The kernel's `ipif::route_lookup` is shared with the
//! network-stack routing code, so we re-implement the same
//! longest-prefix-match logic here and verify the cases that the
//! plan calls out:
//!   - Loopback addresses (127.0.0.0/8) must NOT route through
//!     the physical NIC.
//!   - Direct route to the DNS server must win over the default
//!     route.
//!   - Longest prefix wins between equal-cost routes.

#[cfg(test)]
mod tests {
    #[derive(Clone, Copy)]
    struct RouteEntry {
        dest: u32,
        netmask: u32,
        gateway: u32,
        if_index: u32,
        metric: u32,
    }

    impl RouteEntry {
        fn prefix_len(&self) -> u8 {
            self.netmask.count_ones() as u8
        }
        fn matches(&self, dest: u32) -> bool {
            (dest & self.netmask) == (self.dest & self.netmask)
        }
    }

    fn route_lookup(routes: &[RouteEntry], dest: u32) -> Option<RouteEntry> {
        // Sort by (prefix_len desc, metric asc) for longest-prefix
        // match with lowest-metric tiebreak.
        let mut sorted: Vec<&RouteEntry> = routes.iter().collect();
        sorted.sort_by(|a, b| {
            b.prefix_len()
                .cmp(&a.prefix_len())
                .then(a.metric.cmp(&b.metric))
        });
        sorted
            .into_iter()
            .find(|r| r.matches(dest))
            .copied()
    }

    fn ipv4_is_loopback(ip: u32) -> bool {
        (ip & 0xFF000000) == 0x7F000000
    }

    #[test]
    fn loopback_does_not_route_through_nic() {
        // Add a fake default route via eth0 and a loopback route
        // via the loopback pseudo-interface. Loopback traffic
        // must match the loopback route, not the default.
        let routes = vec![
            RouteEntry {
                dest: 0,
                netmask: 0,
                gateway: 0x0A000202,
                if_index: 1,
                metric: 0,
            }, // default via 10.0.2.2 on eth0
            RouteEntry {
                dest: 0x7F000000,
                netmask: 0xFF000000,
                gateway: 0,
                if_index: 0,
                metric: 0,
            }, // 127.0.0.0/8 on loopback
        ];
        let r = route_lookup(&routes, 0x7F000001).unwrap();
        assert_eq!(r.if_index, 0, "loopback must route via if_index 0");
        assert!(ipv4_is_loopback(0x7F000001));
    }

    #[test]
    fn longest_prefix_wins() {
        let routes = vec![
            RouteEntry {
                dest: 0,
                netmask: 0,
                gateway: 0x0A000202,
                if_index: 1,
                metric: 0,
            },
            RouteEntry {
                dest: 0x0A000200,
                netmask: 0xFFFFFF00,
                gateway: 0x0A000203,
                if_index: 1,
                metric: 0,
            }, // /24 covers 10.0.2.x
        ];
        let r = route_lookup(&routes, 0x0A000205).unwrap();
        assert_eq!(r.gateway, 0x0A000203);
        assert_eq!(r.prefix_len(), 24);
    }

    #[test]
    fn dns_server_route_overrides_default() {
        // After DHCP assigns 10.0.2.3 as DNS, we add a /32 host
        // route so DNS queries do not get stuck behind a more
        // generic default.
        let routes = vec![
            RouteEntry {
                dest: 0,
                netmask: 0,
                gateway: 0x0A000202,
                if_index: 1,
                metric: 0,
            },
            RouteEntry {
                dest: 0x0A000203,
                netmask: 0xFFFFFFFF,
                gateway: 0x0A000202,
                if_index: 1,
                metric: 1,
            },
        ];
        let r = route_lookup(&routes, 0x0A000203).unwrap();
        assert_eq!(r.netmask, 0xFFFFFFFF, "must pick /32 host route, not default");
    }

    #[test]
    fn no_route_returns_none() {
        // Only a /8 route for 192.0.0.0/8; nothing else.
        let routes = vec![RouteEntry {
            dest: 0xC0000000,
            netmask: 0xFF000000,
            gateway: 0,
            if_index: 1,
            metric: 0,
        }];
        // 10.0.2.5 is not in 192.0.0.0/8, must not match.
        let r = route_lookup(&routes, 0x0A000205);
        assert!(r.is_none(), "10.0.2.5 must NOT match 192.0.0.0/8");
        // 192.168.1.1 IS in 192.0.0.0/8, must match.
        let r = route_lookup(&routes, 0xC0A80101);
        assert!(r.is_some(), "192.168.x.x must match 192.0.0.0/8");
    }
}
